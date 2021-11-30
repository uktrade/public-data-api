# Don't absolutely need gevent here, but the web application uses gevent, and
# the Python coverage package doesn't support both threads and gevent
from gevent import (
    monkey,
)
monkey.patch_all()

import ecs_logging

from functools import (
    partial,
)
import logging
import os
import signal
import sys
import threading
import urllib.parse

import sentry_sdk
from tidy_json_to_csv import (
    to_csvs,
)
import urllib3
import zlib

from app_aws import (
    aws_s3_request,
    aws_list_folders,
    aws_head,
    aws_multipart_upload,
)


def ensure_csvs(
        logger, shut_down,
        http, parsed_endpoint,
        aws_access_key_id, aws_secret_access_key, region_name,
):
    # Bump to regenerate all CSVs
    CSV_VERSION = '1'

    signed_s3_request = partial(aws_s3_request, parsed_endpoint, http,
                                aws_access_key_id, aws_secret_access_key, region_name)

    def get_dataset_ids():
        yield from aws_list_folders(signed_s3_request, '')

    def get_dataset_ids_versions(dataset_ids):
        for dataset_id in dataset_ids:
            for version in aws_list_folders(signed_s3_request, f'{dataset_id}/'):
                yield dataset_id, version

    def write_csvs(dataset_id, version):
        def save_csv(path, chunks):
            table = path.replace('_', '-')  # GDS API guidelines prefer dash to underscore
            s3_key = f'{dataset_id}/{version}/tables/{table}/data.csv'
            aws_multipart_upload(signed_s3_request, s3_key, chunks)

        def save_csv_compressed(table, chunks):
            def yield_compressed_bytes(_uncompressed_bytes):
                # wbits controls whether a header and trailer is included in the output.
                # 31 means a basic gzip header and trailing checksum will be included in
                # the output. See https://docs.python.org/3/library/zlib.html#zlib.compressobj
                compress_obj = zlib.compressobj(wbits=31)
                for chunk in _uncompressed_bytes:
                    compressed_bytes = compress_obj.compress(chunk)
                    if compressed_bytes:
                        yield compressed_bytes

                compressed_bytes = compress_obj.flush()
                if compressed_bytes:
                    yield compressed_bytes

            s3_key = f'{dataset_id}/{version}/tables/{table}/data.csv.gz'
            aws_multipart_upload(signed_s3_request, s3_key, yield_compressed_bytes(chunks))

        with signed_s3_request('GET', s3_key=f'{dataset_id}/{version}/data.json') as response:
            if response.status != 200:
                return
            etag = response.headers['etag'].strip('"')
            to_csvs(response.stream(65536), save_csv)

        for table in aws_list_folders(signed_s3_request, f'{dataset_id}/{version}/tables/'):
            s3_key = f'{dataset_id}/{version}/tables/{table}/data.csv'
            with signed_s3_request('GET', s3_key=s3_key) as response:
                if response.status != 200:
                    return
                save_csv_compressed(table, response.stream(65536))

        etag_key = f'{dataset_id}/{version}/data.json__CSV_VERSION_{CSV_VERSION}__{etag}'
        with signed_s3_request('PUT', s3_key=etag_key) as response:
            put_response_body = response.read()
            if response.status != 200:
                raise Exception('Error saving etag object {} {} {}'.format(
                    etag_key, response.status, put_response_body))

        logger.info('Saved as CSV %s %s', dataset_id, version)

    dataset_ids = get_dataset_ids()
    dataset_ids_versions = get_dataset_ids_versions(dataset_ids)
    for dataset_id, version in dataset_ids_versions:
        if shut_down.is_set():
            break

        status, headers = aws_head(signed_s3_request, f'{dataset_id}/{version}/data.json')
        if status != 200:
            continue
        etag = headers['etag'].strip('"')
        etag_key = f'{dataset_id}/{version}/data.json__CSV_VERSION_{CSV_VERSION}__{etag}'
        status, _ = aws_head(signed_s3_request, etag_key)
        if status == 200:
            continue

        try:
            write_csvs(dataset_id, version)
        except Exception:
            logger.exception('Exception writing CSVs %s %s', dataset_id, version)


def main():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ecs_logging.StdlibFormatter())
    logger.addHandler(handler)

    if os.environ.get('SENTRY_DSN'):
        sentry_sdk.init(  # pylint: disable=abstract-class-instantiated
            dsn=os.environ['SENTRY_DSN'],
        )

    parsed_endpoint = urllib.parse.urlsplit(os.environ['AWS_S3_ENDPOINT'])
    PoolClass = \
        urllib3.HTTPConnectionPool if parsed_endpoint.scheme == 'http' else \
        urllib3.HTTPSConnectionPool

    read_and_write_aws_access_key_id = os.environ['READ_AND_WRITE_AWS_ACCESS_KEY_ID']
    read_and_write_aws_secret_access_key = os.environ['READ_AND_WRITE_AWS_SECRET_ACCESS_KEY']
    aws_s3_region = os.environ['AWS_S3_REGION']

    shut_down = threading.Event()

    def run():
        with PoolClass(parsed_endpoint.hostname, port=parsed_endpoint.port, maxsize=1000) as http:
            while True:
                try:
                    ensure_csvs(
                        logger, shut_down,
                        http, parsed_endpoint,
                        read_and_write_aws_access_key_id,
                        read_and_write_aws_secret_access_key,
                        aws_s3_region,
                    )
                except Exception:
                    logger.exception('Failed ensure_csvs')

                if shut_down.wait(timeout=5.0):
                    break

    def stop(_, __):
        shut_down.set()

    signal.signal(signal.SIGTERM, stop)
    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    logger.info('Shut down gracefully')


if __name__ == '__main__':
    main()
