# Don't absolutely need gevent here, but the web application uses gevent, and
# the Python coverage package doesn't support both threads and gevent
from gevent import (
    monkey,
)
monkey.patch_all()

import ecs_logging

from base64 import (
    b64encode,
)
import csv
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

from sqlite_s3_query import sqlite_s3_query

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
        yield from aws_list_folders(signed_s3_request)

    def get_dataset_ids_versions(dataset_ids):
        for dataset_id in dataset_ids:
            for version in aws_list_folders(signed_s3_request, prefix=f'{dataset_id}/'):
                yield dataset_id, version

    def convert_json_to_csvs(dataset_id, version):
        def save_csv(path, chunks):
            table = path.replace('_', '-')  # GDS API guidelines prefer dash to underscore
            s3_key = f'{dataset_id}/{version}/tables/{table}/data.csv'
            aws_multipart_upload(signed_s3_request, s3_key, chunks)

        with signed_s3_request('GET', s3_key=f'{dataset_id}/{version}/data.json') as response:
            if response.status != 200:
                return
            to_csvs(response.stream(65536), save_csv)

    def convert_sqlite_to_csvs(dataset_id, version):

        class PseudoBuffer:
            def write(self, value):
                return value

        def quote_identifier(value):
            return '"' + value.replace('"', '""') + '"'

        def convert_for_csv(value):
            return \
                '#NA' if value is None else \
                b64encode(value).decode() if isinstance(value, bytes) else \
                value

        def csv_data(columns, rows):
            csv_writer = csv.writer(PseudoBuffer(), quoting=csv.QUOTE_NONNUMERIC)
            yield csv_writer.writerow(columns).encode()
            for row in rows:
                yield csv_writer.writerow(convert_for_csv(val) for val in row).encode()

        url = urllib.parse.urlunsplit(parsed_endpoint) + f'{dataset_id}/{version}/data.sqlite'
        with sqlite_s3_query(
                url=url,
                get_credentials=lambda _: (
                    region_name,
                    aws_access_key_id,
                    aws_secret_access_key,
                    None,
                )
        ) as query:

            # Find tables
            with query('''
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY rowid
            ''') as (_, tables):

                for (table_name,) in tables:

                    # Find primary key columns, in correct order
                    table_info_sql = f'PRAGMA table_info({quote_identifier(table_name)})'
                    with query(table_info_sql) as (table_info_cols, table_info_rows):
                        primary_keys = sorted([
                            (table_info_row_dict['pk'], table_info_row_dict['name'])
                            for table_info_row in table_info_rows
                            for table_info_row_dict in [dict(zip(table_info_cols, table_info_row))]
                            if table_info_row_dict['pk']
                        ]) or [(1, 'rowid')]

                    # Save as CSV, with rows ordered by primary kay columns
                    data_sql = f'SELECT * FROM {quote_identifier(table_name)} ORDER BY ' + \
                        ','.join(quote_identifier(key) for (_, key) in primary_keys)
                    with query(data_sql) as (cols, rows):
                        table_id = table_name.replace('_', '-')
                        s3_key = f'{dataset_id}/{version}/tables/{table_id}/data.csv'
                        aws_multipart_upload(signed_s3_request, s3_key, csv_data(cols, rows))

    def save_compressed(dataset_id, version, table, chunks):
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

    dataset_ids = get_dataset_ids()
    dataset_ids_versions = get_dataset_ids_versions(dataset_ids)
    for dataset_id, version in dataset_ids_versions:
        if shut_down.is_set():
            break

        sqlite_s3_key = f'{dataset_id}/{version}/data.sqlite'
        json_s3_key = f'{dataset_id}/{version}/data.json'

        # Decide between SQLite source and JSON source
        status_json, headers_json = aws_head(signed_s3_request, json_s3_key)
        status_sqlite, headers_sqlite = aws_head(signed_s3_request, sqlite_s3_key)

        if status_json == 200 and status_sqlite == 404:
            source_s3_key = json_s3_key
            headers = headers_json
            convert_func = convert_json_to_csvs
        elif status_sqlite == 200:
            source_s3_key = sqlite_s3_key
            headers = headers_sqlite
            convert_func = convert_sqlite_to_csvs
        else:
            continue

        # Skip if we have already converted the source
        etag = headers['etag'].strip('"')
        etag_key = f'{source_s3_key}__CSV_VERSION_{CSV_VERSION}__{etag}'
        status, _ = aws_head(signed_s3_request, etag_key)
        if status == 200:
            continue

        # Convert the source to CSVs
        try:
            convert_func(dataset_id, version)
        except Exception:
            logger.exception('Exception writing CSVs %s %s', dataset_id, version)
            continue

        # Compress the CSVs
        for table in aws_list_folders(signed_s3_request, prefix=f'{dataset_id}/{version}/tables/'):
            csv_s3_key = f'{dataset_id}/{version}/tables/{table}/data.csv'
            with signed_s3_request('GET', s3_key=csv_s3_key) as response:
                if response.status != 200:
                    return
                save_compressed(dataset_id, version, table, response.stream(65536))

        # Re-create the CSVs if the data has since changed...
        status, headers = aws_head(signed_s3_request, source_s3_key)
        if status != 200:
            continue
        if etag != headers['etag'].strip('"'):
            logger.info('Data has changed since starting to generate CSVs')
            continue

        # ... and don't re-create the CSVs if it has not since changed
        with signed_s3_request('PUT', s3_key=etag_key) as response:
            put_response_body = response.read()
            if response.status != 200:
                raise Exception('Error saving etag object {} {} {}'.format(
                    etag_key, response.status, put_response_body))

        logger.info('Saved as CSV %s %s', dataset_id, version)


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
