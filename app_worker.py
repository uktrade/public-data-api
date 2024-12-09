# Don't absolutely need gevent here, but the web application uses gevent, and
# the Python coverage package doesn't support both threads and gevent
from gevent import (
    monkey,
)
monkey.patch_all()

from base64 import (
    b64encode,
)
from contextlib import contextmanager
import csv
from datetime import datetime
from functools import (
    partial,
)
import hashlib
import io
import itertools
import json
import logging
import os
import signal
import sys
import threading
import urllib.parse
from collections import defaultdict

import sentry_sdk
from tidy_json_to_csv import (
    to_csvs,
)
import urllib3
import zlib

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from sqlite_s3_query import sqlite_s3_query_multi
from stream_write_ods import stream_write_ods
from stream_zip import ZipOverflowError

from app_aws import (
    aws_s3_request,
    aws_list_keys,
    aws_list_folders,
    aws_head,
    aws_multipart_upload,
)
from app_heartbeat import (
    heartbeat,
)
from app_logging import (
    ASIMFormatter,
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
            logger.info('Converting %s %s JSON "table" %s to CSV in %s',
                        dataset_id, version, table, s3_key)
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

        def convert_for_json(value):
            return \
                b64encode(value).decode() if isinstance(value, bytes) else \
                value

        def csv_data(columns, rows, with_header):
            csv_writer = csv.writer(PseudoBuffer(), quoting=csv.QUOTE_NONNUMERIC)
            if with_header:
                yield csv_writer.writerow(columns).encode()
            for row in rows:
                yield csv_writer.writerow(convert_for_csv(val) for val in row).encode()

        @contextmanager
        def to_query_single(query_multi, sql, params=()):
            for columns, rows in query_multi(sql, params):
                yield columns, rows
                break

        def get_table_sqls(query):
            with query('''
                SELECT name FROM sqlite_master
                WHERE
                    type = 'table'
                    AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'
                    AND name NOT LIKE '\\_%' ESCAPE '\\'
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

                    data_sql = f'SELECT * FROM {quote_identifier(table_name)} ORDER BY ' + \
                        ','.join(quote_identifier(key) for (_, key) in primary_keys)
                    yield table_name, data_sql

        def fix_ods_types(rows):
            # SQLite doesn't expose type information of query results in all cases, but we want
            # to tell ODS if a value is a date. So we attempt to parse every value as a date, and
            # if it fails, we return it as-is.

            def fix_type(value):
                try:
                    return datetime.strptime(value, '%Y-%m-%d').date()
                except (TypeError, ValueError):
                    return value

            for row in rows:
                yield tuple(fix_type(value) for value in row)

        def to_sheets(query, table_names_sqls, row_fixer):
            for table_name, data_sql in table_names_sqls:
                with query(data_sql) as (cols, rows):
                    yield table_name, cols, row_fixer(rows)

        def stream_write_json(sheets):
            def json_dumps(data):
                return json.dumps(data, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

            def with_is_first(iterable):
                is_first = True
                for val in iterable:
                    yield is_first, val
                    is_first = False

            yield b'{'
            for is_first_table, (table_name, cols, rows) in with_is_first(sheets):
                if not is_first_table:
                    yield b','
                yield json_dumps(table_name) + b':'
                yield b'['
                for is_first_row, row in with_is_first(rows):
                    if not is_first_row:
                        yield b','
                    yield json_dumps(dict(zip(cols, (convert_for_json(val) for val in row))))
                yield b']'
            yield b'}'

        def stream_write_parquet(columns, rows):

            def get_pandas_dfs():
                batch_size = int(os.environ.get('PARQUET_ROW_GROUP_SIZE', 1024 * 128))

                while True:
                    df = pd.DataFrame(itertools.islice(rows, batch_size), columns=columns)
                    if df.empty:
                        break
                    yield df

            # Chunk the rows into batch_size Pandas dataframes
            pandas_dfs = get_pandas_dfs()

            # Infer the schema from the first Pandas dataframe (this is why we convert to Pandas)
            first_df = next(pandas_dfs, None)
            schema = pa.Schema.from_pandas(first_df) if first_df is not None else pa.schema([])

            # Convert the dataframes to PyArrow record batches
            record_batches = (
                pa.RecordBatch.from_pandas(df, schema=schema, preserve_index=False, nthreads=1)
                for df in itertools.chain((first_df,) if first_df is not None else (), pandas_dfs)
            )
            first_df = None  # Free memory used by the first dataframe

            # Write the record batches to an in-memory file-like object, yielding bytes as we go
            with io.BytesIO() as file:
                with pq.ParquetWriter(file, schema=schema) as writer:
                    for record_batch in record_batches:
                        writer.write_batch(record_batch)
                        yield file.getvalue()
                        file.truncate(0)
                        file.seek(0)
                yield file.getvalue()

        url = urllib.parse.urlunsplit(parsed_endpoint) + f'{dataset_id}/{version}/data.sqlite'
        with sqlite_s3_query_multi(
                url=url,
                get_credentials=lambda _: (
                    region_name,
                    aws_access_key_id,
                    aws_secret_access_key,
                    None,
                )
        ) as query_multi:

            query = partial(to_query_single, query_multi)

            # Convert SQLite to an ODS file
            s3_key = f'{dataset_id}/{version}/data.ods'
            logger.info('Converting %s %s SQLite to ODS in %s', dataset_id, version, s3_key)

            def sqlite_to_ods(use_zip_64):
                ods_sheets = to_sheets(query, get_table_sqls(query), fix_ods_types)
                aws_multipart_upload(signed_s3_request, s3_key,
                                     stream_write_ods(ods_sheets, use_zip_64=use_zip_64))
            try:
                sqlite_to_ods(use_zip_64=False)
            except ZipOverflowError:
                logger.info('ODS of entire SQLite would large, retrying with Zip64')
                sqlite_to_ods(use_zip_64=True)

            # Convert SQLite to JSON
            s3_key = f'{dataset_id}/{version}/data.json'
            json_sheets = to_sheets(query, get_table_sqls(query), lambda r: r)
            logger.info('Converting %s %s SQLite to JSON in %s', dataset_id, version, s3_key)
            aws_multipart_upload(signed_s3_request, s3_key, stream_write_json(json_sheets))

            for table_name, data_sql in get_table_sqls(query):
                table_id = table_name.replace('_', '-')

                # Save as CSV, with rows ordered by primary kay columns
                with query(data_sql) as (cols, rows):
                    s3_key = f'{dataset_id}/{version}/tables/{table_id}/data.csv'
                    logger.info('Converting %s %s SQLite table %s to CSV in %s', dataset_id,
                                version, table_name, s3_key)
                    aws_multipart_upload(signed_s3_request, s3_key,
                                         csv_data(cols, rows, with_header=True))

                # Save as parquet file
                with query(data_sql) as (cols, rows):
                    s3_key = f'{dataset_id}/{version}/tables/{table_id}/data.parquet'
                    logger.info('Converting %s %s SQLite table %s to Parquet in %s', dataset_id,
                                version, table_name, s3_key)
                    try:
                        aws_multipart_upload(signed_s3_request, s3_key,
                                             stream_write_parquet(cols, rows))
                    except pa.ArrowException:
                        logger.exception('Unable to convert to parquet')

                # And save as a single ODS file
                s3_key = f'{dataset_id}/{version}/tables/{table_id}/data.ods'
                logger.info('Converting %s %s SQLite table %s to ODS in %s', dataset_id,
                            version, table_name, s3_key)

                def sqlite_tbl_to_ods(data_sql, table_name, use_zip_64):
                    with query(data_sql) as (cols, rows):
                        ods_sheets = ((table_name, cols, fix_ods_types(rows)),)
                        aws_multipart_upload(signed_s3_request, s3_key,
                                             stream_write_ods(ods_sheets, use_zip_64=use_zip_64))
                try:
                    sqlite_tbl_to_ods(data_sql, table_name, use_zip_64=False)
                except ZipOverflowError:
                    logger.info(f'ODS of SQLite table {table_name} too large, retrying with Zip64')
                    sqlite_tbl_to_ods(data_sql, table_name, use_zip_64=True)

            # Run all reports and save as CSVs
            with query('''
                SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_reports'
            ''') as (_, rows):
                if not list(rows):
                    return

            # Multi SQL scripts can contain statements that don't return rows, as well as multiple
            # SELECT statements. We attempt to iterate over all the statements in order for them
            # to be executed, but if they have no rows then they're not attempted to be uploaded
            # as CSVs. If there are multiple SELECT statements, then the last one wins.
            def with_non_zero_rows(it):
                for cols, rows in it:
                    for row in rows:
                        yield (cols, itertools.chain((row,), rows))

            def get_num_statements_with_rows(query_multi, script):
                return sum(1 for _ in with_non_zero_rows(query_multi(script)))

            # Load reports into memory to not hold open a SQLite statement which can lock tables
            with query('''
                SELECT name, script FROM _reports ORDER BY rowid
            ''') as (_, reports_rows):
                reports = tuple(reports_rows)

            for name, script in reports:
                report_id = name.replace('_', '-')

                logger.info('Converting %s %s SQLite report %s to ODS in %s',
                            dataset_id, version, report_id, s3_key)

                # Is this multi-statement query?
                num_statements = get_num_statements_with_rows(query_multi, script)

                # Save as CSV with the results of all statements concatanated together ...
                s3_key = f'{dataset_id}/{version}/reports/{report_id}/data.csv'
                csv_lines = (
                    line
                    for i, (cols, rows) in enumerate(with_non_zero_rows(query_multi(script)))
                    for line in csv_data(cols, rows, with_header=i == 0)
                )
                logger.info('Converting %s %s SQLite report %s to combined CSV in %s',
                            dataset_id, version, report_id, s3_key)
                aws_multipart_upload(signed_s3_request, s3_key, csv_lines)

                # .. and as Parquet with the results of all statements concatanated together ...
                s3_key = f'{dataset_id}/{version}/reports/{report_id}/data.parquet'
                logger.info('Converting %s %s SQLite report %s to combined Parquet in %s',
                            dataset_id, version, report_id, s3_key)
                all_cols_rows = with_non_zero_rows(query_multi(script))
                cols, first_rows = next(all_cols_rows)
                rows = itertools.chain(first_rows, (
                    row
                    for (_, rows_in_query) in all_cols_rows
                    for row in rows_in_query
                ))
                try:
                    aws_multipart_upload(signed_s3_request, s3_key,
                                         stream_write_parquet(cols, rows))
                except pa.ArrowException:
                    logger.exception('Unable to convert to parquet')

                # ... and as ODS with the results of each statement as a separate sheet
                s3_key = f'{dataset_id}/{version}/reports/{report_id}/data.ods'
                logger.info('Converting %s %s SQLite report %s to combined ODS in %s',
                            dataset_id, version, report_id, s3_key)

                def sqlite_report_to_ods(num_statements, name, script, use_zip_64):
                    sheets = (
                        (f'Section {i+1}' if num_statements > 1 else name, cols, rows)
                        for i, (cols, rows) in enumerate(with_non_zero_rows(query_multi(script)))
                    )
                    aws_multipart_upload(signed_s3_request, s3_key,
                                         stream_write_ods(sheets, use_zip_64=use_zip_64))
                try:
                    sqlite_report_to_ods(num_statements, name, script, use_zip_64=False)
                except ZipOverflowError:
                    logger.info(f'ODS of SQLite report {name} too large, retrying with Zip64')
                    sqlite_report_to_ods(num_statements, name, script, use_zip_64=True)

    def save_compressed(s3_key, chunks):
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

        aws_multipart_upload(signed_s3_request, s3_key, yield_compressed_bytes(chunks))

    def save_data_json_metadata(dataset_id):
        def semver_key(path):
            v_major_str, minor_str, patch_str = path.split('.')
            return (int(v_major_str[1:]), int(minor_str), int(patch_str))

        def url_for(version, relative_url):
            return urllib.parse.urljoin(
                os.environ['DOCS_BASE_URL'],
                f'v1/datasets/{dataset_id}/versions/{version}/{relative_url}',
            )

        def flatten(list_of_lists):
            return [item for sublist in list_of_lists for item in sublist]

        logger.info('Updating data.json for %s', dataset_id)

        # Fetch all metadata files
        metadatas = {}
        for key_suffix in aws_list_keys(signed_s3_request, dataset_id + '/'):
            components = key_suffix.split('/')
            if len(components) == 2 and components[1] == 'metadata--csvw.json':
                version = components[0]
                with signed_s3_request('GET', s3_key=dataset_id + '/' + key_suffix) as response:
                    try:
                        metadatas[version] = json.loads(response.read())
                    except json.JSONDecodeError:
                        logger.exception('Skipping %s/%s metadata', dataset_id, version)

        if not metadatas:
            return

        # Sort metadatas by semver, to have most recent at the start
        metadatas = dict(
            sorted(
                metadatas.items(),
                key=lambda key_value: semver_key(key_value[0]),
                reverse=True,
            )
        )

        # Choose most recent metadata as the one for the title
        metadata_recent = metadatas[next(iter(metadatas.keys()))]

        # Ideally each identifier is an URL with an HTML page, but doesn't have to be. So for now,
        # it's not. It's also deliberately not a URL to a specific version of this API, since even
        # in later versions, this identifier must be the same
        identifier_root = os.environ['DOCS_BASE_URL']

        data_json_metadata = json.dumps(
            {
                'dataset': [
                    {
                        'identifier': f'{identifier_root}/datasets/{dataset_id}',
                        'title': metadata_recent['dc:title'],
                        'description': metadata_recent['dc:description'],
                        'license': metadata_recent.get('dc:license'),
                        'publisher': {
                            'name': metadata_recent['dc:creator'],
                        },
                        'distribution': flatten(
                            [
                                {
                                    'title': f'{version} - Metadata',
                                    'format': 'HTML',
                                    'downloadURL': url_for(
                                        version, 'metadata?format=html'
                                    ),
                                }
                            ]
                            + [
                                {
                                    'title': f'{version} - {database["dc:title"]}',
                                    'format': 'SQLite',
                                    'downloadURL': url_for(
                                        version, database['url']
                                    ),
                                }
                                for database in metadata.get('dit:databases', [])
                            ]
                            + [
                                {
                                    'title': f'{version} - {table["dc:title"]}',
                                    'format': 'CSV',
                                    'downloadURL': url_for(
                                        version, table['url']
                                    ),
                                }
                                for table in metadata['tables']
                            ]
                            for (version, metadata) in metadatas.items()
                        ),
                    }
                ]
            }
        ).encode('utf-8')
        s3_key = f'{dataset_id}/data.json'
        with signed_s3_request('PUT', s3_key=s3_key, body=data_json_metadata) as response:
            put_response_body = response.read()
            if response.status != 200:
                raise Exception(
                    f'Error saving etag object {s3_key} {response.status} {put_response_body}')

    dataset_ids = get_dataset_ids()
    dataset_ids_versions = get_dataset_ids_versions(dataset_ids)
    dataset_ids_hash = defaultdict(hashlib.sha256)

    for dataset_id, version in dataset_ids_versions:
        if shut_down.is_set():
            break

        sqlite_s3_key = f'{dataset_id}/{version}/data.sqlite'
        json_s3_key = f'{dataset_id}/{version}/data.json'

        # Decide between SQLite source and JSON source
        status_json, headers_json = aws_head(signed_s3_request, json_s3_key)
        status_sqlite, headers_sqlite = aws_head(signed_s3_request, sqlite_s3_key)

        if status_json == 200 and status_sqlite == 404:
            logger.debug('Source format of %s %s is JSON', dataset_id, version)
            source_s3_key = json_s3_key
            headers = headers_json
            convert_func = convert_json_to_csvs
        elif status_sqlite == 200:
            logger.debug('Source format of %s %s is SQLite', dataset_id, version)
            source_s3_key = sqlite_s3_key
            headers = headers_sqlite
            convert_func = convert_sqlite_to_csvs
        else:
            logger.warning('Unknown source format of %s %s - skipping', dataset_id, version)
            continue

        # Hash all the etags to make sure we (re)generate the metadata json file
        etag = headers['etag'].strip('"')
        etag_key = f'{source_s3_key}__CSV_VERSION_{CSV_VERSION}__{etag}'
        dataset_ids_hash[dataset_id].update(etag_key.encode())

        # Skip if we have already converted the source
        status, _ = aws_head(signed_s3_request, etag_key)
        if status == 200:
            logger.debug('Have already converted %s %s to other formats', dataset_id, version)
            continue

        # Convert the source to CSVs
        logger.info('Converting %s %s to other formats', dataset_id, version)

        try:
            convert_func(dataset_id, version)
        except Exception:
            logger.exception('Exception writing CSVs %s %s', dataset_id, version)
            continue

        # Compress the CSVs
        logger.info('Compressing %s %s CSVs', dataset_id, version)

        prefixes = (f'{dataset_id}/{version}/tables/', f'{dataset_id}/{version}/reports/')
        for prefix in prefixes:
            for table in aws_list_folders(signed_s3_request, prefix=prefix):
                csv_s3_key = f'{prefix}{table}/data.csv'
                logger.info('Compressing %s %s CSV table/report %s to %s',
                            dataset_id, version, table, csv_s3_key)
                with signed_s3_request('GET', s3_key=csv_s3_key) as response:
                    if response.status != 200:
                        return
                    save_compressed(f'{csv_s3_key}.gz', response.stream(65536))

        # Compress the source file
        with signed_s3_request('GET', s3_key=source_s3_key) as response:
            if response.status != 200:
                continue
            logger.info('Compressing %s %s source file', dataset_id, version)
            save_compressed(source_s3_key + '.gz', response.stream(65536))

        # Re-create the CSVs if the data has since changed...
        status, headers = aws_head(signed_s3_request, source_s3_key)
        if status != 200:
            continue
        if etag != headers['etag'].strip('"'):
            logger.info('Data has changed since starting to generate CSVs')
            continue

        # ... and don't re-create the CSVs if it has not since changed
        logger.info('Putting %s %s etag key at %s', dataset_id, version, etag_key)
        with signed_s3_request('PUT', s3_key=etag_key) as response:
            put_response_body = response.read()
            if response.status != 200:
                raise Exception(
                    f'Error saving etag object {etag_key,} {response.status} {put_response_body}')

        logger.info('Saved as CSV %s %s', dataset_id, version)

    def get(s3_key):
        with signed_s3_request('GET', s3_key=s3_key) as response:
            body = response.read()
            if response.status == 200:
                return body
        return b''

    # Save all the metadata files (done at the end so we have definitely done all the conversions)
    for dataset_id, sha256 in dataset_ids_hash.items():
        if shut_down.is_set():
            break
        digest = sha256.hexdigest().encode()
        hash_key = f'{dataset_id}/sha256'
        if get(hash_key) == digest:
            continue
        save_data_json_metadata(dataset_id)
        with signed_s3_request('PUT', s3_key=hash_key, body=digest) as response:
            put_response_body = response.read()
            if response.status != 200:
                raise Exception(
                    f'Error saving sha256 of {dataset_id} {response.status} {put_response_body}')


def main():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ASIMFormatter())
    logger.addHandler(handler)

    # Converting SQLite files makes many HTTP requests (in the hundreds of thousands level for
    # the UK Tariff) and the INFO log level makes the logs too noisy to be very useful
    httpxLogger = logging.getLogger('httpx')
    httpxLogger.setLevel(logging.WARNING)

    if os.environ.get('SENTRY_DSN'):
        sentry_sdk.init(  # pylint: disable=abstract-class-instantiated
            dsn=os.environ['SENTRY_DSN'],
            enable_tracing=True,
        )

    parsed_endpoint = urllib.parse.urlsplit(os.environ['AWS_S3_ENDPOINT'])
    PoolClass = \
        urllib3.HTTPConnectionPool if parsed_endpoint.scheme == 'http' else \
        urllib3.HTTPSConnectionPool

    read_and_write_aws_access_key_id = os.environ['READ_AND_WRITE_AWS_ACCESS_KEY_ID']
    read_and_write_aws_secret_access_key = os.environ['READ_AND_WRITE_AWS_SECRET_ACCESS_KEY']
    aws_s3_region = os.environ['AWS_S3_REGION']

    shut_down = threading.Event()
    shut_down_heartbeat = threading.Event()

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

    logger.info('Starting heartbeat')
    heartbeat_thread = threading.Thread(target=heartbeat, kwargs={
        'logger': logger,
        'shut_down_heartbeat': shut_down_heartbeat,
        'thread': thread,
    })
    heartbeat_thread.start()

    thread.join()

    logger.info('Shutting down heartbeat')
    shut_down_heartbeat.set()
    heartbeat_thread.join()
    logger.info('Shut down heartbeat')

    sentry_client = sentry_sdk.Hub.current.client
    if sentry_client is not None:
        sentry_client.close(timeout=2.0)
    logger.info('Shut down gracefully')


if __name__ == '__main__':
    main()
