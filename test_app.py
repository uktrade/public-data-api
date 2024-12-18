# pylint: disable=unused-argument

from base64 import (
    b64encode,
)
from contextlib import contextmanager
from datetime import (
    datetime,
)
import hashlib
import hmac
import gzip
import itertools
import json
import os
import tempfile
import time
import shlex
import sqlite3
import socket
import subprocess
import urllib.parse
import uuid
from pathlib import Path
from xml.etree import (
    ElementTree as ET,
)
import zlib

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
import requests


@contextmanager
def application(port=8080, max_attempts=500, aws_access_key_id='AKIAIOSFODNN7EXAMPLE', sleep=0):
    outputs = {}

    put_object_no_raise('', b'')  # Ensures bucket created
    put_object('', '''
        <VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <Status>Enabled</Status>
        </VersioningConfiguration>
    '''.encode(), params=(('versioning', ''),))
    delete_all_objects()
    with open('Procfile', 'r', encoding='utf-8') as file:
        lines = file.read().splitlines()

    process_definitions = {
        name.strip(): shlex.split(args)
        for line in lines + [
            '__sentry: python -m mock_sentry_app',
            '__google_analytics: python -m mock_google_analytics_app',
        ]
        for name, args in [line.split(':')]
    }

    process_outs = {
        name: (tempfile.NamedTemporaryFile(delete=False),
               tempfile.NamedTemporaryFile(delete=False))
        for name, _ in process_definitions.items()
    }

    processes = {
        name: subprocess.Popen(
            args,
            stdout=process_outs[name][0],
            stderr=process_outs[name][1],
            env={
                **os.environ,
                'PORT': str(port),
                'DOCS_BASE_URL': 'http://127.0.0.1:8080',
                'AWS_S3_REGION': 'us-east-1',
                'PARQUET_ROW_GROUP_SIZE': '1024',
                'READONLY_AWS_ACCESS_KEY_ID': aws_access_key_id,
                'READONLY_AWS_SECRET_ACCESS_KEY': (
                    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
                ),
                'READ_AND_WRITE_AWS_ACCESS_KEY_ID': aws_access_key_id,
                'READ_AND_WRITE_AWS_SECRET_ACCESS_KEY': (
                    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
                ),
                'AWS_S3_ENDPOINT': 'http://127.0.0.1:9000/my-bucket/',
                'ENVIRONMENT': 'test',
                'SENTRY_DSN': 'http://foo@localhost:9003/1',
                'GA_ENDPOINT': 'http://localhost:9002/collect',
                'GA_TRACKING_ID': 'XX-XXXXX-X',
            }
        )
        for name, args in process_definitions.items()
    }

    def read_and_close(f):
        f.seek(0)
        contents = f.read()
        f.close()
        return contents

    def stop():
        time.sleep(0.10)  # Sentry needs some extra time to log any errors
        time.sleep(sleep)
        for _, process in processes.items():
            process.terminate()
        for _, process in processes.items():
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
        output_errors = {
            name: (read_and_close(stdout), read_and_close(stderr))
            for name, (stdout, stderr) in process_outs.items()
        }

        return output_errors

    try:
        for i in range(0, max_attempts):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    break
            except (OSError, ConnectionRefusedError):
                if i == max_attempts - 1:
                    raise
                time.sleep(0.02)

        yield (processes, outputs)
    finally:
        outputs.update(stop())
        delete_all_objects()


@pytest.fixture(name='processes')
def fixture_processes():
    with application() as (processes, outputs):
        yield (processes, outputs)


@pytest.fixture(name='processes_bad_key')
def fixture_processes_bad_key():
    with application(aws_access_key_id='not-exist') as (processes, outputs):
        yield (processes, outputs)


def test_meta_application_fails():
    with pytest.raises(ConnectionError):
        application(max_attempts=1).__enter__()  # pylint: disable=no-member


def get_sqlite_data():
    with tempfile.NamedTemporaryFile() as f:
        with sqlite3.connect(f.name) as con:
            cur = con.cursor()

            cur.execute('''
                CREATE TABLE my_table (
                    col_blob blob
                )
            ''')
            cur.execute('INSERT INTO my_table VALUES (?)',
                        (str(uuid.uuid4()).encode() * 100000,))

        return f.read()


def get_json_data():
    return json.dumps({'top': [{'col': str(uuid.uuid4()) * 100000}]}).encode()


def gzip_compress(source):
    def _chunks():
        compress_obj = zlib.compressobj(wbits=31)
        compressed_bytes = compress_obj.compress(source)
        if compressed_bytes:
            yield compressed_bytes

        compressed_bytes = compress_obj.flush()
        if compressed_bytes:
            yield compressed_bytes

    return b''.join(_chunks())


@pytest.mark.parametrize('encoding,compressor', (
    ('gzip', gzip_compress),
    (None, lambda x: x),
))
@pytest.mark.parametrize('requested_format,expected_content_type,get_content', (
    ('json', 'application/json', get_json_data),
    ('sqlite', 'application/vnd.sqlite3', get_sqlite_data),
))
def test_key_that_exists(processes, encoding, compressor, requested_format,
                         expected_content_type, get_content):
    dataset_id = str(uuid.uuid4())
    content = get_content()
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, requested_format)

    url = version_data_public_url(dataset_id, version, requested_format)
    headers = {'accept-encoding': encoding}

    # Wait for the backend to convert/compress the data if necessary
    for _ in range(0, 24):
        with \
                requests.Session() as session, \
                session.get(url, headers=headers) as response:

            if (
                response.status_code != 200
                or response.headers.get('content-type') != expected_content_type
                or response.headers.get('content-encoding') != encoding
            ):
                time.sleep(10)
            else:
                break

    with \
            requests.Session() as session, \
            session.get(url, headers=headers) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(compressor(content)))
        assert response.headers['content-type'], expected_content_type
        assert response.headers.get('content-encoding') == encoding
        assert 'content-disposition' not in response.headers
        assert not response.history

    url = version_data_public_url_download(dataset_id, version, requested_format)
    headers = {'accept-encoding': encoding}
    with \
            requests.Session() as session, \
            session.get(url, headers=headers) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(compressor(content)))
        assert response.headers['content-type'] == expected_content_type
        assert response.headers.get('content-encoding') == encoding
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}.{requested_format}"'
        assert not response.history


def test_sqlite_conversion_to_ods(processes):
    dataset_id = str(uuid.uuid4())
    version = 'v0.0.1'

    def get_sqlite_with_multiple_tables():
        with tempfile.NamedTemporaryFile() as f:
            with sqlite3.connect(f.name) as con:
                cur = con.cursor()

                cur.execute('''
                    CREATE TABLE my_table_a (
                        col_text TEXT,
                        col_int INTEGER,
                        col_date DATE
                    )
                ''')
                cur.execute('INSERT INTO my_table_a VALUES ("One", 1, "2021-01-02")')
                cur.execute('INSERT INTO my_table_a VALUES ("Two", 2, "2021-01-03")')
                cur.execute('''
                    CREATE TABLE my_table_b (
                        col_text TEXT,
                        col_int INTEGER
                    )
                ''')
                cur.execute('INSERT INTO my_table_b VALUES ("Three", 3)')
                cur.execute('INSERT INTO my_table_b VALUES ("Four", 4)')

            return f.read()

    put_version_data(dataset_id, version, get_sqlite_with_multiple_tables(), 'sqlite')

    time.sleep(20)

    url = version_data_public_url_download(dataset_id, version, 'ods')
    with \
            requests.Session() as session, \
            session.get(url) as response:
        assert response.headers['content-type'] == 'application/vnd.oasis.opendocument.spreadsheet'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}.ods"'
        assert not response.history

        with tempfile.NamedTemporaryFile() as f:
            f.write(response.content)
            f.flush()
            report_a = pd.read_excel(f.name, 'my_table_a')
            report_a_rows = report_a.values.tolist()
            report_a_cols = report_a.columns.tolist()
            report_b = pd.read_excel(f.name, 'my_table_b')
            report_b_rows = report_b.values.tolist()
            report_b_cols = report_b.columns.tolist()

    assert report_a_cols == ['col_text', 'col_int', 'col_date', ]
    assert report_a_rows == [
        ['One', 1.0, pd.Timestamp('2021-01-02')],
        ['Two', 2.0, pd.Timestamp('2021-01-03')],
    ]
    assert report_b_cols == ['col_text', 'col_int', ]
    assert report_b_rows == [['Three', 3.0], ['Four', 4.0]]


def test_metadata_key_that_exists(processes):
    dataset_id = str(uuid.uuid4())
    content = json.dumps({
        'dc:title': 'The title of the dataset',
        'tables': [
            {
                'dc:title': 'The first table',
                'url': 'tables/the-first-table/data?format=csv&download',
                'tableSchema': {'columns': []}
            },
            {
                'dc:title': 'The second table',
                'url': 'tables/the-second-table/data?format=csv&download',
                'tableSchema': {'columns': []}
            },
            {
                'dc:title': 'The first report',
                'url': 'reports/the-first-report/data?format=csv&download',
                'tableSchema': {'columns': []}
            },
            {
                'dc:title': 'The second report',
                'url': 'reports/the-second-report/data?format=csv&download',
                'tableSchema': {'columns': []}
            },
        ]
    }).encode('utf-8')
    version = 'v0.0.1'
    put_version('table', dataset_id, version, 'the-first-table',
                b'header\n' + b'value\n' * 10000)
    put_version('table', dataset_id, version, 'the-second-table',
                b'header\n' + b'value\n' * 1000000)
    put_version('report', dataset_id, version, 'the-first-report',
                b'header\n' + b'value\n' * 20000)
    put_version('report', dataset_id, version, 'the-second-report',
                b'header\n' + b'value\n' * 2000000)
    put_version_metadata(dataset_id, version, content)

    with \
            requests.Session() as session, \
            session.get(version_metadata_public_url(dataset_id, version)) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'application/csvm+json'
        assert 'content-disposition' not in response.headers
        assert not response.history

    with \
            requests.Session() as session, \
            session.get(version_metadata_public_url_download(dataset_id, version)) as response:
        assert response.content in content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'application/csvm+json'
        assert response.headers[
            'content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}--metadata--csvw.json"'
        assert not response.history

    with \
            requests.Session() as session, \
            session.get(version_metadata_public_html_url(dataset_id, version)) as response:
        assert b'The title of the dataset - v0.0.1' in response.content
        assert b'60.0 kB' in response.content
        assert b'6.0 MB' in response.content
        assert b'120.0 kB' in response.content
        assert b'12.0 MB' in response.content
        assert datetime.now().strftime('%d %B %Y').encode() in response.content
        assert b'?format=csvw&amp;download"' in response.content
        assert response.headers['content-type'] == 'text/html'
        assert 'content-disposition' not in response.headers
        assert not response.history

    content = json.dumps({
        'dc:title': 'The updated title of the dataset',
        'dc:description': 'The updated description',
        'dc:license': 'http://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/',
        'dc:creator': 'The creator',
        'dit:databases': [{
            'dc:title': 'Data',
            'url': 'data?format=sqlite&download'
        }],
        'tables': [
            {
                'dc:title': 'The first table',
                'url': 'tables/the-first-table/data?format=csv&download',
                'tableSchema': {'columns': []}
            },
            {
                'dc:title': 'The second table',
                'url': 'tables/the-second-table/data?format=csv&download',
                'tableSchema': {'columns': []}
            },
            {
                'dc:title': 'The first report',
                'url': 'reports/the-first-report/data?format=csv&download',
                'tableSchema': {'columns': []}
            },
            {
                'dc:title': 'The second report',
                'url': 'reports/the-second-report/data?format=csv&download',
                'tableSchema': {'columns': []}
            },
        ]
    }).encode('utf-8')
    version = 'v0.0.2'
    put_version('table', dataset_id, version, 'the-first-table',
                b'header\n' + b'value\n' * 10000)
    put_version('table', dataset_id, version, 'the-second-table',
                b'header\n' + b'value\n' * 1000000)
    put_version('report', dataset_id, version, 'the-first-report',
                b'header\n' + b'value\n' * 20000)
    put_version('report', dataset_id, version, 'the-second-report',
                b'header\n' + b'value\n' * 2000000)
    put_version_data(dataset_id, version, get_sqlite_data(), 'sqlite')
    put_version_metadata(dataset_id, version, content)

    with \
            requests.Session() as session, \
            session.get(version_metadata_public_html_url(dataset_id, version)) as response:
        assert b'The updated title of the dataset - v0.0.2' in response.content
        assert b'(SQLite, 3.6 MB)' in response.content

    time.sleep(36)

    with \
            requests.Session() as session, \
            session.get(dataset_metadata_public_url(dataset_id)) as response:
        dataset_metadata = response.json()
        assert dataset_metadata == {'dataset': [{
            'identifier': f'http://127.0.0.1:8080/datasets/{dataset_id}',
            'title': 'The updated title of the dataset',
            'description': 'The updated description',
            'license': 'http://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/',
            'publisher': {
                'name': 'The creator',
            },
            'distribution': [{
                'title': 'v0.0.2 - Metadata',
                'format': 'HTML',
                'downloadURL': version_metadata_public_html_url(dataset_id, 'v0.0.2'),
            }, {
                'title': 'v0.0.2 - Data',
                'format': 'SQLite',
                'downloadURL': version_data_public_url_download(dataset_id, 'v0.0.2', 'sqlite'),
            }, {
                'title': 'v0.0.2 - The first table',
                'format': 'CSV',
                'downloadURL': version_public_url_download('table', dataset_id,
                                                           'v0.0.2', 'the-first-table', 'csv'),
            }, {
                'title': 'v0.0.2 - The second table',
                'format': 'CSV',
                'downloadURL': version_public_url_download('table', dataset_id,
                                                           'v0.0.2', 'the-second-table', 'csv'),
            }, {
                'title': 'v0.0.2 - The first report',
                'format': 'CSV',
                'downloadURL': version_public_url_download('report', dataset_id,
                                                           'v0.0.2', 'the-first-report', 'csv'),
            }, {
                'title': 'v0.0.2 - The second report',
                'format': 'CSV',
                'downloadURL': version_public_url_download('report', dataset_id,
                                                           'v0.0.2', 'the-second-report', 'csv'),
            }, {
                'title': 'v0.0.1 - Metadata',
                'format': 'HTML',
                'downloadURL': version_metadata_public_html_url(dataset_id, 'v0.0.1'),
            }, {
                'title': 'v0.0.1 - The first table',
                'format': 'CSV',
                'downloadURL': version_public_url_download('table', dataset_id,
                                                           'v0.0.1', 'the-first-table', 'csv'),
            }, {
                'title': 'v0.0.1 - The second table',
                'format': 'CSV',
                'downloadURL': version_public_url_download('table', dataset_id,
                                                           'v0.0.1', 'the-second-table', 'csv'),
            }, {
                'title': 'v0.0.1 - The first report',
                'format': 'CSV',
                'downloadURL': version_public_url_download('report', dataset_id,
                                                           'v0.0.1', 'the-first-report', 'csv'),
            }, {
                'title': 'v0.0.1 - The second report',
                'format': 'CSV',
                'downloadURL': version_public_url_download('report', dataset_id,
                                                           'v0.0.1', 'the-second-report', 'csv'),
            }]
        }]}


def test_metadata_key_that_does_not_exist(processes):
    with \
            requests.Session() as session, \
            session.get(dataset_metadata_public_url('not-exist')) as response:
        assert response.status_code == 404


def test_table_key_that_exists(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    table = 'table'
    version = 'v0.0.1'
    put_version('table', dataset_id, version, table, content)

    with \
            requests.Session() as session, \
            session.get(version_public_url('table', dataset_id,
                                           version, table, 'csv')) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'text/csv'
        assert 'content-disposition' not in response.headers
        assert not response.history

    with \
            requests.Session() as session, \
            session.get(version_public_url_download('table', dataset_id,
                                                    version, table, 'csv')) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}--{table}.csv"'
        assert not response.history


@pytest.mark.parametrize('table_or_report,expected_filename_format', (
    ('table', '{dataset_id}--{version}--{table}.csv'),
    ('report', '{dataset_id}--{version}--report--{table}.csv'),
))
def test_table_gzipped(processes, table_or_report, expected_filename_format):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    table = 'table'
    version = 'v0.0.1'
    expected_filename = expected_filename_format.format(
        dataset_id=dataset_id, version=version, table=table)

    put_version(table_or_report, dataset_id, version, table, content)
    put_version_gzipped(table_or_report, dataset_id, version, table, content)

    with \
            requests.Session() as session, \
            session.get(version_public_url_download(table_or_report, dataset_id,
                                                    version, table, 'csv'),
                        headers={'accept-encoding': None}
                        ) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{expected_filename}"'
        assert 'content-encoding' not in response.headers
        assert not response.history

    with \
            requests.Session() as session, \
            session.get(version_public_url_download(table_or_report, dataset_id,
                                                    version, table, 'csv'),
                        headers={'accept-encoding': 'gzip'}
                        ) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(gzip.compress(content)))
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-encoding'] == 'gzip'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{expected_filename}"'
        assert not response.history


def test_table_serves_uncompressed_if_gzip_file_does_not_exist(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    table = 'table'
    version = 'v0.0.1'
    put_version('table', dataset_id, version, table, content)

    with \
            requests.Session() as session, \
            session.get(version_public_url_download('table', dataset_id, version, table, 'csv'),
                        headers={'accept-encoding': 'gzip'}
                        ) as response:
        assert response.content, content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}--{table}.csv"'
        assert 'content-encoding' not in response.headers
        assert not response.history


def test_table_serves_uncompressed_if_s3_select_query_provided(processes):
    dataset_id = str(uuid.uuid4())
    content = \
        'col_a,col_b\na,b\nc🍰é,d\ne,d\n&>,d\n' \
        '"Ah, a comma",d\n"A quote "" ",d\n\\u00f8C,d'.encode(
            'utf-8')
    table = 'table'
    version = 'v0.0.1'
    put_version('table', dataset_id, version, table, content)
    put_version_gzipped('table', dataset_id, version, table, content)
    params = {
        'query-s3-select': 'SELECT col_a FROM S3Object[*] WHERE col_b = \'d\''
    }
    with \
            requests.Session() as session, \
            session.get(version_public_url_download('table', dataset_id, version, table, 'csv'),
                        params=params, headers={'accept-encoding': 'gzip'}
                        ) as response:
        assert response.content == \
            'c🍰é\ne\n&>' '\n"Ah, a comma"\n"A quote "" "\n\\u00f8C\n'.encode('utf-8')
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}--{table}.csv"'
        assert 'content-encoding' not in response.headers
        assert not response.history


def test_table_s3_select(processes):
    dataset_id = str(uuid.uuid4())
    # Note that unlike JSON, a unicode escape sequence like \u00f8C is not an encoded
    # character, it is just a sequences of characters that looks like a unicode escape
    # sequence. So we assert that it goes through unchanged to make sure no JSON-like
    # proccessing is applied to the CSV
    content = \
        'col_a,col_b\na,b\nc🍰é,d\ne,d\n&>,d\n' \
        '"Ah, a comma",d\n"A quote "" ",d\n\\u00f8C,d'.encode(
            'utf-8')
    table = 'table'
    version = 'v0.0.1'
    put_version('table', dataset_id, version, table, content)
    params = {
        'query-s3-select': 'SELECT col_a FROM S3Object[*] WHERE col_b = \'d\''
    }
    with \
            requests.Session() as session, \
            session.get(version_public_url_download('table', dataset_id, version, table, 'csv'),
                        params=params) as response:
        assert response.content == \
            'c🍰é\ne\n&>' '\n"Ah, a comma"\n"A quote "" "\n\\u00f8C\n'.encode('utf-8')
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}--{table}.csv"'
        assert not response.history


@pytest.mark.parametrize('table_or_report', (
    'table',
    'report',
))
def test_filter_rows(processes, table_or_report):
    dataset_id = str(uuid.uuid4())
    content = json.dumps({
        'dc:title': 'The title of the dataset',
        'tables': [
            {
                'url': f'{table_or_report}s/the-first-table/data?format=csv&download',
                'dc:title': 'First table title',
                'tableSchema': {'columns': [
                    {
                        'name': 'id_field',
                        'dc:description': 'An ID field',
                        'dit:filterable': True
                    },
                    {
                        'name': 'name_field',
                        'dc:description': 'A name field',
                        'dit:filterable': False
                    },
                ]}
            },
        ]

    }).encode('utf-8')
    version = 'v0.0.1'
    contents = b'id_field,name_field\n' + b'1,test\n'
    put_version(table_or_report, dataset_id, version, 'the-first-table', contents)
    put_version_metadata(dataset_id, version, content)

    with \
            requests.Session() as session, \
            session.get(version_filter_rows(table_or_report, dataset_id,
                                            version,
                                            'the-first-table')
                        ) as response:
        assert b'Table: First table title' in response.content
        assert b'id_field' in response.content
        assert b'An ID field' in response.content
        # name_field has dit:filterable set to False so should not be available to filter on
        assert b'name_field' not in response.content
        assert b'A name field' not in response.content


@pytest.mark.parametrize('table_or_report,expected_filename_format', (
    ('table', '{dataset_id}--{version}--{table}.csv'),
    ('report', '{dataset_id}--{version}--report--{table}.csv'),
))
def test_filter_columns(processes, table_or_report, expected_filename_format):
    dataset_id = str(uuid.uuid4())
    content = json.dumps({
        'dc:title': 'The title of the dataset',
        'tables': [
            {
                'url': f'{table_or_report}s/the-first-table/data?format=csv&download',
                'dc:title': 'First table title',
                'tableSchema': {'columns': [
                    {
                        'name': 'id_field',
                        'dc:description': 'An ID field',
                        'dit:filterable': True
                    },
                    {
                        'name': 'name_field',
                        'dc:description': 'A name field',
                        'dit:filterable': False
                    },
                ]}
            },
        ]

    }).encode('utf-8')
    version = 'v0.0.1'
    contents = b'id_field,name_field\n' + b'1,foo\n' + b'2,bar\n'
    expected_filename = expected_filename_format.format(
        dataset_id=dataset_id, version=version, table='the-first-table')
    put_version(table_or_report, dataset_id, version, 'the-first-table', contents)
    put_version_metadata(dataset_id, version, content)

    with \
            requests.Session() as session, \
            session.get(version_filter_columns(table_or_report, dataset_id,
                                               version,
                                               'the-first-table')
                        ) as response:
        assert b'Table: First table title' in response.content
        # all metadata fields should be available when selecting the required columns
        assert b'id_field' in response.content
        assert b'name_field' in response.content

    # should return all rows and all columns
    base_query_args = '&query-simple'
    with \
            requests.Session() as session, \
            session.get(version_public_url_download(table_or_report, dataset_id,
                                                    version,
                                                    'the-first-table', 'csv')
                        + base_query_args) as response:
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{expected_filename}"'

        assert b'1,foo' in response.content
        assert b'2,bar' in response.content

    # should return all rows but only the name_field column
    query_args = base_query_args + '&_columns=name_field'
    with \
            requests.Session() as session, \
            session.get(version_public_url_download(table_or_report, dataset_id,
                                                    version,
                                                    'the-first-table', 'csv')
                        + query_args) as response:
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{expected_filename}"'

        assert b'1' not in response.content
        assert b'foo' in response.content
        assert b'2' not in response.content
        assert b'bar' in response.content

    # should return only rows with id_field=1 and only the name_field column
    query_args = base_query_args + '&id_field=1&_columns=name_field'
    with \
            requests.Session() as session, \
            session.get(version_public_url_download(table_or_report, dataset_id,
                                                    version,
                                                    'the-first-table', 'csv')
                        + query_args) as response:
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{expected_filename}"'

        assert b'1' not in response.content
        assert b'foo' in response.content
        assert b'2' not in response.content
        assert b'bar' not in response.content

    # should return rows with both id_field=1 and id_field=2 and only the name_field column
    query_args = base_query_args + '&id_field=1,2&_columns=name_field'
    with \
            requests.Session() as session, \
            session.get(version_public_url_download(table_or_report, dataset_id,
                                                    version,
                                                    'the-first-table', 'csv')
                        + query_args) as response:
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{expected_filename}"'

        assert b'1' not in response.content
        assert b'foo' in response.content
        assert b'2' not in response.content
        assert b'bar' in response.content


def test_multiple_concurrent_requests(processes):
    dataset_id_1 = str(uuid.uuid4())
    dataset_id_2 = str(uuid.uuid4())
    version_1 = 'v0.0.1'
    version_2 = 'v0.0.2'
    content_1 = str(uuid.uuid4()).encode() * 1000000
    content_2 = str(uuid.uuid4()).encode() * 1000000

    put_version_data(dataset_id_1, version_1, content_1, 'json')
    put_version_data(dataset_id_2, version_2, content_2, 'json')

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id_1,
                                                version_1, 'json'), stream=True) as response_1, \
            session.get(version_data_public_url(dataset_id_2,
                                                version_2, 'json'), stream=True) as response_2:

        iter_1 = response_1.iter_content(chunk_size=16384)
        iter_2 = response_2.iter_content(chunk_size=16384)

        response_content_1 = []
        response_content_2 = []

        num_single = 0
        num_both = 0

        # We This gives a reasonable guarantee that the server can handle
        # multiple requests concurrently, and we haven't accidentally added
        # something blocking
        while True:
            try:
                chunk_1 = next(iter_1)
            except StopIteration:
                chunk_1 = b''
            else:
                response_content_1.append(chunk_1)

            try:
                chunk_2 = next(iter_2)
            except StopIteration:
                chunk_2 = b''
            else:
                response_content_2.append(chunk_2)

            if chunk_1 and chunk_2:
                num_both += 1
            else:
                num_single += 1

            if not chunk_1 and not chunk_2:
                break

    assert b''.join(response_content_1) == content_1
    assert b''.join(response_content_2) == content_2
    assert num_both > 1000
    assert num_single < 100


def test_key_that_exists_during_shutdown_completes(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    chunks = []

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, version, 'json'),
                        stream=True) as response:

        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'application/json'
        processes[0]['web'].terminate()

        for chunk in response.iter_content(chunk_size=16384):
            chunks.append(chunk)
            time.sleep(0.02)

    assert b''.join(chunks) == content


def test_list_datasets_no_datasets(processes):
    with \
            requests.Session() as session, \
            session.get(list_datasets_public_url()) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"datasets": []}'


def test_list_datasets(processes):
    dataset_id = 'my-dataset'
    content = str(uuid.uuid4()).encode() * 100
    put_version_data(dataset_id, 'v0.0.1', content, 'json')
    with \
            requests.Session() as session, \
            session.get(list_datasets_public_url()) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"datasets": [{"id": "my-dataset"}]}'

    # new version to the same dataset
    put_version_data(dataset_id, 'v0.0.2', content, 'json')
    with \
            requests.Session() as session, \
            session.get(list_datasets_public_url()) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"datasets": [{"id": "my-dataset"}]}'

    put_version_data('your-dataset', 'v0.0.1', content, 'json')
    with \
            requests.Session() as session, \
            session.get(list_datasets_public_url()) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"datasets": [{"id": "my-dataset"}, {"id": "your-dataset"}]}'


def test_list_datasets_no_healthcheck(processes):
    dataset_id = 'my-dataset'
    content = str(uuid.uuid4()).encode() * 100
    put_version_data(dataset_id, 'v0.0.1', content, 'json')
    put_version_data('healthcheck', 'v0.0.1', b'header\n' + b'value\n' * 10, 'json')
    with \
            requests.Session() as session, \
            session.get(list_datasets_public_url()) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"datasets": [{"id": "my-dataset"}]}'


def test_list_dataset_versions_no_datasets(processes):
    dataset_id = str(uuid.uuid4())

    with \
            requests.Session() as session, \
            session.get(list_dataset_versions_public_url(dataset_id)) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"versions": []}'


def test_list_dataset_versions(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100
    put_version_data(dataset_id, 'v0.0.1', content, 'json')

    with \
            requests.Session() as session, \
            session.get(list_dataset_versions_public_url(dataset_id)) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"versions": [{"id": "v0.0.1"}]}'

    put_version_data(dataset_id, 'v0.0.2', content, 'json')
    with \
            requests.Session() as session, \
            session.get(list_dataset_versions_public_url(dataset_id)) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"versions": [{"id": "v0.0.2"}, {"id": "v0.0.1"}]}'


def test_list_tables_for_dataset_version_no_tables(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    with \
            requests.Session() as session, \
            session.get(list_dataset_public_url('table', dataset_id, version)) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"tables": []}'


@pytest.mark.parametrize('table_or_report', (
    'table',
    'report',
))
def test_list_tables_for_dataset_version(processes, table_or_report):
    dataset_id = str(uuid.uuid4())
    put_version(table_or_report, dataset_id, 'v0.0.1', 'foo', b'header\n' + b'value\n' * 10000)
    url = list_dataset_public_url(table_or_report, dataset_id, 'v0.0.1')
    with \
            requests.Session() as session, \
            session.get(url) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"' + table_or_report.encode() + b's": [{"id": "foo"}]}'

    put_version(table_or_report, dataset_id, 'v0.0.1', 'bar', b'header\n' + b'value\n' * 1000000)
    url = list_dataset_public_url(table_or_report, dataset_id, 'v0.0.1')
    with \
            requests.Session() as session, \
            session.get(url) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"' + table_or_report.encode() + \
            b's": [{"id": "bar"}, {"id": "foo"}]}'

    put_version(table_or_report, dataset_id, 'v0.0.2', 'baz', b'header\n' + b'value\n' * 10000)
    url = list_dataset_public_url(table_or_report, dataset_id, 'v0.0.1')
    with \
            requests.Session() as session, \
            session.get(url) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"' + table_or_report.encode() + \
            b's": [{"id": "bar"}, {"id": "foo"}]}'

    url = list_dataset_public_url(table_or_report, dataset_id, 'v0.0.2')
    with \
            requests.Session() as session, \
            session.get(url) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"' + table_or_report.encode() + b's": [{"id": "baz"}]}'


def test_list_tables_for_dataset__latest_version(processes):
    dataset_id = str(uuid.uuid4())
    put_version('table', dataset_id, 'v0.0.1', 'foo', b'header\n' + b'value\n' * 10000)
    put_version('table', dataset_id, 'v0.0.2', 'bar', b'header\n' + b'value\n' * 10000)
    put_version('table', dataset_id, 'v0.0.2', 'baz', b'header\n' + b'value\n' * 10000)
    with \
            requests.Session() as session, \
            session.get(list_dataset_public_url('table', dataset_id, 'latest')) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"tables": [{"id": "bar"}, {"id": "baz"}]}'


def test_key_that_exists_after_multiple_sigterm_completes(processes):
    # PaaS can apparently send multiple sigterms

    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    chunks = []

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, version, 'json'),
                        stream=True) as response:

        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'application/json'
        processes[0]['web'].terminate()
        time.sleep(0.1)
        processes[0]['web'].terminate()
        time.sleep(1.0)

        for chunk in response.iter_content(chunk_size=16384):
            chunks.append(chunk)
            time.sleep(0.02)

    assert b''.join(chunks) == content


def test_key_that_exists_during_shutdown_completes_but_new_connection_rejected(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    chunks = []

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, version, 'json'),
                        stream=True, headers={'Connection': 'close'}) as response:
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'application/json'

        processes[0]['web'].terminate()
        time.sleep(1.0)

        with pytest.raises(requests.exceptions.ConnectionError):
            session.get(version_data_public_url(dataset_id, version, 'json'), stream=True)

        for chunk in response.iter_content(chunk_size=16384):
            chunks.append(chunk)
            time.sleep(0.02)

    assert b''.join(chunks) == content


def test_key_that_exists_during_shutdown_completes_but_request_on_old_conn(processes):
    # Check that connections that were open before the SIGTERM still work
    # after. Unsure if this is desired on PaaS, so this is more of
    # documenting current behaviour

    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    chunks = []

    with requests.Session() as session:
        # Ensure we have two connections
        data_url = version_data_public_url(dataset_id, version, 'json')
        with session.get(data_url, stream=True) as resp_2, \
                session.get(data_url, stream=True) as resp_3:

            for chunk in resp_2.iter_content(chunk_size=16384):
                pass

            for chunk in resp_3.iter_content(chunk_size=16384):
                pass

        with session.get(data_url, stream=True) as resp_4:
            processes[0]['web'].terminate()
            time.sleep(1.0)

            # No exception raised since the connection is already open
            with session.get(data_url):
                pass

            for chunk in resp_4.iter_content(chunk_size=16384):
                time.sleep(0.02)
                chunks.append(chunk)

    assert b''.join(chunks) == content


def test_range_request_from_start(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    headers = {'range': 'bytes=0-'}
    data_url = version_data_public_url(dataset_id, version, 'json')
    with \
            requests.Session() as session, \
            session.get(data_url, headers=headers) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'application/json'


def test_range_request_after_start(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    data_url = version_data_public_url(dataset_id, version, 'json')
    headers = {'range': 'bytes=1-'}
    with \
            requests.Session() as session, \
            session.get(data_url, headers=headers) as response:
        assert response.content == content[1:]
        assert response.headers['content-length'] == str(len(content) - 1)
        assert response.headers['content-type'] == 'application/json'


def test_bad_aws_credentials(processes_bad_key):
    dataset_id = str(uuid.uuid4())
    version = 'v0.0.1'

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, version, 'json')) as response:
        assert response.status_code == 500


def test_key_that_does_not_exist(processes):
    dataset_id = str(uuid.uuid4())
    version = 'v0.0.1'

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, version, 'json')) as response:
        assert response.status_code == 404


def test_table_key_that_does_not_exist(processes):
    dataset_id = str(uuid.uuid4())
    version = 'v0.0.1'
    table = 'table'

    with \
            requests.Session() as session, \
            session.get(version_public_url('table', dataset_id, version,
                                           table, 'csv')) as response:
        assert response.status_code == 404


def test_key_that_exists_without_format(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    with \
            requests.Session() as session, \
            session.get(version_data_public_url_no_format(dataset_id, version)) as response:
        assert response.status_code == 400
        assert response.content == b'The query string must have a "format" term'
        assert not response.history

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, version, 'json')) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'application/json'
        assert not response.history


def test_table_key_that_exists_without_format(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    table = 'table'
    put_version('table', dataset_id, version, table, content)

    table_url = version_public_url_no_format('table', dataset_id, version, table)
    with requests.Session() as session, session.get(table_url) as response:
        assert response.status_code == 400
        assert response.content == b'The query string must have a "format" term'
        assert not response.history

    table_url = version_public_url('table', dataset_id, version, table, 'csv')
    with requests.Session() as session, session.get(table_url) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'text/csv'
        assert not response.history


def test_key_that_exists_with_bad_format(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    with \
            requests.Session() as session, \
            session.get(version_data_public_url_bad_format(dataset_id, version)) as response:
        assert response.status_code == 400
        assert response.content == \
            b'The query string "format" term must be one of ' + \
            b'"(\'json\', \'sqlite\', \'ods\')"'
        assert not response.history

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, version, 'json')) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'application/json'
        assert not response.history


def test_table_key_that_exists_with_bad_format(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    table = 'table'
    put_version('table', dataset_id, version, table, content)

    table_url = version_public_url_bad_format('table', dataset_id, version, table)
    with requests.Session() as session, session.get(table_url) as response:
        assert response.status_code == 400
        assert response.content == \
            b'The query string "format" term must be one of "(\'csv\', \'ods\', \'parquet\')"'
        assert not response.history

    table_url = version_public_url('table', dataset_id, version, table, 'csv')
    with requests.Session() as session, session.get(table_url) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'text/csv'
        assert not response.history


def test_select_all(processes):
    dataset_id = str(uuid.uuid4())
    content = json.dumps({
        'topLevel': (
            [{'a': '>&', 'd': 'e'}] * 100000
            + [{'a': 'c'}] * 1
            + [{'a': '🍰', 'd': 'f'}] * 100000
        )
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    params = {
        'query-s3-select': 'SELECT * FROM S3Object[*].topLevel[*]'
    }
    expected_content = json.dumps({
        'rows': (
            [{'a': '>&', 'd': 'e'}] * 100000
            + [{'a': 'c'}] * 1
            + [{'a': '🍰', 'd': 'f'}] * 100000
        ),
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

    data_url = version_data_public_url(dataset_id, version, 'json')
    with requests.Session() as session, session.get(data_url, params=params) as response:
        assert response.status_code == 200
        assert response.content == expected_content
        assert response.headers['content-type'] == 'application/json'
        assert not response.history

    # By this time a gzipped version would have been created, so we make sure
    # that requests still work if this has happened
    time.sleep(12)
    headers = {'accept-encoding': 'gzip'}
    with \
            requests.Session() as session, \
            session.get(data_url, params=params, headers=headers) as response:
        assert response.status_code == 200
        assert response.content == expected_content
        assert response.headers['content-type'] == 'application/json'
        assert not response.history


def test_select_newlines(processes):
    dataset_id = str(uuid.uuid4())
    content = json.dumps({
        'topLevel': (
            [{'a': '\n' * 10000}] * 100
        )
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    params = {
        'query-s3-select': 'SELECT * FROM S3Object[*].topLevel[*]'
    }
    expected_content = json.dumps({
        'rows': (
            [{'a': '\n' * 10000}] * 100
        ),
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

    data_url = version_data_public_url(dataset_id, version, 'json')
    with requests.Session() as session, session.get(data_url, params=params) as response:
        assert response.status_code == 200
        assert response.content == expected_content
        assert not response.history


def test_select_strings_that_are_almost_unicode_escapes(processes):
    dataset_id = str(uuid.uuid4())
    content = json.dumps({
        'topLevel': (
            [{'a': '\\u003e🍰\\u0026>&\\u003e\\u0026>\\u0026\\u002\\\\u0026\\n' * 10000}] * 10
        )
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    params = {
        'query-s3-select': 'SELECT * FROM S3Object[*].topLevel[*]'
    }
    expected_content = json.dumps({
        'rows': (
            [{'a': '\\u003e🍰\\u0026>&\\u003e\\u0026>\\u0026\\u002\\\\u0026\\n' * 10000}] * 10
        ),
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

    data_url = version_data_public_url(dataset_id, version, 'json')
    with requests.Session() as session, session.get(data_url, params=params) as response:
        assert response.status_code == 200
        assert response.content == expected_content
        assert response.headers['content-type'] == 'application/json'
        assert not response.history


def test_select_subset(processes):
    dataset_id = str(uuid.uuid4())
    content = json.dumps({
        'topLevel': (
            [{'a': '>&', 'd': 'e'}] * 100000
            + [{'a': 'c'}] * 1
            + [{'a': '🍰', 'd': 'f'}] * 100000
        )
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    params = {
        'query-s3-select':
            'SELECT * FROM S3Object[*].topLevel[*] AS t '
            + "WHERE t.a = '>&' OR t.a='🍰'"
    }
    expected_content = json.dumps({
        'rows': [{'a': '>&', 'd': 'e'}] * 100000 + [{'a': '🍰', 'd': 'f'}] * 100000,
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

    data_url = version_data_public_url(dataset_id, version, 'json')
    with requests.Session() as session, session.get(data_url, params=params) as response:
        assert response.status_code == 200
        assert response.content == expected_content
        assert response.headers['content-type'] == 'application/json'
        assert not response.history


def test_select_no_results(processes):
    dataset_id = str(uuid.uuid4())
    content = json.dumps({
        'topLevel': (
            [{'a': '>&', 'd': 'e'}] * 100000
            + [{'a': 'c'}] * 1
            + [{'a': '🍰', 'd': 'f'}] * 100000
        )
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    params = {
        'query-s3-select': "SELECT * FROM S3Object[*].topLevel[*] AS t WHERE t.a = 'notexists'"
    }
    expected_content = json.dumps({
        'rows': []
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

    data_url = version_data_public_url(dataset_id, version, 'json')
    with requests.Session() as session, session.get(data_url, params=params) as response:
        assert response.status_code == 200
        assert response.content == expected_content
        assert response.headers['content-type'] == 'application/json'
        assert not response.history


def test_no_latest_version(processes):
    dataset_id = 'does-not-exist'

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, 'latest', 'json')) as response:
        assert response.status_code == 404
        assert response.content == b'Dataset not found'
        assert not response.history

    table_url = version_public_url('table', dataset_id, 'latest', 'does-not-exist', 'csv')
    with requests.Session() as session, session.get(table_url) as response:
        assert response.status_code == 404
        assert response.content == b'Dataset not found'
        assert not response.history


def test_redirect_to_latest_version(processes):
    dataset_id = str(uuid.uuid4())
    table = 'table'

    # Ranges chosen to make sure we have at least 3 pages from S3 list objects, and to make
    # sure we hit as many cases as possible where if we were taking the latest version
    # alphabetically, we would choose the wrong version
    for major, minor, patch in itertools.product(range(0, 11), range(0, 11), range(0, 33)):
        content = str(uuid.uuid4()).encode() * 10
        version = f'v{major}.{minor}.{patch}'
        put_version_data(dataset_id, version, content, 'json')
        put_version('table', dataset_id, version, table, content)

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, 'latest', 'json'),
                        headers={'x-forwarded-proto': 'https'},
                        allow_redirects=False
                        ) as response:
        assert response.headers['location'].startswith('https://')

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, 'latest', 'json')) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'application/json'
        assert len(response.history) == 1
        assert response.history[0].status_code == 302
        assert 'v10.10.32' in response.request.url

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, 'v2', 'json')) as response:
        assert response.headers['content-type'] == 'application/json'
        assert len(response.history) == 1
        assert response.history[0].status_code == 302
        assert 'v2.10.32' in response.request.url

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, 'v3.4', 'json')) as response:
        assert response.headers['content-type'] == 'application/json'
        assert len(response.history) == 1
        assert response.history[0].status_code == 302
        assert 'v3.4.32' in response.request.url


def test_table_redirect_to_latest_version(processes):
    dataset_id = str(uuid.uuid4())
    table = 'table'
    # Ranges chosen to make sure we have at least 3 pages from S3 list objects, and to make
    # sure we hit as many cases as possible where if we were taking the latest version
    # alphabetically, we would choose the wrong version
    for major, minor, patch in itertools.product(range(0, 11), range(0, 11), range(0, 33)):
        content = str(uuid.uuid4()).encode() * 10
        version = f'v{major}.{minor}.{patch}'
        put_version('table', dataset_id, version, table, content)

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, 'latest', 'json'),
                        headers={'x-forwarded-proto': 'https'},
                        allow_redirects=False
                        ) as response:
        assert response.headers['location'].startswith('https://')

    with \
            requests.Session() as session, \
            session.get(version_public_url('table', dataset_id,
                                           'latest', table, 'csv')) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'text/csv'
        assert len(response.history) == 1
        assert response.history[0].status_code == 302
        assert 'v10.10.32' in response.request.url

    with \
            requests.Session() as session, \
            session.get(version_public_url('table', dataset_id, 'v2', table, 'csv')) as response:
        assert response.headers['content-type'] == 'text/csv'
        assert len(response.history) == 1
        assert response.history[0].status_code == 302
        assert 'v2.10.32' in response.request.url

    with \
            requests.Session() as session, \
            session.get(version_public_url('table', dataset_id, 'v3.4', table, 'csv')) as response:
        assert response.headers['content-type'] == 'text/csv'
        assert len(response.history) == 1
        assert response.history[0].status_code == 302
        assert 'v3.4.32' in response.request.url


def test_redirect_to_latest_version_query(processes):
    dataset_id = str(uuid.uuid4())

    content_1 = json.dumps({
        'top_level': [{'a': 'y'}, {'a': 'y'}, {'common': 'b'}]
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    version_1 = 'v9.9.9'
    put_version_data(dataset_id, version_1, content_1, 'json')

    content_2 = json.dumps({
        'top_level': [{'a': 'y'}, {'common': 'b'}]
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    version_2 = 'v10.0.0'
    put_version_data(dataset_id, version_2, content_2, 'json')

    params = {
        'query-s3-select': "SELECT * FROM S3Object[*].top_level[*] row WHERE row.a = 'y'"
    }
    expected_content = json.dumps({
        'rows': [{'a': 'y'}],
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

    data_url = version_data_public_url(dataset_id, 'latest', 'json')
    with requests.Session() as session, session.get(data_url, params=params) as response:
        assert response.content in expected_content
        assert response.headers['content-type'] in 'application/json'
        assert len(response.history) == 1
        assert response.history[0].status_code == 302
        assert 'v10.0.0' in response.request.url


def test_redirect_with_utf_8_in_query_string(processes):
    # Test that documents that non-URL encoded values in query strings are redirected to their
    # URL-encoded equivalent. Not sure if this behaviour is desirable or not.
    dataset_id = str(uuid.uuid4())
    content = b'{"some":"content"}'
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')
    url = version_data_public_url(dataset_id, 'latest', 'json')
    url_parsed = urllib.parse.urlsplit(url)

    url_full_path = url_parsed.path.encode(
        'ascii') + b'?format=json&something=' + '🍰'.encode('utf-8')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((url_parsed.hostname, url_parsed.port))
    sock.send(
        b'GET ' + url_full_path + b' HTTP/1.1\r\n'
        b'host:127.0.0.1\r\n'
        b'connection:close\r\n'
        b'\r\n')

    full_response = b''
    while True:
        response = sock.recv(4096)
        if not response:
            break
        full_response += response
    sock.close()

    cake_url_encoded = urllib.parse.quote_from_bytes('🍰'.encode('utf-8')).encode('ascii')
    assert b'&something=' + cake_url_encoded in full_response


def test_csv_created(processes):
    dataset_id = str(uuid.uuid4())
    version = 'v0.0.1'
    content = b'{"top":[{"id":1,"key":"value","nested":[{"key_2":"value_2"}]}]}'
    put_version_data(dataset_id, version, content, 'json')

    time.sleep(12)

    top_bytes, top_headers = get_csv_data(dataset_id, version, 'top')
    assert top_bytes == b'"id","key"\r\n1,"value"\r\n'

    nested_bytes, _ = get_csv_data(dataset_id, version, 'top--nested')
    assert nested_bytes == b'"top__id","key_2"\r\n1,"value_2"\r\n'

    top_bytes, top_headers = get_csv_data_gzipped(dataset_id, version, 'top')
    assert gzip.decompress(top_bytes) == b'"id","key"\r\n1,"value"\r\n'

    time.sleep(12)

    # Ensure that we haven't unnecessarily recreated the CSVs
    _, top_headers_2 = get_csv_data(dataset_id, version, 'top')
    assert top_headers['last-modified'] == top_headers_2['last-modified']


def test_csvs_created_from_sqlite_without_reports(processes):
    dataset_id = str(uuid.uuid4())
    version = 'v0.0.1'

    with tempfile.NamedTemporaryFile() as f:
        with sqlite3.connect(f.name) as con:
            cur = con.cursor()

            # There are only 5 datatypes in SQLite: INTEGER, REAL, TEXT, BLOB, and NULL
            cur.execute('''
                CREATE TABLE my_table_no_primary_key (
                    col_int int,
                    col_real real,
                    col_text text,
                    col_blob blob
                )
            ''')
            cur.execute('INSERT INTO my_table_no_primary_key VALUES (?,?,?,?)',
                        (1, 1.5, 'Some text 🍰', b'\0\1\2'))
            cur.execute('INSERT INTO my_table_no_primary_key VALUES (?,?,?,?)',
                        (1, None, 'Some text 🍰', None))

            # Ensure we order by primary key when there is one, including when it's multi-column,
            # and when the columns are not ordered in the same order as they are in the table
            cur.execute('''
                CREATE TABLE my_table_with_primary_key (
                    col_int_a int,
                    col_int_b int,
                    PRIMARY KEY (col_int_b, col_int_a)
                )
            ''')
            cur.execute('INSERT INTO my_table_with_primary_key VALUES (?,?)', (2, 2))
            cur.execute('INSERT INTO my_table_with_primary_key VALUES (?,?)', (1, 3))
            cur.execute('INSERT INTO my_table_with_primary_key VALUES (?,?)', (3, 2))
            cur.execute('INSERT INTO my_table_with_primary_key VALUES (?,?)', (3, 1))

        put_version_data(dataset_id, version, f.read(), 'sqlite')

    time.sleep(12)

    table_bytes, _ = get_csv_data(dataset_id, version, 'my-table-no-primary-key')
    assert table_bytes == \
        b'"col_int","col_real","col_text","col_blob"\r\n' + \
        b'1,1.5,"Some text ' + '🍰'.encode('utf-8') + b'","' + b64encode(b'\0\1\2') + b'"\r\n' + \
        b'1,"#NA","Some text ' + '🍰'.encode('utf-8') + b'","#NA"\r\n'

    table_bytes, _ = get_csv_data(dataset_id, version, 'my-table-with-primary-key')
    assert table_bytes == \
        b'"col_int_a","col_int_b"\r\n' + \
        b'3,1\r\n' + \
        b'2,2\r\n' + \
        b'3,2\r\n' + \
        b'1,3\r\n'

    params = {
        'query-s3-select': 'SELECT col_text FROM S3Object[*].my_table_no_primary_key[*]'
    }
    expected_content = json.dumps({
        'rows': [
            {'col_text': 'Some text 🍰'},
            {'col_text': 'Some text 🍰'},
        ],
    }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

    data_url = version_data_public_url(dataset_id, version, 'json')
    with requests.Session() as session, session.get(data_url, params=params) as response:
        assert response.status_code == 200
        assert response.content == expected_content
        assert not response.history


def test_parquets_created_from_sqlite_without_reports(processes):
    dataset_id = str(uuid.uuid4())
    version = 'v0.0.1'

    with tempfile.NamedTemporaryFile() as f:
        with sqlite3.connect(f.name) as con:
            cur = con.cursor()

            # There are only 5 datatypes in SQLite: INTEGER, REAL, TEXT, BLOB, and NULL
            cur.execute('''
                CREATE TABLE my_table_no_primary_key (
                    col_int int,
                    col_real real,
                    col_text text,
                    col_blob blob
                )
            ''')
            for _ in range(0, 3000):
                cur.execute('INSERT INTO my_table_no_primary_key VALUES (?,?,?,?)',
                            (1, 1.5, 'Some text 🍰', b'\0\1\2'))
                cur.execute('INSERT INTO my_table_no_primary_key VALUES (?,?,?,?)',
                            (1, None, 'Some text 🍰', None))

            # Ensure we order by primary key when there is one, including when it's multi-column,
            # and when the columns are not ordered in the same order as they are in the table
            cur.execute('''
                CREATE TABLE my_table_with_primary_key (
                    col_int_a int,
                    col_int_b int,
                    PRIMARY KEY (col_int_b, col_int_a)
                )
            ''')
            cur.execute('INSERT INTO my_table_with_primary_key VALUES (?,?)', (2, 2))
            cur.execute('INSERT INTO my_table_with_primary_key VALUES (?,?)', (1, 3))
            cur.execute('INSERT INTO my_table_with_primary_key VALUES (?,?)', (3, 2))
            cur.execute('INSERT INTO my_table_with_primary_key VALUES (?,?)', (3, 1))

        put_version_data(dataset_id, version, f.read(), 'sqlite')

    time.sleep(30)

    with requests.Session() as session:
        table_url = version_public_url('table', dataset_id, version,
                                       'my-table-no-primary-key', 'parquet')
        with session.get(table_url) as response:
            table = pq.read_table(pa.BufferReader(response.content))
            assert table.column_names == ['col_int', 'col_real', 'col_text', 'col_blob']
            assert table.num_rows == 6000
            assert table.to_pylist() == [
                {
                    'col_blob': b'\x00\x01\x02',
                    'col_int': 1,
                    'col_real': 1.5,
                    'col_text': 'Some text 🍰',
                }, {
                    'col_blob': None,
                    'col_int': 1,
                    'col_real': None,
                    'col_text': 'Some text 🍰',
                },
            ] * 3000

        table_url = version_public_url('table', dataset_id, version,
                                       'my-table-with-primary-key', 'parquet')
        with session.get(table_url) as response:
            table = pq.read_table(pa.BufferReader(response.content))
            assert table.column_names == ['col_int_a', 'col_int_b']
            assert table.num_rows == 4
            assert table.to_pylist() == [
                {
                    'col_int_a': 3,
                    'col_int_b': 1,
                }, {
                    'col_int_a': 2,
                    'col_int_b': 2,
                }, {
                    'col_int_a': 3,
                    'col_int_b': 2,
                }, {
                    'col_int_a': 1,
                    'col_int_b': 3,
                },
            ]


def test_csvs_and_parquets_and_ods_created_from_sqlite_with_reports(processes):
    dataset_id = str(uuid.uuid4())
    version = 'v0.0.1'

    with tempfile.NamedTemporaryFile() as f:
        with sqlite3.connect(f.name) as con:
            cur = con.cursor()

            cur.execute('''
                CREATE TABLE my_table_with_primary_key (
                    col_int_a int,
                    col_int_b int,
                    PRIMARY KEY (col_int_b, col_int_a)
                )
            ''')
            cur.execute('INSERT INTO my_table_with_primary_key VALUES (?,?)', (2, 2))
            cur.execute('INSERT INTO my_table_with_primary_key VALUES (?,?)', (1, 3))
            cur.execute('INSERT INTO my_table_with_primary_key VALUES (?,?)', (3, 2))
            cur.execute('INSERT INTO my_table_with_primary_key VALUES (?,?)', (3, 1))

            cur.execute('''
                CREATE TABLE _reports (
                    name TEXT,
                    script TEXT
                )
            ''')
            cur.execute('INSERT INTO _reports(name, script) VALUES (?,?)', ('my_report', '''
                CREATE TEMPORARY TABLE my_temp AS SELECT * FROM my_table_with_primary_key;
                SELECT * FROM my_temp;
                SELECT * FROM my_table_with_primary_key
                WHERE col_int_a = 3
                ORDER BY col_int_b
            '''))

        put_version_data(dataset_id, version, f.read(), 'sqlite')

    time.sleep(12)

    report_url = version_public_url_download('report', dataset_id, version, 'my-report', 'csv')
    with \
            requests.Session() as session, \
            session.get(report_url) as response:
        assert response.content == \
            b'"col_int_a","col_int_b"' + \
            b'\r\n2,2\r\n1,3\r\n3,2\r\n3,1\r\n3,1\r\n3,2\r\n'

    report_url = version_public_url_download('report', dataset_id, version, 'my-report', 'parquet')
    with \
            requests.Session() as session, \
            session.get(report_url) as response:

        table = pq.read_table(pa.BufferReader(response.content))
        assert table.column_names == ['col_int_a', 'col_int_b']
        assert table.num_rows == 6
        assert table.to_pylist() == [
            {
                'col_int_a': 2,
                'col_int_b': 2,
            }, {
                'col_int_a': 1,
                'col_int_b': 3,
            }, {
                'col_int_a': 3,
                'col_int_b': 2,
            }, {
                'col_int_a': 3,
                'col_int_b': 1,
            }, {
                'col_int_a': 3,
                'col_int_b': 1,
            }, {
                'col_int_a': 3,
                'col_int_b': 2,
            },
        ]

    report_url = version_public_url_download('report', dataset_id, version, 'my-report', 'ods')
    with \
            requests.Session() as session, \
            session.get(report_url) as response:

        with tempfile.NamedTemporaryFile() as f:
            f.write(response.content)
            f.flush()

            report_1 = pd.read_excel(f.name, 'Section 1')
            report_1_rows = report_1.values.tolist()
            report_1_cols = report_1.columns.tolist()
            report_2 = pd.read_excel(f.name, 'Section 2')
            report_2_rows = report_2.values.tolist()
            report_2_cols = report_2.columns.tolist()

    assert report_1_cols == ['col_int_a', 'col_int_b', ]
    assert report_1_rows == [
        [2.0, 2.0],
        [1.0, 3.0],
        [3.0, 2.0],
        [3.0, 1.0],
    ]

    assert report_2_cols == ['col_int_a', 'col_int_b', ]
    assert report_2_rows == [
        [3.0, 1.0],
        [3.0, 2.0],
    ]


def test_logs_asim_format():
    with application(sleep=120) as (_, outputs):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content, 'json')
        url = f'/v1/datasets/{dataset_id}/versions/{version}/data'
        with requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, version, 'json'),
                            headers={'Connection': 'close'}
                            ) as response:
            assert response.status_code == 200

    web_output, web_error = outputs['web']
    assert web_error == b''
    web_output_logs = web_output.decode().split('\n')
    assert len(web_output_logs) >= 1
    web_api_call_log = [json.loads(log) for log in web_output_logs if url in log]
    assert len(web_api_call_log) == 2
    assert 'EventMessage' in web_api_call_log[0]
    assert b'Shut down gracefully' in web_output

    worker_output, worker_error = outputs['worker']
    assert worker_error == b''
    assert b'Shut down gracefully' in worker_output


def test_heartbeat():
    hearbeat_file = Path(f'{tempfile.gettempdir()}/public_data_api_worker_heartbeat')

    with application(sleep=120) as (_, outputs):
        time.sleep(2)
        assert hearbeat_file.exists()
        heartbeat_timestamp = float(hearbeat_file.read_text(encoding='utf-8'))
        current_timestamp = datetime.now().timestamp()
        assert current_timestamp - heartbeat_timestamp < 10

    worker_output, worker_error = outputs['worker']
    assert worker_error == b''
    assert b'Shut down heartbeat' in worker_output
    assert not hearbeat_file.exists()


def test_check_heartbeat():
    result = subprocess.run(['python', '-m', 'app_heartbeat'], check=False)
    assert result.returncode == 1

    with application():
        time.sleep(2)

        result = subprocess.run(['python', '-m', 'app_heartbeat'], check=False)
        assert result.returncode == 0

    result = subprocess.run(['python', '-m', 'app_heartbeat'], check=False)
    assert result.returncode == 1


def test_healthcheck_ok(processes):
    dataset_id = 'healthcheck'
    content_str = {'status': 'OK'}
    content = json.dumps(content_str).encode()
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    with \
            requests.Session() as session, \
            session.get('http://127.0.0.1:8080/pingdom/ping.xml') as response:
        assert response.status_code == 200
        assert '<status>OK</status>' in str(response.content)
        assert response.headers['content-type'] == 'text/xml'
        assert response.headers['Cache-Control'] == 'no-cache, no-store, must-revalidate'


def test_healthcheck_fail(processes):
    dataset_id = 'healthcheck'
    content_str = {'foo': 'bar'}
    content = json.dumps(content_str).encode()
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    with \
            requests.Session() as session, \
            session.get('http://127.0.0.1:8080/pingdom/ping.xml') as response:
        assert response.status_code == 503


def test_headers(processes):
    dataset_id = str(uuid.uuid4())
    content_str = {'foo': 'bar'}
    content = json.dumps(content_str).encode()
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    data_url = version_data_public_url(dataset_id, version, 'json')
    with requests.Session() as session, session.get(data_url) as response:
        assert response.status_code == 200
        assert response.headers['access-control-allow-origin'] == '*'
        assert response.headers['x-robots-tag'] == 'no-index, no-follow'

    root = 'http://127.0.0.1:8080/'
    with requests.Session() as session, session.get(root) as response:
        assert response.status_code == 200
        assert response.headers['access-control-allow-origin'] == '*'
        assert 'x-robots-tag' not in response.headers


def test_sentry_integration(processes_bad_key):
    # Passing a bad AWS access key will result in a 403 when calling S3
    # and this will raise an Exception that should be reported to sentry.
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    for _ in range(10):
        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, version, 'json')) as response:
            assert response.status_code == 500

    time.sleep(1)

    with \
            requests.Session() as session, \
            session.get('http://127.0.0.1:9003/api/1/errors') as response:
        assert int(response.content) >= 10


def test_google_analytics_integration_on_api(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')
    with requests.Session() as session:
        session.get(version_data_public_url(dataset_id, version, 'json'))
        session.get(version_data_public_url_download(dataset_id, version, 'json'))
        session.get(version_public_url('table', dataset_id, version, 'table', 'csv'))
        session.get(version_public_url_download('table', dataset_id, version, 'table', 'csv'))

        time.sleep(1)
        response = session.post('http://127.0.0.1:9002/calls')
        calls = json.loads(response.content)
        assert len(calls) == 4
        assert calls[0]['dl'] == \
            f'http://127.0.0.1:8080/v1/datasets/{dataset_id}/versions/v0.0.1/data?format=json'


def test_google_analytics_integration_on_docs(processes):
    with requests.Session() as session:
        session.get('http://127.0.0.1:8080')
        session.get('http://127.0.0.1:8080')
        session.get('http://127.0.0.1:8080')

        time.sleep(1)
        response = session.post('http://127.0.0.1:9002/calls')
        assert len(json.loads(response.content)) == 3


def test_docs(processes):
    with requests.Session() as session, session.get('http://127.0.0.1:8080') as response:
        assert response.status_code == 200


def put_version_metadata(dataset_id, version, contents):
    return put_object(f'{dataset_id}/{version}/metadata--csvw.json', contents)


def put_version_data(dataset_id, version, contents, extension):
    return put_object(f'{dataset_id}/{version}/data.{extension}', contents)


def put_version(table_or_report, dataset_id, version, table, contents):
    return put_object(f'{dataset_id}/{version}/{table_or_report}s/{table}/data.csv', contents)


def put_version_gzipped(table_or_report, dataset_id, version, table, contents):
    return put_object(
        f'{dataset_id}/{version}/{table_or_report}s/{table}/data.csv.gz', gzip.compress(contents)
    )


def get_csv_data(dataset_id, version, table):
    return get_object(f'{dataset_id}/{version}/tables/{table}/data.csv')


def get_csv_data_gzipped(dataset_id, version, table):
    return get_object(f'{dataset_id}/{version}/tables/{table}/data.csv.gz')


def put_object(key, contents, params=()):
    url = f'http://127.0.0.1:9000/my-bucket/{key}'
    body_hash = hashlib.sha256(contents).hexdigest()
    parsed_url = urllib.parse.urlsplit(url)

    headers = aws_sigv4_headers(
        'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        (), 's3', 'us-east-1', parsed_url.netloc, 'PUT', parsed_url.path, params, body_hash,
    )
    with requests.put(url, params=params, data=contents, headers=dict(headers)) as response:
        response.raise_for_status()


def put_object_no_raise(key, contents):
    url = f'http://127.0.0.1:9000/my-bucket/{key}'
    body_hash = hashlib.sha256(contents).hexdigest()
    parsed_url = urllib.parse.urlsplit(url)

    headers = aws_sigv4_headers(
        'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        (), 's3', 'us-east-1', parsed_url.netloc, 'PUT', parsed_url.path, (), body_hash,
    )
    requests.put(url, data=contents, headers=dict(headers))


def get_object(key):
    url = f'http://127.0.0.1:9000/my-bucket/{key}'
    body_hash = hashlib.sha256(b'').hexdigest()
    parsed_url = urllib.parse.urlsplit(url)

    headers = aws_sigv4_headers(
        'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        (), 's3', 'us-east-1', parsed_url.netloc, 'GET', parsed_url.path, (), body_hash,
    )
    with requests.get(url, headers=dict(headers)) as response:
        response.raise_for_status()
        return response.content, response.headers


def delete_all_objects():
    def list_keys():
        url = 'http://127.0.0.1:9000/my-bucket/'
        parsed_url = urllib.parse.urlsplit(url)
        namespace = '{http://s3.amazonaws.com/doc/2006-03-01/}'
        key_marker = ''
        version_marker = ''

        def _list(extra_query_items=()):
            nonlocal key_marker, version_marker

            key_marker = ''
            version_marker = ''
            query = (
                ('max-keys', '1000'),
                ('versions', ''),
            ) + extra_query_items

            body = b''
            body_hash = hashlib.sha256(body).hexdigest()
            headers = aws_sigv4_headers(
                'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                (), 's3', 'us-east-1', parsed_url.netloc, 'GET', parsed_url.path, query, body_hash,
            )
            with requests.get(url, data=body, params=query, headers=dict(headers)) as response:
                response.raise_for_status()
                body_bytes = response.content

            for element in ET.fromstring(body_bytes):
                if element.tag in (f'{namespace}Version', f'{namespace}DeleteMarker'):
                    for child in element:
                        if child.tag == f'{namespace}Key':
                            key = child.text
                        if child.tag == f'{namespace}VersionId':
                            version_id = child.text
                    yield key, version_id
                if element.tag == f'{namespace}NextKeyMarker':
                    key_marker = element.text
                if element.tag == f'{namespace}NextVersionMarker':
                    version_marker = element.text

        yield from _list()

        while key_marker:
            yield from _list((('key-marker', key_marker), ('version-marker', version_marker)))

    for key, version_id in list_keys():
        url = f'http://127.0.0.1:9000/my-bucket/{key}'
        params = (('versionId', version_id),)
        parsed_url = urllib.parse.urlsplit(url)
        body = b''
        body_hash = hashlib.sha256(body).hexdigest()
        headers = aws_sigv4_headers(
            'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            (), 's3', 'us-east-1', parsed_url.netloc, 'DELETE', parsed_url.path, params, body_hash,
        )
        with requests.delete(url, params=params, data=body, headers=dict(headers)) as response:
            response.raise_for_status()


_url_prefix = 'http://127.0.0.1:8080/v1/datasets'


def list_datasets_public_url():
    return f'{_url_prefix}?format=json'


def list_dataset_versions_public_url(dataset_id):
    return f'{_url_prefix}/{dataset_id}/versions?format=json'


def list_dataset_public_url(table_or_report, dataset_id, version):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/{table_or_report}s?format=json'


def dataset_metadata_public_url(dataset_id):
    return f'{_url_prefix}/{dataset_id}/metadata?format=data.json'


def version_metadata_public_url(dataset_id, version):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/metadata?format=csvw'


def version_metadata_public_url_download(dataset_id, version):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/metadata?format=csvw&download'


def version_metadata_public_html_url(dataset_id, version):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/metadata?format=html'


def version_data_public_url(dataset_id, version, requested_format):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/data?format={requested_format}'


def version_data_public_url_download(dataset_id, version, requested_format):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/data?format={requested_format}&download'


def version_data_public_url_no_format(dataset_id, version):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/data'


def version_data_public_url_bad_format(dataset_id, version):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/data?format=txt'


def version_public_url(table_or_report, dataset_id, version, table, _format):
    return (f'{_url_prefix}/{dataset_id}/versions/{version}/{table_or_report}s/{table}/'
            + f'data?format={_format}')


def version_public_url_download(table_or_report, dataset_id, version, table, _format):
    return (f'{_url_prefix}/{dataset_id}/versions/{version}/{table_or_report}s/{table}/'
            + f'data?format={_format}&download')


def version_public_url_no_format(table_or_report, dataset_id, version, table):
    return (f'{_url_prefix}/{dataset_id}/versions/{version}/{table_or_report}s/{table}/'
            + 'data')


def version_public_url_bad_format(table_or_report, dataset_id, version, table):
    return (f'{_url_prefix}/{dataset_id}/versions/{version}/{table_or_report}s/{table}/'
            + 'data?format=txt')


def version_filter_rows(table_or_report, dataset_id, version, table):
    return (f'{_url_prefix}/{dataset_id}/versions/{version}/{table_or_report}s/{table}/'
            + 'filter/rows')


def version_filter_columns(table_or_report, dataset_id, version, table):
    return (f'{_url_prefix}/{dataset_id}/versions/{version}/{table_or_report}s/{table}/'
            + 'filter/columns')


def aws_sigv4_headers(access_key_id, secret_access_key, pre_auth_headers,
                      service, region, host, method, path, params, body_hash):
    algorithm = 'AWS4-HMAC-SHA256'

    now = datetime.utcnow()
    amzdate = now.strftime('%Y%m%dT%H%M%SZ')
    datestamp = now.strftime('%Y%m%d')
    credential_scope = f'{datestamp}/{region}/{service}/aws4_request'

    pre_auth_headers_lower = tuple((
        (header_key.lower(), ' '.join(header_value.split()))
        for header_key, header_value in pre_auth_headers
    ))
    required_headers = (
        ('host', host),
        ('x-amz-content-sha256', body_hash),
        ('x-amz-date', amzdate),
    )
    headers = sorted(pre_auth_headers_lower + required_headers)
    signed_headers = ';'.join(key for key, _ in headers)

    def signature():
        def canonical_request():
            canonical_uri = urllib.parse.quote(path, safe='/~')
            quoted_params = sorted(
                (urllib.parse.quote(key, safe='~'), urllib.parse.quote(value, safe='~'))
                for key, value in params
            )
            canonical_querystring = '&'.join(f'{key}={value}' for key, value in quoted_params)
            canonical_headers = ''.join(f'{key}:{value}\n' for key, value in headers)

            return f'{method}\n{canonical_uri}\n{canonical_querystring}\n' + \
                   f'{canonical_headers}\n{signed_headers}\n{body_hash}'

        def sign(key, msg):
            return hmac.new(key, msg.encode('ascii'), hashlib.sha256).digest()

        string_to_sign = f'{algorithm}\n{amzdate}\n{credential_scope}\n' + \
                         hashlib.sha256(canonical_request().encode('ascii')).hexdigest()

        date_key = sign(('AWS4' + secret_access_key).encode('ascii'), datestamp)
        region_key = sign(date_key, region)
        service_key = sign(region_key, service)
        request_key = sign(service_key, 'aws4_request')
        return sign(request_key, string_to_sign).hex()

    return (
        (b'authorization', (
            f'{algorithm} Credential={access_key_id}/{credential_scope}, '
            f'SignedHeaders={signed_headers}, Signature=' + signature()).encode('ascii')
         ),
        (b'x-amz-date', amzdate.encode('ascii')),
        (b'x-amz-content-sha256', body_hash.encode('ascii')),
    ) + pre_auth_headers
