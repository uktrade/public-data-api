# pylint: disable=unused-argument

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
import socket
import subprocess
import urllib.parse
import uuid
from xml.etree import (
    ElementTree as ET,
)

import pytest
import requests


@contextmanager
def application(port=8080, max_attempts=500, aws_access_key_id='AKIAIOSFODNN7EXAMPLE'):
    outputs = {}

    delete_all_objects()
    with open('Procfile', 'r') as file:
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
        name: (tempfile.NamedTemporaryFile(), tempfile.NamedTemporaryFile())
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
                'AWS_S3_REGION': 'us-east-1',
                'READONLY_AWS_ACCESS_KEY_ID': aws_access_key_id,
                'READONLY_AWS_SECRET_ACCESS_KEY': (
                    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
                ),
                'READ_AND_WRITE_AWS_ACCESS_KEY_ID': aws_access_key_id,
                'READ_AND_WRITE_AWS_SECRET_ACCESS_KEY': (
                    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
                ),
                'AWS_S3_ENDPOINT': 'http://127.0.0.1:9000/my-bucket/',
                'APM_SECRET_TOKEN': 'secret_token',
                'APM_SERVER_URL': 'http://localhost:8201',
                'ENVIRONMENT': 'test',
                'SENTRY_DSN': 'http://foo@localhost:9001/1',
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
        for _, process in processes.items():
            process.terminate()
        for _, process in processes.items():
            process.wait(timeout=10)
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


def test_key_that_exists(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, version, 'json')) as response:
        assert response.content == content
        assert response.headers['content-length'], str(len(content))
        assert response.headers['content-type'], 'application/json'
        assert'content-disposition' not in response.headers
        assert not response.history

    with \
            requests.Session() as session, \
            session.get(version_data_public_url_download(dataset_id, version, 'json')) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'application/json'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}.json"'
        assert not response.history


def test_metadata_key_that_exists(processes):
    dataset_id = str(uuid.uuid4())
    content = json.dumps({
        'dc:title': 'The title of the dataset',
        'tables': [
            {
                'id': 'the-first-table',
                'tableSchema': {'columns': []}
            },
            {
                'id': 'the-second-table',
                'tableSchema': {'columns': []}
            },
        ]

    }).encode('utf-8')
    version = 'v0.0.1'
    put_version_table(dataset_id, version, 'the-first-table', b'header\n' + b'value\n' * 10000)
    put_version_table(dataset_id, version, 'the-second-table',
                      b'header\n' + b'value\n' * 1000000)
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
        assert datetime.now().strftime('%d %B %Y').encode() in response.content
        assert b'?format=csvw&amp;download"' in response.content
        assert response.headers['content-type'] == 'text/html'
        assert 'content-disposition' not in response.headers
        assert not response.history


def test_table_key_that_exists(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    table = 'table'
    version = 'v0.0.1'
    put_version_table(dataset_id, version, table, content)

    with \
            requests.Session() as session, \
            session.get(version_table_public_url(dataset_id, version, table)) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'text/csv'
        assert 'content-disposition' not in response.headers
        assert not response.history

    with \
            requests.Session() as session, \
            session.get(version_table_public_url_download(dataset_id,
                                                          version, table)) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}--{table}.csv"'
        assert not response.history


def test_table_gzipped(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    table = 'table'
    version = 'v0.0.1'
    put_version_table(dataset_id, version, table, content)
    put_version_table_gzipped(dataset_id, version, table, content)

    with \
            requests.Session() as session, \
            session.get(version_table_public_url_download(dataset_id, version, table),
                        headers={'accept-encoding': None}
                        ) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers[
            'content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}--{table}.csv"'
        assert 'content-encoding' not in response.headers
        assert not response.history

    with \
            requests.Session() as session, \
            session.get(version_table_public_url_download(dataset_id, version, table),
                        headers={'accept-encoding': 'gzip'}
                        ) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(gzip.compress(content)))
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-encoding'] == 'gzip'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}--{table}.csv"'
        assert not response.history


def test_table_serves_uncompressed_if_gzip_file_does_not_exist(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    table = 'table'
    version = 'v0.0.1'
    put_version_table(dataset_id, version, table, content)

    with \
            requests.Session() as session, \
            session.get(version_table_public_url_download(dataset_id, version, table),
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
    put_version_table(dataset_id, version, table, content)
    put_version_table_gzipped(dataset_id, version, table, content)
    params = {
        'query-s3-select': 'SELECT col_a FROM S3Object[*] WHERE col_b = \'d\''
    }
    with \
            requests.Session() as session, \
            session.get(version_table_public_url_download(dataset_id, version, table),
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
    put_version_table(dataset_id, version, table, content)
    params = {
        'query-s3-select': 'SELECT col_a FROM S3Object[*] WHERE col_b = \'d\''
    }
    with \
            requests.Session() as session, \
            session.get(version_table_public_url_download(dataset_id, version, table),
                        params=params) as response:
        assert response.content == \
            'c🍰é\ne\n&>' '\n"Ah, a comma"\n"A quote "" "\n\\u00f8C\n'.encode('utf-8')
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}--{table}.csv"'
        assert not response.history


def test_filter_rows(processes):
    dataset_id = str(uuid.uuid4())
    content = json.dumps({
        'dc:title': 'The title of the dataset',
        'tables': [
            {
                'url': 'tables/the-first-table/data?format=csv&download',
                'dc:title': 'First table title',
                'id': 'the-first-table',
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
    put_version_table(dataset_id, version, 'the-first-table', contents)
    put_version_metadata(dataset_id, version, content)

    with \
            requests.Session() as session, \
            session.get(version_table_filter_rows(dataset_id,
                                                  version,
                                                  'the-first-table')
                        ) as response:
        assert b'Table: First table title' in response.content
        assert b'id_field' in response.content
        assert b'An ID field' in response.content
        # name_field has dit:filterable set to False so should not be available to filter on
        assert b'name_field' not in response.content
        assert b'A name field' not in response.content


def test_filter_columns(processes):
    dataset_id = str(uuid.uuid4())
    content = json.dumps({
        'dc:title': 'The title of the dataset',
        'tables': [
            {
                'url': 'tables/the-first-table/data?format=csv&download',
                'dc:title': 'First table title',
                'id': 'the-first-table',
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
    put_version_table(dataset_id, version, 'the-first-table', contents)
    put_version_metadata(dataset_id, version, content)

    with \
            requests.Session() as session, \
            session.get(version_table_filter_columns(dataset_id,
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
            session.get(version_table_public_url_download(dataset_id,
                                                          version,
                                                          'the-first-table')
                        + base_query_args) as response:
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}--the-first-table.csv"'

        assert b'1,foo' in response.content
        assert b'2,bar' in response.content

    # should return all rows but only the name_field column
    query_args = base_query_args + '&_columns=name_field'
    with \
            requests.Session() as session, \
            session.get(version_table_public_url_download(dataset_id,
                                                          version,
                                                          'the-first-table')
                        + query_args) as response:
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}--the-first-table.csv"'

        assert b'1' not in response.content
        assert b'foo' in response.content
        assert b'2' not in response.content
        assert b'bar' in response.content

    # should return only rows with id_field=1 and only the name_field column
    query_args = base_query_args + '&id_field=1&_columns=name_field'
    with \
            requests.Session() as session, \
            session.get(version_table_public_url_download(dataset_id,
                                                          version,
                                                          'the-first-table')
                        + query_args) as response:
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}--the-first-table.csv"'

        assert b'1' not in response.content
        assert b'foo' in response.content
        assert b'2' not in response.content
        assert b'bar' not in response.content

    # should return rows with both id_field=1 and id_field=2 and only the name_field column
    query_args = base_query_args + '&id_field=1,2&_columns=name_field'
    with \
            requests.Session() as session, \
            session.get(version_table_public_url_download(dataset_id,
                                                          version,
                                                          'the-first-table')
                        + query_args) as response:
        assert response.headers['content-type'] == 'text/csv'
        assert response.headers['content-disposition'] == \
            f'attachment; filename="{dataset_id}--{version}--the-first-table.csv"'

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
            session.get(list_dataset_tables_public_url(dataset_id, version)) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"tables": []}'


def test_list_tables_for_dataset_version(processes):
    dataset_id = str(uuid.uuid4())
    put_version_table(dataset_id, 'v0.0.1', 'foo', b'header\n' + b'value\n' * 10000)
    with \
            requests.Session() as session, \
            session.get(list_dataset_tables_public_url(dataset_id, 'v0.0.1')) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"tables": [{"id": "foo"}]}'

    put_version_table(dataset_id, 'v0.0.1', 'bar', b'header\n' + b'value\n' * 1000000)
    with \
            requests.Session() as session, \
            session.get(list_dataset_tables_public_url(dataset_id, 'v0.0.1')) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"tables": [{"id": "bar"}, {"id": "foo"}]}'

    put_version_table(dataset_id, 'v0.0.2', 'baz', b'header\n' + b'value\n' * 10000)
    with \
            requests.Session() as session, \
            session.get(list_dataset_tables_public_url(dataset_id, 'v0.0.1')) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"tables": [{"id": "bar"}, {"id": "foo"}]}'

    with \
            requests.Session() as session, \
            session.get(list_dataset_tables_public_url(dataset_id, 'v0.0.2')) as response:
        assert response.headers['content-type'] == 'text/json'
        assert response.content == b'{"tables": [{"id": "baz"}]}'


def test_list_tables_for_dataset__latest_version(processes):
    dataset_id = str(uuid.uuid4())
    put_version_table(dataset_id, 'v0.0.1', 'foo', b'header\n' + b'value\n' * 10000)
    put_version_table(dataset_id, 'v0.0.2', 'bar', b'header\n' + b'value\n' * 10000)
    put_version_table(dataset_id, 'v0.0.2', 'baz', b'header\n' + b'value\n' * 10000)
    with \
            requests.Session() as session, \
            session.get(list_dataset_tables_public_url(dataset_id, 'latest')) as response:
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
                        stream=True) as response:
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
            session.get(version_table_public_url(dataset_id, version, table)) as response:
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
    put_version_table(dataset_id, version, table, content)

    table_url = version_table_public_url_no_format(dataset_id, version, table)
    with requests.Session() as session, session.get(table_url) as response:
        assert response.status_code == 400
        assert response.content == b'The query string must have a "format" term'
        assert not response.history

    table_url = version_table_public_url(dataset_id, version, table)
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
        assert response.content == b'The query string "format" term must be one of "(\'json\',)"'
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
    put_version_table(dataset_id, version, table, content)

    table_url = version_table_public_url_bad_format(dataset_id, version, table)
    with requests.Session() as session, session.get(table_url) as response:
        assert response.status_code == 400
        assert response.content == b'The query string "format" term must be one of "(\'csv\',)"'
        assert not response.history

    table_url = version_table_public_url(dataset_id, version, table)
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

    table_url = version_table_public_url(dataset_id, 'latest', 'does-not-exist')
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
        put_version_table(dataset_id, version, table, content)

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
        put_version_table(dataset_id, version, table, content)

    with \
            requests.Session() as session, \
            session.get(version_data_public_url(dataset_id, 'latest', 'json'),
                        headers={'x-forwarded-proto': 'https'},
                        allow_redirects=False
                        ) as response:
        assert response.headers['location'].startswith('https://')

    with \
            requests.Session() as session, \
            session.get(version_table_public_url(dataset_id, 'latest', table)) as response:
        assert response.content == content
        assert response.headers['content-length'] == str(len(content))
        assert response.headers['content-type'] == 'text/csv'
        assert len(response.history) == 1
        assert response.history[0].status_code == 302
        assert 'v10.10.32' in response.request.url

    with \
            requests.Session() as session, \
            session.get(version_table_public_url(dataset_id, 'v2', table)) as response:
        assert response.headers['content-type'] == 'text/csv'
        assert len(response.history) == 1
        assert response.history[0].status_code == 302
        assert 'v2.10.32' in response.request.url

    with \
            requests.Session() as session, \
            session.get(version_table_public_url(dataset_id, 'v3.4', table)) as response:
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
    delete_all_objects()

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


def test_logs_ecs_format():
    with application() as (_, outputs):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content, 'json')
        url = f'/v1/datasets/{dataset_id}/versions/{version}/data'
        with requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, version, 'json')) as response:
            assert response.status_code == 200

    web_output, web_error = outputs['web']
    assert web_error == b''
    web_output_logs = web_output.decode().split('\n')
    assert len(web_output_logs) >= 1
    web_api_call_log = [json.loads(log) for log in web_output_logs if url in log]
    assert len(web_api_call_log) == 2
    assert 'ecs' in web_api_call_log[0]
    assert b'Shut down gracefully' in web_output

    worker_output, worker_error = outputs['worker']
    assert worker_error == b''
    assert b'Shut down gracefully' in worker_output


def test_elastic_apm(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')
    url = f'/v1/datasets/{dataset_id}/versions/{version}/data'
    query = json.dumps({
        'query': {
            'match': {
                'url.path': url
            }
        }
    })
    with requests.Session() as session:
        retry = 0
        while retry < 20:
            session.get(version_data_public_url(dataset_id, version, 'json'))
            time.sleep(1)
            response = requests.get(
                url='http://localhost:9201/apm-7.8.0-transaction/_search',
                data=query,
                headers={'Accept': 'application/json', 'Content-type': 'application/json'}
            )
            res = json.loads(response.text)
            if retry > 0 and 'hits' in res and res['hits']['total']['value']:
                break
            time.sleep(3)
            retry += 1

    assert 'hits' in res, f'Unexpected Elastic Search api response: {str(res)}'
    assert res['hits']['total']['value'] >= 1, 'No hits found'


def test_healthcheck_ok(processes):
    dataset_id = 'healthcheck'
    content_str = {'status': 'OK'}
    content = json.dumps(content_str).encode()
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    with \
            requests.Session() as session, \
            session.get('http://127.0.0.1:8080/healthcheck') as response:
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
            session.get('http://127.0.0.1:8080/healthcheck') as response:
        assert response.status_code == 503


def test_noindex_header(processes):
    dataset_id = str(uuid.uuid4())
    content_str = {'foo': 'bar'}
    content = json.dumps(content_str).encode()
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')

    data_url = version_data_public_url(dataset_id, version, 'json')
    with requests.Session() as session, session.get(data_url) as response:
        assert response.status_code == 200
        assert response.headers['X-Robots-Tag'] == 'no-index, no-follow'


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
            session.get('http://127.0.0.1:9001/api/1/errors') as response:
        assert int(response.content) >= 10


def test_google_analytics_integration(processes):
    dataset_id = str(uuid.uuid4())
    content = str(uuid.uuid4()).encode() * 100000
    version = 'v0.0.1'
    put_version_data(dataset_id, version, content, 'json')
    with requests.Session() as session:
        session.get(version_data_public_url(dataset_id, version, 'json'))
        session.get(version_data_public_url_download(dataset_id, version, 'json'))
        session.get(version_table_public_url(dataset_id, version, 'table'))
        session.get(version_table_public_url_download(dataset_id, version, 'table'))
        with \
                requests.Session() as session, \
                session.post('http://127.0.0.1:9002/calls') as response:
            assert int(response.content) == 4


def test_docs(processes):
    with requests.Session() as session, session.get('http://127.0.0.1:8080') as response:
        assert response.status_code == 200


def put_version_metadata(dataset_id, version, contents):
    return put_object(f'{dataset_id}/{version}/metadata--csvw.json', contents)


def put_version_data(dataset_id, version, contents, extension):
    return put_object(f'{dataset_id}/{version}/data.{extension}', contents)


def put_version_table(dataset_id, version, table, contents):
    return put_object(f'{dataset_id}/{version}/tables/{table}/data.csv', contents)


def put_version_table_gzipped(dataset_id, version, table, contents):
    return put_object(
        f'{dataset_id}/{version}/tables/{table}/data.csv.gz', gzip.compress(contents)
    )


def get_csv_data(dataset_id, version, table):
    return get_object(f'{dataset_id}/{version}/tables/{table}/data.csv')


def get_csv_data_gzipped(dataset_id, version, table):
    return get_object(f'{dataset_id}/{version}/tables/{table}/data.csv.gz')


def put_object(key, contents):
    url = f'http://127.0.0.1:9000/my-bucket/{key}'
    body_hash = hashlib.sha256(contents).hexdigest()
    parsed_url = urllib.parse.urlsplit(url)

    headers = aws_sigv4_headers(
        'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        (), 's3', 'us-east-1', parsed_url.netloc, 'PUT', parsed_url.path, (), body_hash,
    )
    with requests.put(url, data=contents, headers=dict(headers)) as response:
        response.raise_for_status()


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
        token = ''

        def _list(extra_query_items=()):
            nonlocal token

            token = ''
            query = (
                ('max-keys', '1000'),
                ('list-type', '2'),
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
                if element.tag == f'{namespace}Contents':
                    for child in element:
                        if child.tag == f'{namespace}Key':
                            yield child.text
                if element.tag == f'{namespace}NextContinuationToken':
                    token = element.text

        yield from _list()

        while token:
            yield from _list((('continuation-token', token),))

    for key in list_keys():
        url = f'http://127.0.0.1:9000/my-bucket/{key}'
        parsed_url = urllib.parse.urlsplit(url)
        body = b''
        body_hash = hashlib.sha256(body).hexdigest()
        headers = aws_sigv4_headers(
            'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            (), 's3', 'us-east-1', parsed_url.netloc, 'DELETE', parsed_url.path, (), body_hash,
        )
        with requests.delete(url, data=body, headers=dict(headers)) as response:
            response.raise_for_status()


_url_prefix = 'http://127.0.0.1:8080/v1/datasets'


def list_datasets_public_url():
    return f'{_url_prefix}?format=json'


def list_dataset_versions_public_url(dataset_id):
    return f'{_url_prefix}/{dataset_id}/versions?format=json'


def list_dataset_tables_public_url(dataset_id, version):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/tables?format=json'


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


def version_table_public_url(dataset_id, version, table):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/tables/{table}/data?format=csv'


def version_table_public_url_download(dataset_id, version, table):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/tables/{table}/data?format=csv&download'


def version_table_public_url_no_format(dataset_id, version, table):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/tables/{table}/data'


def version_table_public_url_bad_format(dataset_id, version, table):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/tables/{table}/data?format=txt'


def version_table_filter_rows(dataset_id, version, table):
    return (
        f'{_url_prefix}/{dataset_id}/versions/{version}/tables/{table}/'
        'filter/rows'
    )


def version_table_filter_columns(dataset_id, version, table):
    return (
        f'{_url_prefix}/{dataset_id}/versions/{version}/tables/{table}/'
        'filter/columns'
    )


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
