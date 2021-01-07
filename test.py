from datetime import (
    datetime,
)
import hashlib
import hmac
import itertools
import json
import os
import time
import shlex
import socket
import subprocess
import unittest
import urllib.parse
import uuid

import requests


def with_application(port, max_attempts=500, aws_access_key_id='AKIAIOSFODNN7EXAMPLE'):
    def decorator(original_test):
        def test_with_application(self):
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

            processes = {
                name: subprocess.Popen(
                    args,
                    stderr=subprocess.PIPE,  # Silence logs
                    stdout=subprocess.PIPE,
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

            def stop():
                time.sleep(0.10)  # Sentry needs some extra time to log any errors
                for _, process in processes.items():
                    process.kill()
                for _, process in processes.items():
                    process.wait(timeout=5)
                output_errors = {
                    name: process.communicate()
                    for name, process in processes.items()
                }
                for _, process in processes.items():
                    process.stderr.close()
                    process.stdout.close()
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
                original_test(self, processes)
            finally:
                output_errors = stop()

            return output_errors
        return test_with_application
    return decorator


class TestS3Proxy(unittest.TestCase):

    def test_meta_with_application_fails(self):
        @with_application(8080, max_attempts=1)
        def test(*_):
            pass

        with self.assertRaises(ConnectionError):
            test(self)

    @with_application(8080)
    def test_key_that_exists(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, version)) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'application/json')
            self.assertNotIn('content-disposition', response.headers)
            self.assertEqual(len(response.history), 0)

        with \
                requests.Session() as session, \
                session.get(version_data_public_url_download(dataset_id, version)) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'application/json')
            self.assertEqual(response.headers['content-disposition'],
                             f'attachment; filename="{dataset_id}--{version}.json"')
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_metadata_key_that_exists(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_metadata(dataset_id, version, content)

        with \
                requests.Session() as session, \
                session.get(version_metadata_public_url(dataset_id, version)) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'application/csvm+json')
            self.assertNotIn('content-disposition', response.headers)
            self.assertEqual(len(response.history), 0)

        with \
                requests.Session() as session, \
                session.get(version_metadata_public_url_download(dataset_id, version)) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'application/csvm+json')
            self.assertEqual(response.headers['content-disposition'],
                             f'attachment; filename="{dataset_id}--{version}--'
                             'metadata--csvw.json"')
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_table_key_that_exists(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        table = 'table'
        version = 'v0.0.1'
        put_version_table(dataset_id, version, table, content)

        with \
                requests.Session() as session, \
                session.get(version_table_public_url(dataset_id, version, table)) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'text/csv')
            self.assertNotIn('content-disposition', response.headers)
            self.assertEqual(len(response.history), 0)

        with \
                requests.Session() as session, \
                session.get(version_table_public_url_download(dataset_id,
                                                              version, table)) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'text/csv')
            self.assertEqual(response.headers['content-disposition'],
                             f'attachment; filename="{dataset_id}--{version}--{table}.csv"')
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_table_s3_select(self, _):
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
            print(response)
            self.assertEqual(
                response.content, 'c🍰é\ne\n&>'
                '\n"Ah, a comma"\n"A quote "" "\n\\u00f8C\n'.encode('utf-8'))
            self.assertEqual(response.headers['content-type'], 'text/csv')
            self.assertEqual(response.headers['content-disposition'],
                             f'attachment; filename="{dataset_id}--{version}--{table}.csv"')
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_multiple_concurrent_requests(self, _):
        dataset_id_1 = str(uuid.uuid4())
        dataset_id_2 = str(uuid.uuid4())
        version_1 = 'v0.0.1'
        version_2 = 'v0.0.2'
        content_1 = str(uuid.uuid4()).encode() * 1000000
        content_2 = str(uuid.uuid4()).encode() * 1000000

        put_version_data(dataset_id_1, version_1, content_1)
        put_version_data(dataset_id_2, version_2, content_2)

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id_1,
                                                    version_1), stream=True) as response_1, \
                session.get(version_data_public_url(dataset_id_2,
                                                    version_2), stream=True) as response_2:

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

        self.assertEqual(b''.join(response_content_1), content_1)
        self.assertEqual(b''.join(response_content_2), content_2)
        self.assertGreater(num_both, 1000)
        self.assertLess(num_single, 100)

    @with_application(8080)
    def test_key_that_exists_during_shutdown_completes(self, processes):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        chunks = []

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, version), stream=True) as response:

            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'application/json')
            processes['web'].terminate()

            for chunk in response.iter_content(chunk_size=16384):
                chunks.append(chunk)
                time.sleep(0.02)

        self.assertEqual(b''.join(chunks), content)

    @with_application(8080)
    def test_key_that_exists_after_multiple_sigterm_completes(self, processes):
        # PaaS can apparently send multiple sigterms

        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        chunks = []

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, version), stream=True) as response:

            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'application/json')
            processes['web'].terminate()
            time.sleep(0.1)
            processes['web'].terminate()

            for chunk in response.iter_content(chunk_size=16384):
                chunks.append(chunk)
                time.sleep(0.02)

        self.assertEqual(b''.join(chunks), content)

    @with_application(8080)
    def test_key_that_exists_during_shutdown_completes_but_new_connection_rejected(self,
                                                                                   processes):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        chunks = []

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, version), stream=True) as response:
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'application/json')

            processes['web'].terminate()

            with self.assertRaises(requests.exceptions.ConnectionError):
                session.get(version_data_public_url(dataset_id, version), stream=True)

            for chunk in response.iter_content(chunk_size=16384):
                chunks.append(chunk)
                time.sleep(0.02)

        self.assertEqual(b''.join(chunks), content)

    @with_application(8080)
    def test_key_that_exists_during_shutdown_completes_but_request_on_old_conn(self, processes):
        # Check that connections that were open before the SIGTERM still work
        # after. Unsure if this is desired on PaaS, so this is more of
        # documenting current behaviour

        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        chunks = []

        with requests.Session() as session:
            # Ensure we have two connections
            data_url = version_data_public_url(dataset_id, version)
            with session.get(data_url, stream=True) as resp_2, \
                    session.get(data_url, stream=True) as resp_3:

                for chunk in resp_2.iter_content(chunk_size=16384):
                    pass

                for chunk in resp_3.iter_content(chunk_size=16384):
                    pass

            with session.get(data_url, stream=True) as resp_4:
                processes['web'].terminate()

                # No exception raised since the connection is already open
                with session.get(data_url):
                    pass

                for chunk in resp_4.iter_content(chunk_size=16384):
                    time.sleep(0.02)
                    chunks.append(chunk)

        self.assertEqual(b''.join(chunks), content)

    @with_application(8080)
    def test_range_request_from_start(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        headers = {'range': 'bytes=0-'}
        data_url = version_data_public_url(dataset_id, version)
        with \
                requests.Session() as session, \
                session.get(data_url, headers=headers) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'application/json')

    @with_application(8080)
    def test_range_request_after_start(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        data_url = version_data_public_url(dataset_id, version)
        headers = {'range': 'bytes=1-'}
        with \
                requests.Session() as session, \
                session.get(data_url, headers=headers) as response:
            self.assertEqual(response.content, content[1:])
            self.assertEqual(response.headers['content-length'], str(len(content) - 1))
            self.assertEqual(response.headers['content-type'], 'application/json')

    @with_application(8080, aws_access_key_id='not-exist')
    def test_bad_aws_credentials(self, _):
        dataset_id = str(uuid.uuid4())
        version = 'v0.0.1'

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, version)) as response:
            self.assertEqual(response.status_code, 500)

    @with_application(8080)
    def test_key_that_does_not_exist(self, _):
        dataset_id = str(uuid.uuid4())
        version = 'v0.0.1'

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, version)) as response:
            self.assertEqual(response.status_code, 404)

    @with_application(8080)
    def test_table_key_that_does_not_exist(self, _):
        dataset_id = str(uuid.uuid4())
        version = 'v0.0.1'
        table = 'table'

        with \
                requests.Session() as session, \
                session.get(version_table_public_url(dataset_id, version, table)) as response:
            self.assertEqual(response.status_code, 404)

    @with_application(8080)
    def test_key_that_exists_without_format(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        with \
                requests.Session() as session, \
                session.get(version_data_public_url_no_format(dataset_id, version)) as response:
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.content, b'The query string must have a "format" term')
            self.assertEqual(len(response.history), 0)

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, version)) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'application/json')
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_table_key_that_exists_without_format(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        table = 'table'
        put_version_table(dataset_id, version, table, content)

        table_url = version_table_public_url_no_format(dataset_id, version, table)
        with requests.Session() as session, session.get(table_url) as response:
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.content, b'The query string must have a "format" term')
            self.assertEqual(len(response.history), 0)

        table_url = version_table_public_url(dataset_id, version, table)
        with requests.Session() as session, session.get(table_url) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'text/csv')
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_key_that_exists_with_bad_format(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        with \
                requests.Session() as session, \
                session.get(version_data_public_url_bad_format(dataset_id, version)) as response:
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.content,
                             b'The query string "format" term must be one of "(\'json\',)"')
            self.assertEqual(len(response.history), 0)

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, version)) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'application/json')
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_table_key_that_exists_with_bad_format(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        table = 'table'
        put_version_table(dataset_id, version, table, content)

        table_url = version_table_public_url_bad_format(dataset_id, version, table)
        with requests.Session() as session, session.get(table_url) as response:
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.content,
                             b'The query string "format" term must be one of "(\'csv\',)"')
            self.assertEqual(len(response.history), 0)

        table_url = version_table_public_url(dataset_id, version, table)
        with requests.Session() as session, session.get(table_url) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'text/csv')
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_select_all(self, _):
        dataset_id = str(uuid.uuid4())
        content = json.dumps({
            'topLevel': (
                [{'a': '>&', 'd': 'e'}] * 100000
                + [{'a': 'c'}] * 1
                + [{'a': '🍰', 'd': 'f'}] * 100000
            )
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

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

        data_url = version_data_public_url(dataset_id, version)
        with requests.Session() as session, session.get(data_url, params=params) as response:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, expected_content)
            self.assertEqual(response.headers['content-type'], 'application/json')
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_select_newlines(self, _):
        dataset_id = str(uuid.uuid4())
        content = json.dumps({
            'topLevel': (
                [{'a': '\n' * 10000}] * 100
            )
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        params = {
            'query-s3-select': 'SELECT * FROM S3Object[*].topLevel[*]'
        }
        expected_content = json.dumps({
            'rows': (
                [{'a': '\n' * 10000}] * 100
            ),
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

        data_url = version_data_public_url(dataset_id, version)
        with requests.Session() as session, session.get(data_url, params=params) as response:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, expected_content)
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_select_strings_that_are_almost_unicode_escapes(self, _):
        dataset_id = str(uuid.uuid4())
        content = json.dumps({
            'topLevel': (
                [{'a': '\\u003e🍰\\u0026>&\\u003e\\u0026>\\u0026\\u002\\\\u0026\\n' * 10000}] * 10
            )
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        params = {
            'query-s3-select': 'SELECT * FROM S3Object[*].topLevel[*]'
        }
        expected_content = json.dumps({
            'rows': (
                [{'a': '\\u003e🍰\\u0026>&\\u003e\\u0026>\\u0026\\u002\\\\u0026\\n' * 10000}] * 10
            ),
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

        data_url = version_data_public_url(dataset_id, version)
        with requests.Session() as session, session.get(data_url, params=params) as response:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, expected_content)
            self.assertEqual(response.headers['content-type'], 'application/json')
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_select_subset(self, _):
        dataset_id = str(uuid.uuid4())
        content = json.dumps({
            'topLevel': (
                [{'a': '>&', 'd': 'e'}] * 100000
                + [{'a': 'c'}] * 1
                + [{'a': '🍰', 'd': 'f'}] * 100000
            )
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        params = {
            'query-s3-select':
                'SELECT * FROM S3Object[*].topLevel[*] AS t '
                + "WHERE t.a = '>&' OR t.a='🍰'"
        }
        expected_content = json.dumps({
            'rows': [{'a': '>&', 'd': 'e'}] * 100000 + [{'a': '🍰', 'd': 'f'}] * 100000,
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

        data_url = version_data_public_url(dataset_id, version)
        with requests.Session() as session, session.get(data_url, params=params) as response:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, expected_content)
            self.assertEqual(response.headers['content-type'], 'application/json')
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_select_no_results(self, _):
        dataset_id = str(uuid.uuid4())
        content = json.dumps({
            'topLevel': (
                [{'a': '>&', 'd': 'e'}] * 100000
                + [{'a': 'c'}] * 1
                + [{'a': '🍰', 'd': 'f'}] * 100000
            )
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        params = {
            'query-s3-select': "SELECT * FROM S3Object[*].topLevel[*] AS t WHERE t.a = 'notexists'"
        }
        expected_content = json.dumps({
            'rows': []
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

        data_url = version_data_public_url(dataset_id, version)
        with requests.Session() as session, session.get(data_url, params=params) as response:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, expected_content)
            self.assertEqual(response.headers['content-type'], 'application/json')
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_no_latest_version(self, _):
        dataset_id = 'does-not-exist'

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, 'latest')) as response:
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.content, b'Dataset not found')
            self.assertEqual(len(response.history), 0)

        table_url = version_table_public_url(dataset_id, 'latest', 'does-not-exist')
        with requests.Session() as session, session.get(table_url) as response:
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.content, b'Dataset not found')
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_redirect_to_latest_version(self, _):
        dataset_id = str(uuid.uuid4())
        table = 'table'
        # Ranges chosen to make sure we have at least 3 pages from S3 list objects, and to make
        # sure we hit as many cases as possible where if we were taking the latest version
        # alphabetically, we would choose the wrong version
        for major, minor, patch in itertools.product(range(0, 11), range(0, 11), range(0, 33)):
            content = str(uuid.uuid4()).encode() * 10
            version = f'v{major}.{minor}.{patch}'
            put_version_data(dataset_id, version, content)
            put_version_table(dataset_id, version, table, content)

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, 'latest'),
                            headers={'x-forwarded-proto': 'https'},
                            allow_redirects=False
                            ) as response:
            self.assertTrue(response.headers['location'].startswith('https://'))

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, 'latest')) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'application/json')
            self.assertEqual(len(response.history), 1)
            self.assertEqual(302, response.history[0].status_code)
            self.assertIn('v10.10.32', response.request.url)

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, 'v2')) as response:
            self.assertEqual(response.headers['content-type'], 'application/json')
            self.assertEqual(len(response.history), 1)
            self.assertEqual(302, response.history[0].status_code)
            self.assertIn('v2.10.32', response.request.url)

        with \
                requests.Session() as session, \
                session.get(version_data_public_url(dataset_id, 'v3.4')) as response:
            self.assertEqual(response.headers['content-type'], 'application/json')
            self.assertEqual(len(response.history), 1)
            self.assertEqual(302, response.history[0].status_code)
            self.assertIn('v3.4.32', response.request.url)

    @with_application(8080)
    def test_table_redirect_to_latest_version(self, _):
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
                session.get(version_data_public_url(dataset_id, 'latest'),
                            headers={'x-forwarded-proto': 'https'},
                            allow_redirects=False
                            ) as response:
            self.assertTrue(response.headers['location'].startswith('https://'))

        with \
                requests.Session() as session, \
                session.get(version_table_public_url(dataset_id, 'latest', table)) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(response.headers['content-type'], 'text/csv')
            self.assertEqual(len(response.history), 1)
            self.assertEqual(302, response.history[0].status_code)
            self.assertIn('v10.10.32', response.request.url)

        with \
                requests.Session() as session, \
                session.get(version_table_public_url(dataset_id, 'v2', table)) as response:
            self.assertEqual(response.headers['content-type'], 'text/csv')
            self.assertEqual(len(response.history), 1)
            self.assertEqual(302, response.history[0].status_code)
            self.assertIn('v2.10.32', response.request.url)

        with \
                requests.Session() as session, \
                session.get(version_table_public_url(dataset_id, 'v3.4', table)) as response:
            self.assertEqual(response.headers['content-type'], 'text/csv')
            self.assertEqual(len(response.history), 1)
            self.assertEqual(302, response.history[0].status_code)
            self.assertIn('v3.4.32', response.request.url)

    @with_application(8080)
    def test_redirect_to_latest_version_query(self, _):
        dataset_id = str(uuid.uuid4())

        content_1 = json.dumps({
            'top_level': [{'a': 'y'}, {'a': 'y'}, {'common': 'b'}]
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        version_1 = 'v9.9.9'
        put_version_data(dataset_id, version_1, content_1)

        content_2 = json.dumps({
            'top_level': [{'a': 'y'}, {'common': 'b'}]
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        version_2 = 'v10.0.0'
        put_version_data(dataset_id, version_2, content_2)

        params = {
            'query-s3-select': "SELECT * FROM S3Object[*].top_level[*] row WHERE row.a = 'y'"
        }
        expected_content = json.dumps({
            'rows': [{'a': 'y'}],
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

        data_url = version_data_public_url(dataset_id, 'latest')
        with requests.Session() as session, session.get(data_url, params=params) as response:
            self.assertEqual(response.content, expected_content)
            self.assertEqual(response.headers['content-type'], 'application/json')
            self.assertEqual(len(response.history), 1)
            self.assertEqual(302, response.history[0].status_code)
            self.assertIn('v10.0.0', response.request.url)

    @with_application(8080)
    def test_redirect_with_utf_8_in_query_string(self, _):
        # Test that documents that non-URL encoded values in query strings are redirected to their
        # URL-encoded equivalent. Not sure if this behaviour is desirable or not.
        dataset_id = str(uuid.uuid4())
        content = b'{"some":"content"}'
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)
        url = version_data_public_url(dataset_id, 'latest')
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
        self.assertIn(b'&something=' + cake_url_encoded, full_response)

    @with_application(8080)
    def test_csv_created(self, _):
        dataset_id = str(uuid.uuid4())
        version = 'v0.0.1'
        content = b'{"top":[{"id":1,"key":"value","nested":[{"key_2":"value_2"}]}]}'
        put_version_data(dataset_id, version, content)

        time.sleep(12)

        top_bytes, top_headers = get_csv_data(dataset_id, version, 'top')
        self.assertEqual(top_bytes, b'"id","key"\r\n1,"value"\r\n')

        nested_bytes, _ = get_csv_data(dataset_id, version, 'top--nested')
        self.assertEqual(nested_bytes, b'"top__id","key_2"\r\n1,"value_2"\r\n')

        time.sleep(12)

        # Ensure that we haven't unnecessarily recreated the CSVs
        _, top_headers_2 = get_csv_data(dataset_id, version, 'top')
        self.assertEqual(top_headers['last-modified'], top_headers_2['last-modified'])

    def test_logs_ecs_format(self):

        url = None

        @with_application(8080)
        def make_api_call(*_):
            nonlocal url
            dataset_id = str(uuid.uuid4())
            content = str(uuid.uuid4()).encode() * 100000
            version = 'v0.0.1'
            put_version_data(dataset_id, version, content)
            url = f'/v1/datasets/{dataset_id}/versions/{version}/data'
            with requests.Session() as session, \
                    session.get(version_data_public_url(dataset_id, version)) as response:
                self.assertEqual(200, response.status_code)

        output, error = make_api_call(self)['web']
        self.assertEqual(error, b'')
        output_logs = output.decode().split('\n')
        assert len(output_logs) >= 1
        api_call_log = [json.loads(log) for log in output_logs if url in log]
        assert len(api_call_log) == 2
        assert 'ecs' in api_call_log[0]

    @with_application(8080)
    def test_elastic_apm(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)
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
                session.get(version_data_public_url(dataset_id, version))
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

    @with_application(8080)
    def test_healthcheck_ok(self, _):
        dataset_id = 'healthcheck'
        content_str = {'status': 'OK'}
        content = json.dumps(content_str).encode()
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        with \
                requests.Session() as session, \
                session.get('http://127.0.0.1:8080/healthcheck') as response:
            self.assertEqual(response.status_code, 200)
            self.assertTrue('<status>OK</status>' in str(response.content))
            self.assertEqual(response.headers['content-type'], 'text/xml')
            self.assertEqual(response.headers['Cache-Control'],
                             'no-cache, no-store, must-revalidate')

    @with_application(8080)
    def test_healthcheck_fail(self, _):
        dataset_id = 'healthcheck'
        content_str = {'foo': 'bar'}
        content = json.dumps(content_str).encode()
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        with \
                requests.Session() as session, \
                session.get('http://127.0.0.1:8080/healthcheck') as response:
            self.assertEqual(response.status_code, 503)

    @with_application(8080)
    def test_noindex_header(self, _):
        dataset_id = str(uuid.uuid4())
        content_str = {'foo': 'bar'}
        content = json.dumps(content_str).encode()
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        data_url = version_data_public_url(dataset_id, version)
        with requests.Session() as session, session.get(data_url) as response:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['X-Robots-Tag'], 'no-index, no-follow')

    @with_application(8080, aws_access_key_id='not-exist')
    def test_sentry_integration(self, _):
        # Passing a bad AWS access key will result in a 403 when calling S3
        # and this will raise an Exception that should be reported to sentry.
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        for _ in range(10):
            with \
                    requests.Session() as session, \
                    session.get(version_data_public_url(dataset_id, version)) as response:
                self.assertEqual(response.status_code, 500)

        with \
                requests.Session() as session, \
                session.get('http://127.0.0.1:9001/api/1/errors') as response:
            self.assertGreaterEqual(int(response.content), 10)

    @with_application(8080)
    def test_google_analytics_integration(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)
        with requests.Session() as session:
            session.get(version_data_public_url(dataset_id, version))
            session.get(version_data_public_url_download(dataset_id, version))
            session.get(version_table_public_url(dataset_id, version, 'table'))
            session.get(version_table_public_url_download(dataset_id, version, 'table'))
            with \
                    requests.Session() as session, \
                    session.post('http://127.0.0.1:9002/calls') as response:
                self.assertEqual(int(response.content), 4)


def put_version_metadata(dataset_id, version, contents):
    return put_object(f'{dataset_id}/{version}/metadata--csvw.json', contents)


def put_version_data(dataset_id, version, contents):
    return put_object(f'{dataset_id}/{version}/data.json', contents)


def put_version_table(dataset_id, version, table, contents):
    return put_object(f'{dataset_id}/{version}/tables/{table}/data.csv', contents)


def get_csv_data(dataset_id, version, table):
    return get_object(f'{dataset_id}/{version}/tables/{table}/data.csv')


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


_url_prefix = 'http://127.0.0.1:8080/v1/datasets'


def version_metadata_public_url(dataset_id, version):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/metadata?format=csvw'


def version_metadata_public_url_download(dataset_id, version):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/metadata?format=csvw&download'


def version_data_public_url(dataset_id, version):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/data?format=json'


def version_data_public_url_download(dataset_id, version):
    return f'{_url_prefix}/{dataset_id}/versions/{version}/data?format=json&download'


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
