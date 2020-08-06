from datetime import (
    datetime,
)
import hashlib
import hmac
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


def with_application(port, max_attempts=100, aws_access_key_id='AKIAIOSFODNN7EXAMPLE'):
    def decorator(original_test):
        def test_with_application(self):
            with open('Procfile', 'r') as file:
                args = shlex.split(next(line for line in file.read().splitlines()
                                        if line.startswith('web:'))[5:])

            process = subprocess.Popen(
                args,
                stderr=subprocess.PIPE,  # Silence logs
                stdout=subprocess.PIPE,
                env={
                    **os.environ,
                    'PORT': str(port),
                    'AWS_S3_REGION': 'us-east-1',
                    'AWS_ACCESS_KEY_ID': aws_access_key_id,
                    'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                    'AWS_S3_ENDPOINT': 'http://127.0.0.1:9000/my-bucket/',
                }
            )

            def stop():
                process.terminate()
                process.wait(timeout=5)
                process.stderr.close()
                process.stdout.close()

            try:
                for i in range(0, max_attempts):
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                            break
                    except (OSError, ConnectionRefusedError):
                        if i == max_attempts - 1:
                            raise
                        time.sleep(0.02)
                original_test(self, process)
            finally:
                stop()

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
                session.get(version_public_url(dataset_id, version)) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
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
                session.get(version_public_url(dataset_id_1,
                                               version_1), stream=True) as response_1, \
                session.get(version_public_url(dataset_id_2,
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
    def test_key_that_exists_during_shutdown_completes(self, process):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        chunks = []

        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version), stream=True) as response:

            self.assertEqual(response.headers['content-length'], str(len(content)))
            process.terminate()

            for chunk in response.iter_content(chunk_size=16384):
                chunks.append(chunk)
                time.sleep(0.02)

        self.assertEqual(b''.join(chunks), content)

    @with_application(8080)
    def test_key_that_exists_after_multiple_sigterm_completes(self, process):
        # PaaS can apparently send multiple sigterms

        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        chunks = []

        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version), stream=True) as response:

            self.assertEqual(response.headers['content-length'], str(len(content)))
            process.terminate()
            time.sleep(0.1)
            process.terminate()

            for chunk in response.iter_content(chunk_size=16384):
                chunks.append(chunk)
                time.sleep(0.02)

        self.assertEqual(b''.join(chunks), content)

    @with_application(8080)
    def test_key_that_exists_during_shutdown_completes_but_new_connection_rejected(self, process):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        chunks = []

        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version), stream=True) as response:
            self.assertEqual(response.headers['content-length'], str(len(content)))

            process.terminate()

            with self.assertRaises(requests.exceptions.ConnectionError):
                session.get(version_public_url(dataset_id, version), stream=True)

            for chunk in response.iter_content(chunk_size=16384):
                chunks.append(chunk)
                time.sleep(0.02)

        self.assertEqual(b''.join(chunks), content)

    @with_application(8080)
    def test_key_that_exists_during_shutdown_completes_but_request_on_old_conn(self, process):
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
            with \
                    session.get(version_public_url(dataset_id, version), stream=True) as resp_2, \
                    session.get(version_public_url(dataset_id, version), stream=True) as resp_3:

                for chunk in resp_2.iter_content(chunk_size=16384):
                    pass

                for chunk in resp_3.iter_content(chunk_size=16384):
                    pass

            with session.get(version_public_url(dataset_id, version), stream=True) as resp_4:

                process.terminate()

                # No exception raised since the connection is already open
                with session.get(version_public_url(dataset_id, version)):
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
        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version), headers=headers) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))

    @with_application(8080)
    def test_range_request_after_start(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        headers = {'range': 'bytes=1-'}
        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version), headers=headers) as response:
            self.assertEqual(response.content, content[1:])
            self.assertEqual(response.headers['content-length'], str(len(content) - 1))

    @with_application(8080, aws_access_key_id='not-exist')
    def test_bad_aws_credentials(self, _):
        dataset_id = str(uuid.uuid4())
        version = 'v0.0.1'

        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version)) as response:
            self.assertEqual(response.status_code, 500)

    @with_application(8080)
    def test_key_that_does_not_exist(self, _):
        dataset_id = str(uuid.uuid4())
        version = 'v0.0.1'

        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version)) as response:
            self.assertEqual(response.status_code, 404)

    @with_application(8080)
    def test_key_that_exists_without_format(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        with \
                requests.Session() as session, \
                session.get(version_public_url_no_format(dataset_id, version)) as response:
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.content, b'The query string must have a "format" term')
            self.assertEqual(len(response.history), 0)

        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version)) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(len(response.history), 0)

    @with_application(8080)
    def test_key_that_exists_with_bad_format(self, _):
        dataset_id = str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        version = 'v0.0.1'
        put_version_data(dataset_id, version, content)

        with \
                requests.Session() as session, \
                session.get(version_public_url_bad_format(dataset_id, version)) as response:
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.content, b'The query string "format" term must equal "json"')
            self.assertEqual(len(response.history), 0)

        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version)) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
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
            'query_sql': 'SELECT * FROM S3Object[*].topLevel[*]'
        }
        expected_content = json.dumps({
            'rows': (
                [{'a': '>&', 'd': 'e'}] * 100000
                + [{'a': 'c'}] * 1
                + [{'a': '🍰', 'd': 'f'}] * 100000
            ),
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version), params=params) as response:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, expected_content)
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
            'query_sql': 'SELECT * FROM S3Object[*].topLevel[*]'
        }
        expected_content = json.dumps({
            'rows': (
                [{'a': '\n' * 10000}] * 100
            ),
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version), params=params) as response:
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
            'query_sql': 'SELECT * FROM S3Object[*].topLevel[*]'
        }
        expected_content = json.dumps({
            'rows': (
                [{'a': '\\u003e🍰\\u0026>&\\u003e\\u0026>\\u0026\\u002\\\\u0026\\n' * 10000}] * 10
            ),
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version), params=params) as response:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, expected_content)
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
            'query_sql': "SELECT * FROM S3Object[*].topLevel[*] AS t WHERE t.a = '>&' OR t.a='🍰'"
        }
        expected_content = json.dumps({
            'rows': [{'a': '>&', 'd': 'e'}] * 100000 + [{'a': '🍰', 'd': 'f'}] * 100000,
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version), params=params) as response:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, expected_content)
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
            'query_sql': "SELECT * FROM S3Object[*].topLevel[*] AS t WHERE t.a = 'notexists'"
        }
        expected_content = json.dumps({
            'rows': []
        }, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

        with \
                requests.Session() as session, \
                session.get(version_public_url(dataset_id, version), params=params) as response:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, expected_content)
            self.assertEqual(len(response.history), 0)


def put_version_data(dataset_id, version, contents):
    return put_object(f'{dataset_id}/{version}/data.json', contents)


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


def version_public_url(dataset_id, version):
    return f'http://127.0.0.1:8080/v1/datasets/{dataset_id}/versions/{version}/data?format=json'


def version_public_url_no_format(dataset_id, version):
    return f'http://127.0.0.1:8080/v1/datasets/{dataset_id}/versions/{version}/data'


def version_public_url_bad_format(dataset_id, version):
    return f'http://127.0.0.1:8080/v1/datasets/{dataset_id}/versions/{version}/data?format=csv'


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
