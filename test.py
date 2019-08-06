from datetime import (
    datetime,
)
import hashlib
import hmac
import os
import time
import socket
import subprocess
import unittest
import urllib.parse
import uuid

import requests


class TestS3Proxy(unittest.TestCase):

    def test_meta_create_application_fails(self):
        wait_until_started, stop_application = create_application(
            8080, max_attempts=1)

        with self.assertRaises(ConnectionError):
            wait_until_started()

        stop_application()

    def test_key_that_exists(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)

        wait_until_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with requests.get(f'http://127.0.0.1:8080/{key}') as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))

    def test_multiple_concurrent_requests(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)

        wait_until_started()

        key_1 = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        key_2 = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content_1 = str(uuid.uuid4()).encode() * 1000000
        content_2 = str(uuid.uuid4()).encode() * 1000000

        put_object(key_1, content_1)
        put_object(key_2, content_2)

        with \
                requests.get(f'http://127.0.0.1:8080/{key_1}', stream=True) as response_1, \
                requests.get(f'http://127.0.0.1:8080/{key_2}', stream=True) as response_2:

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

    def test_range_request_from_start(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)

        wait_until_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with requests.get(f'http://127.0.0.1:8080/{key}', headers={
                'range': 'bytes=0-',
        }) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))

    def test_range_request_after_start(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)

        wait_until_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with requests.get(f'http://127.0.0.1:8080/{key}', headers={
                'range': 'bytes=1-',
        }) as response:
            self.assertEqual(response.content, content[1:])
            self.assertEqual(response.headers['content-length'], str(len(content) - 1))

    def test_bad_aws_credentials(self):
        wait_until_started, stop_application = create_application(
            8080, aws_access_key_id='not-exist')
        self.addCleanup(stop_application)

        wait_until_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())

        with requests.get(f'http://127.0.0.1:8080/{key}') as response:
            self.assertEqual(response.status_code, 500)

    def test_key_that_does_not_exist(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)

        wait_until_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())

        with requests.get(f'http://127.0.0.1:8080/{key}') as response:
            self.assertEqual(response.status_code, 404)


def create_application(
        port, max_attempts=100,
        aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
):
    process = subprocess.Popen(
        ['python3', 'app.py', ],
        stderr=subprocess.PIPE,  # Silence logs
        stdout=subprocess.PIPE,
        env={
            **os.environ,
            'PORT': str(port),
            'AWS_DEFAULT_REGION': 'us-east-1',
            'AWS_ACCESS_KEY_ID': aws_access_key_id,
            'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'AWS_S3_ENDPOINT': 'http://127.0.0.1:9000/',
            'AWS_S3_BUCKET': 'my-bucket',
        }
    )

    def wait_until_started():
        for i in range(0, max_attempts):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    break
            except ConnectionRefusedError:
                if i == max_attempts - 1:
                    raise
                time.sleep(0.01)

    def stop():
        process.terminate()
        process.wait(timeout=5)
        process.stderr.close()
        process.stdout.close()

    return wait_until_started, stop


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
