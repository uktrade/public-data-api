import os
import time
import socket
import subprocess
import unittest
import uuid

import boto3
from botocore.client import (
    Config,
)
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

        client = get_s3_client()
        client.put_object(
            Bucket='my-bucket',
            Key=key,
            Body=content,
        )

        response = requests.get(f'http://127.0.0.1:8080/{key}')
        self.assertEqual(response.content, content)
        self.assertEqual(response.headers['content-length'], str(len(content)))

    def test_range_request_from_start(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)

        wait_until_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000

        client = get_s3_client()
        client.put_object(
            Bucket='my-bucket',
            Key=key,
            Body=content,
        )

        response = requests.get(f'http://127.0.0.1:8080/{key}', headers={
            'range': 'bytes=0-',
        })
        self.assertEqual(response.content, content)
        self.assertEqual(response.headers['content-length'], str(len(content)))

    def test_range_request_after_start(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)

        wait_until_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000

        client = get_s3_client()
        client.put_object(
            Bucket='my-bucket',
            Key=key,
            Body=content,
        )

        response = requests.get(f'http://127.0.0.1:8080/{key}', headers={
            'range': 'bytes=1-',
        })
        self.assertEqual(response.content, content[1:])
        self.assertEqual(response.headers['content-length'], str(len(content) - 1))

    def test_bad_aws_credentials(self):
        wait_until_started, stop_application = create_application(
            8080, aws_access_key_id='not-exist')
        self.addCleanup(stop_application)

        wait_until_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())

        response = requests.get(f'http://127.0.0.1:8080/{key}')
        self.assertEqual(response.status_code, 500)

    def test_key_that_does_not_exist(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)

        wait_until_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())

        response = requests.get(f'http://127.0.0.1:8080/{key}')
        self.assertEqual(response.status_code, 404)


def create_application(
        port, max_attempts=100,
        aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
):
    process = subprocess.Popen(
        ['python3', 'app.py', ],
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

    return wait_until_started, stop


def get_s3_client():
    return boto3.client(
        's3',
        endpoint_url='http://127.0.0.1:9000/',
        aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
        aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        config=Config(signature_version='s3v4'),
        region_name='us-east-1',
    )
