import os
import time
import socket
import subprocess
import unittest

import requests


class TestS3Proxy(unittest.TestCase):

    def test_root(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)

        wait_until_started()

        response = requests.get('http://127.0.0.1:8080/')
        self.assertEqual(response.content, b'Hello World!')


def create_application(port, max_attempts=100):
    process = subprocess.Popen(
        ['python3', 'app.py', ],
        env={
            **os.environ,
            'PORT': str(port),
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
