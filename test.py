import os
import time
import socket
import subprocess
import unittest

import requests


class TestS3Proxy(unittest.TestCase):

    def test_root(self):
        stop_application = create_application(8080)
        self.addCleanup(stop_application)

        response = requests.get('http://127.0.0.1:8080/')
        self.assertEqual(response.content, b'Hello World!')


def create_application(port):
    process = subprocess.Popen(
        ['python3', 'app.py', ],
        env={
            **os.environ,
            'PORT': str(port),
        }
    )

    max_attempts = 100
    for i in range(0, max_attempts):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                break
        except OSError:
            if i == max_attempts - 1:
                raise
            time.sleep(0.01)

    def stop():
        process.terminate()
        process.wait(timeout=5)

    return stop
