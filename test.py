import time
import socket
import subprocess
import unittest


class TestS3Proxy(unittest.TestCase):

    def test_root(self):
        stop_application = create_application()
        self.addCleanup(stop_application)


def create_application():
    process = subprocess.Popen(
        ['python3', 'app.py', ]
    )

    for _ in range(0, 10):
        try:
            with socket.create_connection(('127.0.0.1', 8080), timeout=0.2):
                break
        except OSError:
            time.sleep(0.01)

    def stop():
        process.terminate()
        process.wait(timeout=5)

    return stop
