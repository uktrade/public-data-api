from datetime import (
    datetime,
)
import hashlib
import hmac
import json
from multiprocessing import (
    Process,
)
import os
import re
import sys
import time
import signal
import socket
import subprocess
import unittest
import urllib.parse
import uuid

from flask import (
    Flask,
    Response,
    request,
)
import redis
import requests


class TestS3Proxy(unittest.TestCase):

    def test_meta_create_application_fails(self):
        wait_until_started, stop_application = create_application(
            8080, max_attempts=1)

        with self.assertRaises(ConnectionError):
            wait_until_started()

        stop_application()

    def test_meta_sso_fails(self):
        wait_until_sso_started, stop_sso = create_sso(max_attempts=1)

        with self.assertRaises(ConnectionError):
            wait_until_sso_started()

        stop_sso()

    def test_key_that_exists(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}') as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(len(response.history), 3)

    def test_key_that_exists_parallel_requests_same_session(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso(tokens_returned=('the-token', 'the-token'))
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with requests.Session() as session:
            with session.get(f'http://127.0.0.1:8080/{key}', allow_redirects=False) as resp_1_1:
                url_1_2 = resp_1_1.headers['location']

            with session.get(f'http://127.0.0.1:8080/{key}', allow_redirects=False) as resp_2_1:
                url_2_2 = resp_2_1.headers['location']

            with session.get(url_1_2, allow_redirects=False) as resp_1_2:
                url_1_2 = resp_1_2.headers['location']

            with session.get(url_2_2, allow_redirects=False) as resp_2_2:
                url_2_2 = resp_2_2.headers['location']

            with session.get(url_1_2, allow_redirects=False) as resp_1_3:
                url_1_3 = resp_1_3.headers['location']

            with session.get(url_1_2, allow_redirects=False) as resp_2_3:
                url_2_3 = resp_2_3.headers['location']

            with session.get(url_1_3) as resp_1_4:
                self.assertEqual(resp_1_4.status_code, 200)
                self.assertEqual(resp_1_4.content, content)
                self.assertEqual(resp_1_4.headers['content-length'], str(len(content)))

            with session.get(url_2_3) as resp_2_4:
                self.assertEqual(resp_2_4.status_code, 200)
                self.assertEqual(resp_2_4.content, content)
                self.assertEqual(resp_2_4.headers['content-length'], str(len(content)))

    def test_key_that_exists_parallel_requests_new_session_on_redirection_endpoint(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso(tokens_returned=('the-token', 'the-token'))
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with \
                requests.Session() as sess_1, \
                requests.Session() as sess_2:
            with sess_1.get(f'http://127.0.0.1:8080/{key}', allow_redirects=False) as resp_1_1:
                url_1_2 = resp_1_1.headers['location']

            with sess_1.get(f'http://127.0.0.1:8080/{key}', allow_redirects=False) as resp_2_1:
                url_2_2 = resp_2_1.headers['location']

            with sess_1.get(url_1_2, allow_redirects=False) as resp_1_2:
                url_1_2 = resp_1_2.headers['location']

            with sess_1.get(url_2_2, allow_redirects=False) as resp_2_2:
                url_2_2 = resp_2_2.headers['location']

            with sess_1.get(url_1_2, allow_redirects=False) as resp_1_3:
                url_1_3 = resp_1_3.headers['location']

            # No cookies, so no dependant on anything in the session
            with sess_2.get(url_1_2, allow_redirects=False) as resp_2_3:
                url_2_3 = resp_2_3.headers['location']

            with sess_1.get(url_1_3) as resp_1_4:
                self.assertEqual(resp_1_4.status_code, 200)
                self.assertEqual(resp_1_4.content, content)
                self.assertEqual(resp_1_4.headers['content-length'], str(len(content)))

            with sess_2.get(url_2_3) as resp_2_4:
                self.assertEqual(resp_2_4.status_code, 200)
                self.assertEqual(resp_2_4.content, content)
                self.assertEqual(resp_2_4.headers['content-length'], str(len(content)))
                self.assertEqual(len(resp_2_4.history), 2)

    def test_key_that_exists_parallel_requests_mix_state_on_redirection_endpoint(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso(tokens_returned=('the-token', 'the-token'))
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with requests.Session() as sess:
            with sess.get(f'http://127.0.0.1:8080/{key}', allow_redirects=False) as resp_1_1:
                url_1_2 = resp_1_1.headers['location']

            with sess.get(f'http://127.0.0.1:8080/{key}', allow_redirects=False) as resp_2_1:
                url_2_2 = resp_2_1.headers['location']

            with sess.get(url_1_2, allow_redirects=False) as resp_1_2:
                url_1_2 = urllib.parse.urlsplit(resp_1_2.headers['location'])

            with sess.get(url_2_2, allow_redirects=False) as resp_2_2:
                url_2_2 = urllib.parse.urlsplit(resp_2_2.headers['location'])

            query_1 = urllib.parse.parse_qs(url_1_2.query)
            state_1_1, _ = query_1['state'][0].split('__')
            _, state_2_2 = urllib.parse.parse_qs(url_2_2.query)['state'][0].split('__')

            mixed_state_url = urllib.parse.urlunsplit(urllib.parse.SplitResult(
                url_1_2.scheme,
                url_1_2.netloc,
                url_1_2.path,
                f'code={query_1["code"][0]}&state={state_1_1}__{state_2_2}',
                fragment=''
            ))
            with sess.get(mixed_state_url, allow_redirects=False) as resp:
                self.assertEqual(resp.status_code, 403)

    def test_key_that_exists_no_trailing_question_mark(self):
        # Ensure that the server does not redirect to a URL with a trailing
        # question mark. A raw socket request is make to have access to the
        # raw bytes of the response, which are hidden if using Python requests
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        url_1 = f'http://127.0.0.1:8080/{key}'
        with \
                requests.Session() as session:
            with session.get(url_1, allow_redirects=False) as resp_1:
                url_2 = resp_1.headers['location']
                cookies_str = ';'.join(f'{key}={value}' for key, value in resp_1.cookies.items())

            with session.get(url_2, allow_redirects=False) as resp_2:
                url_3 = resp_2.headers['location']

            url_3_parsed = urllib.parse.urlsplit(url_3)
            url_3_full_path = url_3_parsed.path + \
                ('?' + url_3_parsed.query if url_3_parsed.query else '')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('127.0.0.1', 8080))
            req = \
                f'GET {url_3_full_path} HTTP/1.1\r\n' \
                f'host:127.0.0.1\r\n' \
                f'cookie:{cookies_str}\r\n' \
                f'\r\n'
            sock.send(req.encode())

            resp_4 = b''
            while b'\r\n\r\n' not in resp_4:
                resp_4 += sock.recv(4096)
            sock.close()

            self.assertIn(f'location: http://127.0.0.1:8080/{key}\r\n', resp_4.decode())

    def test_key_that_exists_with_trailing_question_mark(self):
        # Ensure that the server preserves trailing question marks through
        # redirects. Python requests can strip this, so we use raw socket
        # requests
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', 8080))
        req_1 = \
            f'GET /{key}? HTTP/1.1\r\n' \
            f'host:127.0.0.1:8080\r\n' \
            f'\r\n'
        sock.send(req_1.encode())

        resp_1 = b''
        while b'\r\n\r\n' not in resp_1:
            resp_1 += sock.recv(4096)
        sock.close()

        url_2 = re.search(b'location: (.*?)\r\n', resp_1, re.IGNORECASE)[1]
        cookie = re.search(b'set-cookie: (.*?)=(.*?);', resp_1, re.IGNORECASE)
        cookie_name, cookie_value = cookie[1].decode(), cookie[2].decode()

        resp_2 = requests.get(url_2, allow_redirects=False)
        url_3 = resp_2.headers['location']

        url_3_parsed = urllib.parse.urlsplit(url_3)
        url_3_full_path = url_3_parsed.path + \
            ('?' + url_3_parsed.query if url_3_parsed.query else '')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', 8080))
        req = \
            f'GET {url_3_full_path} HTTP/1.1\r\n' \
            f'host:127.0.0.1\r\n' \
            f'cookie:{cookie_name}={cookie_value}\r\n' \
            f'\r\n'
        sock.send(req.encode())

        resp_4 = b''
        while b'\r\n\r\n' not in resp_4:
            resp_4 += sock.recv(4096)
        sock.close()

        self.assertIn(f'location: http://127.0.0.1:8080/{key}?\r\n', resp_4.decode())

    def test_key_that_exists_no_session_302(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        url_1 = f'http://localhost:8080/{key}'
        with requests.get(url_1, allow_redirects=False) as resp_1:
            url_2 = resp_1.headers['location']

        with requests.get(url_2, allow_redirects=False) as resp_2:
            url_3 = resp_2.headers['location']

        with requests.get(url_3, allow_redirects=False) as resp_3:
            self.assertEqual(resp_3.content, b'')
            self.assertEqual(resp_3.status_code, 302)

    def test_key_that_exists_second_request_succeeds_no_redirect(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with requests.Session() as session:

            with session.get(f'http://127.0.0.1:8080/{key}'):
                pass

            with session.get(f'http://127.0.0.1:8080/{key}') as response:
                self.assertEqual(response.content, content)
                self.assertEqual(response.headers['content-length'], str(len(content)))
                self.assertEqual(len(response.history), 0)

    def test_key_that_exists_redis_cleared_then_succeeds(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso(tokens_returned=['the-token', 'the-token'])
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with requests.Session() as session:

            with session.get(f'http://127.0.0.1:8080/{key}'):
                pass

            redis_client = redis.from_url('redis://127.0.0.1:6379/0')
            redis_client.flushdb()

            with session.get(f'http://127.0.0.1:8080/{key}') as response:
                pass

            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))
            self.assertEqual(len(response.history), 3)

    def test_key_that_exists_x_forwarded_proto_respected(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        headers = {
            'x-forwarded-proto': 'https',
        }
        # We don't have a SSL server listening, so we expect an SSL error
        with self.assertRaises(requests.exceptions.SSLError):
            with requests.Session() as session:
                session.get(f'http://127.0.0.1:8080/{key}', headers=headers).__enter__()

    def test_key_that_exists_me_response_500_is_500(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso(me_response_code=500)
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}') as response:
            self.assertEqual(response.content, b'')
            self.assertEqual(response.status_code, 500)

    def test_key_that_exists_no_sso_started_returns_500(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with requests.Session() as session:

            with session.get(f'http://127.0.0.1:8080/{key}') as response_1:
                self.assertEqual(response_1.content, content)

            stop_sso()

            with session.get(f'http://127.0.0.1:8080/{key}') as response_2:
                self.assertIn(b'500 Internal Server Error', response_2.content)
                self.assertNotIn(content, response_2.content)
                self.assertEqual(response_2.status_code, 500)

    def test_key_that_exists_bad_code_perms_returns_403(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso(code_returned='not-the-code')
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}') as response:
            self.assertEqual(response.content, b'')
            self.assertEqual(response.status_code, 403)

    def test_key_that_exists_bad_secret_returns_403(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso(client_secret='not-the-secret')
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}') as response:
            self.assertEqual(response.content, b'')
            self.assertEqual(response.status_code, 403)

    def test_key_that_exists_bad_token_perms_redirects_again_to_success(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso(
            tokens_returned=['not-the-token', 'the-token'],
        )
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}') as response:
            self.assertEqual(response.content, content)
            self.assertEqual(len(response.history), 6)

    def test_key_that_exists_soo_token_returns_500_returns_500(self):
        # Make sure we don't get into infinite redirect

        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso(tokens_returned=())
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}') as response:
            self.assertEqual(response.content, b'')
            self.assertEqual(response.status_code, 500)

    def test_key_that_exists_not_logged_in_shows_login(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso(is_logged_in=False)
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}') as response:
            self.assertEqual(response.content, b'The login page')

    def test_multiple_concurrent_requests(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key_1 = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        key_2 = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content_1 = str(uuid.uuid4()).encode() * 1000000
        content_2 = str(uuid.uuid4()).encode() * 1000000

        put_object(key_1, content_1)
        put_object(key_2, content_2)

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key_1}', stream=True) as response_1, \
                session.get(f'http://127.0.0.1:8080/{key_2}', stream=True) as response_2:

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

    def test_key_that_exists_during_shutdown_completes(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        process = wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        chunks = []

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}', stream=True) as response:

            self.assertEqual(response.headers['content-length'], str(len(content)))
            process.terminate()

            for chunk in response.iter_content(chunk_size=16384):
                chunks.append(chunk)
                time.sleep(0.02)

        self.assertEqual(b''.join(chunks), content)

    def test_key_that_exists_after_multiple_sigterm_completes(self):
        # PaaS can apparently send multiple sigterms
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        process = wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        chunks = []

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}', stream=True) as response:

            self.assertEqual(response.headers['content-length'], str(len(content)))
            process.terminate()
            time.sleep(0.1)
            process.terminate()

            for chunk in response.iter_content(chunk_size=16384):
                chunks.append(chunk)
                time.sleep(0.02)

        self.assertEqual(b''.join(chunks), content)

    def test_key_that_exists_during_shutdown_completes_but_new_connection_rejected(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        process = wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        chunks = []

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}', stream=True) as response:
            self.assertEqual(response.headers['content-length'], str(len(content)))

            process.terminate()

            with self.assertRaises(requests.exceptions.ConnectionError):
                session.get(f'http://127.0.0.1:8080/{key}', stream=True)

            for chunk in response.iter_content(chunk_size=16384):
                chunks.append(chunk)
                time.sleep(0.02)

        self.assertEqual(b''.join(chunks), content)

    def test_key_that_exists_during_shutdown_completes_but_request_on_old_conn(self):
        # Check that connections that were open before the SIGTERM still work
        # after. Unsure if this is desired on PaaS, so this is more of
        # documenting current behaviour
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        process = wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 10000
        put_object(key, content)

        chunks = []

        with requests.Session() as session:
            # Ensure we have two connections
            with \
                    session.get(f'http://127.0.0.1:8080/{key}', stream=True) as resp_2, \
                    session.get(f'http://127.0.0.1:8080/{key}', stream=True) as resp_3:

                for chunk in resp_2.iter_content(chunk_size=16384):
                    pass

                for chunk in resp_3.iter_content(chunk_size=16384):
                    pass

            with session.get(f'http://127.0.0.1:8080/{key}', stream=True) as resp_4:

                process.terminate()

                # No exception raised since the connection is already open
                with session.get(f'http://127.0.0.1:8080/{key}'):
                    pass

                for chunk in resp_4.iter_content(chunk_size=16384):
                    time.sleep(0.02)
                    chunks.append(chunk)

        self.assertEqual(b''.join(chunks), content)

    def test_range_request_from_start(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        headers = {'range': 'bytes=0-'}
        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}', headers=headers) as response:
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-length'], str(len(content)))

    def test_range_request_after_start(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())
        content = str(uuid.uuid4()).encode() * 100000
        put_object(key, content)

        headers = {'range': 'bytes=1-'}
        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}', headers=headers) as response:
            self.assertEqual(response.content, content[1:])
            self.assertEqual(response.headers['content-length'], str(len(content) - 1))

    def test_bad_aws_credentials(self):
        wait_until_started, stop_application = create_application(
            8080, aws_access_key_id='not-exist')
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}') as response:
            self.assertEqual(response.status_code, 500)

    def test_direct_redirection_endpoint_with_state_code_443(self):
        wait_until_started, stop_application = create_application(
            8080, aws_access_key_id='not-exist')
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        params = {
            'state': 'the-state',
            'code': 'the-code',
        }
        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/__redirect_from_sso', params=params) as resp:
            self.assertEqual(resp.status_code, 403)

    def test_direct_redirection_endpoint_with_code_no_state_443(self):
        wait_until_started, stop_application = create_application(
            8080, aws_access_key_id='not-exist')
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        params = {
            'code': 'the-code',
        }
        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/__redirect_from_sso', params=params) as resp:
            self.assertEqual(resp.status_code, 403)

    def test_direct_redirection_endpoint_no_state_no_code_443(self):
        wait_until_started, stop_application = create_application(
            8080, aws_access_key_id='not-exist')
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/__redirect_from_sso') as resp:
            self.assertEqual(resp.status_code, 403)

    def test_key_that_does_not_exist(self):
        wait_until_started, stop_application = create_application(8080)
        self.addCleanup(stop_application)
        wait_until_started()
        wait_until_sso_started, stop_sso = create_sso()
        self.addCleanup(stop_sso)
        wait_until_sso_started()

        key = str(uuid.uuid4()) + '/' + str(uuid.uuid4())

        with \
                requests.Session() as session, \
                session.get(f'http://127.0.0.1:8080/{key}') as response:
            self.assertEqual(response.status_code, 404)

    def test_healthcheck(self):
        healthcheck_key = str(uuid.uuid4())

        wait_until_started, stop_application = create_application(
            8080, healthcheck_key=healthcheck_key)
        self.addCleanup(stop_application)
        wait_until_started()

        with requests.get(f'http://127.0.0.1:8080/{healthcheck_key}') as resp_1:
            self.assertEqual(resp_1.status_code, 404)

        put_object(healthcheck_key, b'OK')

        with requests.get(f'http://127.0.0.1:8080/{healthcheck_key}') as resp_1:
            self.assertEqual(resp_1.status_code, 200)
            self.assertEqual(resp_1.content, b'OK')


def create_application(
        port, max_attempts=100,
        aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
        healthcheck_key='heathcheck.txt',
):
    process = subprocess.Popen(
        ['python3', 'app.py', ],
        stderr=subprocess.PIPE,  # Silence logs
        stdout=subprocess.PIPE,
        env={
            **os.environ,
            'PORT': str(port),
            'VCAP_SERVICES': json.dumps({
                'redis': [{'credentials': {'uri': 'redis://127.0.0.1:6379/0'}}]}),
            'SSO_URL': 'http://127.0.0.1:8081/',
            'SSO_CLIENT_ID': 'the-client-id',
            'SSO_CLIENT_SECRET': 'the-client-secret',
            'AWS_S3_REGION': 'us-east-1',
            'AWS_ACCESS_KEY_ID': aws_access_key_id,
            'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'AWS_S3_ENDPOINT': 'http://127.0.0.1:9000/my-bucket/',
            'AWS_S3_HEALTHCHECK_KEY': healthcheck_key,
        }
    )

    def wait_until_started():
        for i in range(0, max_attempts):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    break
            except (OSError, ConnectionRefusedError):
                if i == max_attempts - 1:
                    raise
                time.sleep(0.01)
        return process

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


def create_sso(
        max_attempts=200, is_logged_in=True,
        client_id='the-client-id',
        client_secret='the-client-secret',
        tokens_returned=('the-token',), token_expected='the-token',
        code_returned='the-code', code_expected='the-code',
        me_response_code=200,
):
    # Mock SSO in a different process to not block tests

    def start():
        os.environ['FLASK_ENV'] = 'development'  # Avoid warning about this not a prod server
        app = Flask('app')
        app.add_url_rule('/api/v1/user/me/', view_func=handle_me, methods=['GET'])
        app.add_url_rule('/o/authorize/', view_func=handle_authorize, methods=['GET'])
        app.add_url_rule('/o/token/', view_func=handle_token, methods=['POST'])

        def _stop(_, __):
            sys.exit()

        signal.signal(signal.SIGTERM, _stop)

        try:
            app.run(host='', port=8081, debug=False)
        except SystemExit:
            # app.run doesn't seem to have a good way of killing the server,
            # and want to exit cleanly for code coverage
            pass

    def wait_until_connected():
        for i in range(0, max_attempts):
            try:
                with socket.create_connection(('127.0.0.1', 8081), timeout=0.1):
                    break
            except (OSError, ConnectionRefusedError):
                if i == max_attempts - 1:
                    raise
                time.sleep(0.01)

    def stop():
        process.terminate()
        process.join()

    def handle_me():
        correct = request.headers.get('authorization', '') == f'Bearer {token_expected}'
        me = {
            'email': 'test@test.com',
            'first_name': 'Peter',
            'last_name': 'Piper',
            'user_id': '7f93c2c7-bc32-43f3-87dc-40d0b8fb2cd2',
        }
        return \
            Response(json.dumps(me), status=me_response_code) if correct else \
            Response(status=403)

    def handle_authorize():
        args = request.args
        redirect_url = f'{args["redirect_uri"]}?state={args["state"]}&code={code_returned}'
        return \
            Response(status=302, headers={'location': redirect_url}) if is_logged_in else \
            Response(b'The login page', status=200)

    token_iter = iter(tokens_returned)

    def next_token():
        nonlocal token_iter
        try:
            return next(token_iter)
        except StopIteration:
            iter(tokens_returned)
            return next(token_iter)

    def handle_token():
        correct = \
            request.form['code'] == code_expected and \
            request.form['client_id'] == client_id and \
            request.form['client_secret'] == client_secret and \
            request.form['grant_type'] == 'authorization_code'
        return \
            Response(json.dumps({'access_token': next_token()}), status=200) if correct else \
            Response(status=403)

    process = Process(target=start)
    process.start()

    return wait_until_connected, stop
