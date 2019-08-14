from gevent import (
    monkey,
)
monkey.patch_all()
import gevent

from datetime import (
    datetime,
)
from functools import (
    wraps,
)
import hashlib
import hmac
import logging
import json
import os
import secrets
import signal
import sys
import urllib.parse

from flask import (
    Flask,
    Response,
    request,
)
from gevent.pywsgi import (
    WSGIHandler,
    WSGIServer,
)
import redis
import requests


def proxy_app(
        logger,
        port, redis_url,
        sso_url, sso_client_id, sso_client_secret,
        aws_access_key_id, aws_secret_access_key, endpoint_url, region_name, healthcheck_key,
):

    proxied_request_headers = ['range', ]
    proxied_response_codes = [200, 206, 404, ]
    proxied_response_headers = [
        'accept-ranges', 'content-length', 'content-type', 'date', 'etag', 'last-modified',
        'content-range',
    ]
    redis_prefix = 's3proxy'
    redis_client = redis.from_url(redis_url)

    def start():
        server.serve_forever()

    def stop():
        server.stop()

    def authenticate_by_sso(f):
        auth_path = 'o/authorize/'
        token_path = 'o/token/'
        me_path = 'api/v1/user/me/'
        grant_type = 'authorization_code'
        scope = 'read write'
        response_type = 'code'

        redirect_from_sso_path = '/__redirect_from_sso'

        session_cookie_name = 'assets_session_id'
        session_state_key_prefix = 'sso_state'
        session_token_key = 'sso_token'

        cookie_max_age = 60 * 60 * 9
        redis_max_age_session = 60 * 60 * 10
        redis_max_age_state = 60

        @wraps(f)
        def _authenticate_by_sso(*args, **kwargs):

            if request.path == f'/{healthcheck_key}':
                logger.debug('Allowing healthcheck')
                return f(*args, **kwargs)

            logger.debug('Authenticating %s', request)

            def get_session_value(key):
                session_id = request.cookies[session_cookie_name]
                return redis_get(f'{session_cookie_name}__{session_id}__{key}')

            # In our case all session values are set exactly when we want a new session cookie
            # (done to mitigate session fixation attacks)
            def with_new_session_cookie(response, session_values):
                session_id = secrets.token_urlsafe(64)
                response.set_cookie(
                    session_cookie_name, session_id,
                    httponly=True,
                    secure=request.headers.get('x-forwarded-proto', 'http') == 'https',
                    max_age=cookie_max_age,
                    expires=datetime.utcnow().timestamp() + cookie_max_age,
                )
                for key, value in session_values.items():
                    redis_set(
                        f'{session_cookie_name}__{session_id}__{key}', value,
                        redis_max_age_session)

                return response

            def get_callback_uri():
                scheme = request.headers.get('x-forwarded-proto', 'http')
                return f'{scheme}://{request.host}{redirect_from_sso_path}'

            def get_request_url_with_scheme():
                scheme = request.headers.get('x-forwarded-proto', 'http')
                return f'{scheme}://{request.host}{request.environ["REQUEST_LINE_PATH"]}'

            def redirect_to_sso():
                logger.debug('Redirecting to SSO')
                callback_uri = urllib.parse.quote(get_callback_uri(), safe='')
                state = secrets.token_hex(32)
                redis_set(
                    f'{session_state_key_prefix}__{state}', get_request_url_with_scheme(),
                    redis_max_age_state)

                redirect_to = f'{sso_url}{auth_path}?' \
                    f'scope={scope}&state={state}&' \
                    f'redirect_uri={callback_uri}&' \
                    f'response_type={response_type}&' \
                    f'client_id={sso_client_id}'

                return Response(status=302, headers={'location': redirect_to})

            def redirect_to_final():
                try:
                    code = request.args['code']
                    state = request.args['state']
                    final_uri = redis_get(f'{session_state_key_prefix}__{state}')
                except KeyError:
                    logger.exception('Unable to redirect to final')
                    return Response(b'', 403)

                logger.debug('Attempting to redirect to final: %s', final_uri)

                data = {
                    'grant_type': grant_type,
                    'code': code,
                    'client_id': sso_client_id,
                    'client_secret': sso_client_secret,
                    'redirect_uri': get_callback_uri(),
                }
                with requests.post(f'{sso_url}{token_path}', data=data) as response:
                    content = response.content

                if response.status_code in [401, 403]:
                    logger.debug('token_path response is %s', response.status_code)
                    return Response(b'', response.status_code)

                if response.status_code != 200:
                    logger.debug('token_path error')
                    return Response(b'', 500)

                response = with_new_session_cookie(
                    Response(status=302, headers={'location': final_uri}),
                    {session_token_key: json.loads(content)['access_token']}
                )
                response.autocorrect_location_header = False
                return response

            def get_token_code(token):
                with requests.get(f'{sso_url}{me_path}', headers={
                        'authorization': f'Bearer {token}'
                }) as response:
                    return response.status_code

            if request.path == redirect_from_sso_path:
                return redirect_to_final()

            try:
                token = get_session_value(session_token_key)
            except KeyError:
                return redirect_to_sso()

            token_code = get_token_code(token)
            if token_code in [401, 403]:
                logger.debug('token_code response is %s', token_code)
                return redirect_to_sso()

            if token_code != 200:
                return Response(b'', 500)

            return f(*args, **kwargs)

        return _authenticate_by_sso

    @authenticate_by_sso
    def proxy(path):
        logger.debug('Attempt to proxy: %s', request)

        url = endpoint_url + path
        body_hash = hashlib.sha256(b'').hexdigest()
        pre_auth_headers = tuple((
            (key, request.headers[key])
            for key in proxied_request_headers if key in request.headers
        ))
        parsed_url = urllib.parse.urlsplit(url)
        request_headers = aws_sigv4_headers(
            pre_auth_headers, 's3', parsed_url.netloc, 'GET', parsed_url.path, (), body_hash,
        )
        response = requests.get(url, headers=dict(request_headers), stream=True)

        response_headers = tuple((
            (key, response.headers[key])
            for key in proxied_response_headers if key in response.headers
        ))
        allow_proxy = response.status_code in proxied_response_codes

        logger.debug('Response: %s', response)
        logger.debug('Allowing proxy: %s', allow_proxy)

        def body_upstream():
            try:
                for chunk in response.iter_content(16384):
                    yield chunk
            finally:
                logger.debug('Closing proxied response')
                response.close()

        def body_empty():
            # Ensure this is a generator
            while False:
                yield

            try:
                for _ in response.iter_content(16384):
                    pass
            finally:
                logger.debug('Closing empty response')
                response.close()

        return \
            Response(body_upstream(),
                     status=response.status_code, headers=response_headers) if allow_proxy else \
            Response(body_empty(), status=500)

    def redis_get(key):
        value_bytes = redis_client.get(f'{redis_prefix}__{key}')
        if value_bytes is None:
            raise KeyError(key)
        return value_bytes.decode()

    def redis_set(key, value, ex):
        redis_client.set(f'{redis_prefix}__{key}', value.encode(), ex=ex)

    def aws_sigv4_headers(pre_auth_headers, service, host, method, path, params, body_hash):
        algorithm = 'AWS4-HMAC-SHA256'

        now = datetime.utcnow()
        amzdate = now.strftime('%Y%m%dT%H%M%SZ')
        datestamp = now.strftime('%Y%m%d')
        credential_scope = f'{datestamp}/{region_name}/{service}/aws4_request'

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

            date_key = sign(('AWS4' + aws_secret_access_key).encode('ascii'), datestamp)
            region_key = sign(date_key, region_name)
            service_key = sign(region_key, service)
            request_key = sign(service_key, 'aws4_request')
            return sign(request_key, string_to_sign).hex()

        return (
            (b'authorization', (
                f'{algorithm} Credential={aws_access_key_id}/{credential_scope}, '
                f'SignedHeaders={signed_headers}, Signature=' + signature()).encode('ascii')
             ),
            (b'x-amz-date', amzdate.encode('ascii')),
            (b'x-amz-content-sha256', body_hash.encode('ascii')),
        ) + pre_auth_headers

    class RequestLinePathHandler(WSGIHandler):
        # The default WSGIHandler does not preseve a trailing question mark
        # from the original request-line path sent by the client
        def get_environ(self):
            return {
                **super().get_environ(),
                'REQUEST_LINE_PATH': self.path,
            }

    app = Flask('app')
    app.add_url_rule('/<path:path>', view_func=proxy)
    server = WSGIServer(('0.0.0.0', port), app, handler_class=RequestLinePathHandler)

    return start, stop


def main():
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.DEBUG)
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(stdout_handler)

    start, stop = proxy_app(
        logger,
        int(os.environ['PORT']),
        json.loads(os.environ['VCAP_SERVICES'])['redis'][0]['credentials']['uri'],
        os.environ['SSO_URL'],
        os.environ['SSO_CLIENT_ID'],
        os.environ['SSO_CLIENT_SECRET'],
        os.environ['AWS_ACCESS_KEY_ID'],
        os.environ['AWS_SECRET_ACCESS_KEY'],
        os.environ['AWS_S3_ENDPOINT'],
        os.environ['AWS_S3_REGION'],
        os.environ['AWS_S3_HEALTHCHECK_KEY'],
    )

    gevent.signal(signal.SIGTERM, stop)
    start()
    gevent.get_hub().join()


if __name__ == '__main__':
    main()
