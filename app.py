from gevent import (
    monkey
)
monkey.patch_all()

from datetime import (
    datetime,
)
from functools import (
    wraps,
)
import hashlib
import hmac
import json
import os
import secrets
import signal
import urllib.parse

from flask import (
    Flask,
    Response,
    request,
    session,
)
from gevent.pywsgi import (
    WSGIServer,
)
import requests


def proxy_app(
        sso_url, sso_client_id, sso_client_secret,
        endpoint_url, aws_access_key_id, aws_secret_access_key, region_name, bucket, secret_key,
        port,
):

    proxied_request_headers = ['range', ]
    proxied_response_codes = [200, 206, 404, ]
    proxied_response_headers = [
        'accept-ranges', 'content-length', 'content-type', 'date', 'etag', 'last-modified',
        'content-range',
    ]

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
        session_state_prefix_key = 'sso_state_'
        session_token_key = 'sso_access_token'

        @wraps(f)
        def _authenticate_by_sso(*args, **kwargs):

            def get_callback_uri():
                return request.url_root + redirect_from_sso_path[1:]

            def redirect_to_sso():
                callback_uri = urllib.parse.quote(get_callback_uri(), safe='')

                state = secrets.token_hex(32)
                final_uri = request.url
                session.clear()
                session[f'{session_state_prefix_key}{state}'] = final_uri

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
                    final_uri = session[f'{session_state_prefix_key}{state}']
                except KeyError:
                    return Response(b'', 403)

                with requests.post(f'{sso_url}{token_path}',
                                   data={
                                       'grant_type': grant_type,
                                       'code': code,
                                       'client_id': sso_client_id,
                                       'client_secret': sso_client_secret,
                                       'redirect_uri': get_callback_uri(),
                                   },
                                   ) as response:
                    content = response.content
                if response.status_code == 200:
                    token = json.loads(content)['access_token']
                    session.clear()
                    session[session_token_key] = token
                    return Response(status=302, headers={'location': final_uri})

                if response.status_code == 403:
                    return Response(b'', 403)

                return Response(b'', 500)

            def get_token_code(token):
                with requests.get(f'{sso_url}{me_path}', headers={
                        'authorization': f'Bearer {token}'
                }) as response:
                    return response.status_code

            if request.path == redirect_from_sso_path:
                return redirect_to_final()

            token = session.get(session_token_key, None)
            if token is None:
                return redirect_to_sso()

            token_code = get_token_code(token)
            if token_code == 403:
                return redirect_to_sso()

            if token_code == 200:
                return f(*args, **kwargs)

            return Response(b'', 500)

        return _authenticate_by_sso

    @authenticate_by_sso
    def proxy(path):
        url = endpoint_url + bucket + '/' + path
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

        def body_upstream():
            try:
                for chunk in response.iter_content(16384):
                    yield chunk
            finally:
                response.close()

        def body_empty():
            try:
                for _ in response.iter_content(16384):
                    pass
            finally:
                response.close()

        return \
            Response(body_upstream(),
                     status=response.status_code, headers=response_headers) if allow_proxy else \
            Response(body_empty(), status=500)

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

    app = Flask('app')
    app.add_url_rule('/<path:path>', view_func=proxy)
    app.config.from_mapping({
        'SECRET_KEY': secret_key,
    })
    server = WSGIServer(('0.0.0.0', port), app)

    return start, stop


def main():
    start, stop = proxy_app(
        os.environ['SSO_URL'],
        os.environ['SSO_CLIENT_ID'],
        os.environ['SSO_CLIENT_SECRET'],
        os.environ['AWS_S3_ENDPOINT'],
        os.environ['AWS_ACCESS_KEY_ID'],
        os.environ['AWS_SECRET_ACCESS_KEY'],
        os.environ['AWS_DEFAULT_REGION'],
        os.environ['AWS_S3_BUCKET'],
        os.environ['SECRET_KEY'],
        int(os.environ['PORT']),
    )

    def server_stop(_, __):
        stop()

    signal.signal(signal.SIGTERM, server_stop)

    start()


if __name__ == '__main__':
    main()
