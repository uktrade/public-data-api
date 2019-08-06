from gevent import (
    monkey
)
monkey.patch_all()

from datetime import (
    datetime,
)
import hashlib
import hmac
import os
import signal
import urllib.parse

from flask import (
    Flask,
    Response,
    request,
)
from gevent.pywsgi import (
    WSGIServer,
)
import requests


def proxy_app(endpoint_url, aws_access_key_id, aws_secret_access_key, region_name, bucket, port):

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

    def proxy(path):

        url = endpoint_url + bucket + '/' + path
        body_hash = hashlib.sha256(b'').hexdigest()
        pre_auth_headers = tuple((
            (key, request.headers[key])
            for key in proxied_request_headers if key in request.headers
        ))
        parsed_url = urllib.parse.urlsplit(url)
        request_headers = aws_sigv4_headers(
            aws_access_key_id, aws_secret_access_key, pre_auth_headers,
            's3', region_name, parsed_url.netloc, 'GET', parsed_url.path, (), body_hash,
        )
        response = requests.get(url, headers=dict(request_headers), stream=True)

        response_headers = tuple((
            (key, response.headers[key])
            for key in proxied_response_headers if key in response.headers
        ))
        allow_proxy = response.status_code in proxied_response_codes

        return \
            Response(response.iter_content(16384),
                     status=response.status_code, headers=response_headers) if allow_proxy else \
            Response(b'', status=500)

    bucket = bucket
    app = Flask('app')
    app.add_url_rule('/<path:path>', view_func=proxy)
    server = WSGIServer(('', port), app)

    return start, stop


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


def main():
    start, stop = proxy_app(
        os.environ['AWS_S3_ENDPOINT'],
        os.environ['AWS_ACCESS_KEY_ID'],
        os.environ['AWS_SECRET_ACCESS_KEY'],
        os.environ['AWS_DEFAULT_REGION'],
        os.environ['AWS_S3_BUCKET'],
        int(os.environ['PORT']),
    )

    start()

    def server_stop(_, __):
        stop()

    signal.signal(signal.SIGTERM, server_stop)


if __name__ == '__main__':
    main()
