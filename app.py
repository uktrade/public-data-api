from gevent import (
    monkey,
)
monkey.patch_all()
import gevent

import hashlib
import logging
import os
import signal
import sys
import urllib.parse

from flask import (
    Flask,
    Response,
    request,
)
from gevent.pywsgi import (
    WSGIServer,
)
import urllib3

from app_aws import (
    aws_sigv4_headers,
    aws_select_post_body,
    aws_select_parse_result,
)


def proxy_app(
        logger,
        port,
        aws_access_key_id, aws_secret_access_key, endpoint_url, region_name,
):

    parsed_endpoint = urllib.parse.urlsplit(endpoint_url)
    PoolClass = \
        urllib3.HTTPConnectionPool if parsed_endpoint.scheme == 'http' else \
        urllib3.HTTPSConnectionPool
    http = PoolClass(parsed_endpoint.hostname, port=parsed_endpoint.port, maxsize=1000)

    proxied_request_headers = ['range', ]
    proxied_response_codes = [200, 206, 404, ]
    proxied_response_headers = [
        'accept-ranges', 'content-length', 'date', 'etag', 'last-modified', 'content-range',
    ]

    def start():
        server.serve_forever()

    def stop():
        server.stop()

    def proxy(dataset_id, version):
        logger.debug('Attempt to proxy: %s %s %s', request, dataset_id, version)

        try:
            _format = request.args['format']
        except KeyError:
            return 'The query string must have a "format" term', 400

        if _format != 'json':
            return 'The query string "format" term must equal "json"', 400

        url = f'{endpoint_url}{dataset_id}/v{version}/data.json'
        parsed_url = urllib.parse.urlsplit(url)
        method, body, params, parse_response = \
            (
                'POST',
                aws_select_post_body(request.args['query_sql']),
                (('select', ''), ('select-type', '2')),
                aws_select_parse_result,
            ) if 'query_sql' in request.args else \
            (
                'GET',
                b'',
                {},
                lambda x, _: x,
            )

        body_hash = hashlib.sha256(body).hexdigest()
        pre_auth_headers = tuple((
            (key, request.headers[key])
            for key in proxied_request_headers if key in request.headers
        ))
        encoded_params = urllib.parse.urlencode(params)
        request_headers = aws_sigv4_headers(
            aws_access_key_id, aws_secret_access_key, region_name,
            pre_auth_headers, 's3', parsed_url.netloc, method, parsed_url.path, params, body_hash,
        )
        response = http.request(method, f'{url}?{encoded_params}', headers=dict(
            request_headers), body=body, preload_content=False)

        response_headers_no_content_type = tuple((
            (key, response.headers[key])
            for key in proxied_response_headers if key in response.headers
        ))
        response_headers = response_headers_no_content_type + \
            (('content-type', 'application/json'),)
        allow_proxy = response.status in proxied_response_codes

        logger.debug('Response: %s', response)
        logger.debug('Allowing proxy: %s', allow_proxy)

        def body_empty():
            # Ensure this is a generator
            while False:
                yield

            for _ in response.stream(65536, decode_content=False):
                pass

        downstream_response = \
            Response(parse_response(response.stream(65536, decode_content=False), 65536),
                     status=response.status, headers=response_headers) if allow_proxy else \
            Response(body_empty(), status=500)
        downstream_response.call_on_close(response.release_conn)
        return downstream_response

    app = Flask('app')

    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/v<string:version>/data', view_func=proxy)
    server = WSGIServer(('0.0.0.0', port), app)

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
        os.environ['AWS_ACCESS_KEY_ID'],
        os.environ['AWS_SECRET_ACCESS_KEY'],
        os.environ['AWS_S3_ENDPOINT'],
        os.environ['AWS_S3_REGION'],
    )

    gevent.signal_handler(signal.SIGTERM, stop)
    start()
    gevent.get_hub().join()


if __name__ == '__main__':
    main()
