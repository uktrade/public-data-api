from gevent import (
    monkey,
)
monkey.patch_all()
import gevent

from functools import (
    wraps,
)
import hashlib
import logging
import os
import signal
import sys
import urllib.parse

from flask import (
    Flask,
    Response,
    redirect,
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
    aws_list_folders,
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

    def signed_s3_request(method, s3_key, pre_auth_headers, params, body):
        path = f'{parsed_endpoint.path}{s3_key}'
        body_hash = hashlib.sha256(body).hexdigest()
        request_headers = aws_sigv4_headers(
            aws_access_key_id, aws_secret_access_key, region_name,
            pre_auth_headers, 's3', parsed_endpoint.netloc, method, path, params, body_hash,
        )
        encoded_params = urllib.parse.urlencode(params)
        url = f'{parsed_endpoint.scheme}://{parsed_endpoint.netloc}{path}?{encoded_params}'
        return http.request(method, url,
                            headers=dict(request_headers), body=body, preload_content=False)

    def validate_format(handler):
        @wraps(handler)
        def handler_with_validation(*args, **kwargs):
            try:
                _format = request.args['format']
            except KeyError:
                return 'The query string must have a "format" term', 400

            if _format != 'json':
                return 'The query string "format" term must equal "json"', 400

            return handler(*args, **kwargs)
        return handler_with_validation

    @validate_format
    def proxy(dataset_id, version):
        logger.debug('Attempt to proxy: %s %s %s', request, dataset_id, version)

        s3_key = f'{dataset_id}/v{version}/data.json'
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
                (),
                lambda x, _: x,
            )

        pre_auth_headers = tuple((
            (key, request.headers[key])
            for key in proxied_request_headers if key in request.headers
        ))
        response = signed_s3_request(method, s3_key, pre_auth_headers, params, body)

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

    @validate_format
    def redirect_to_latest(dataset_id):
        def semver_key(path):
            v_major_str, minor_str, patch_str = path.split('.')
            return (int(v_major_str[1:]), int(minor_str), int(patch_str))

        folders = aws_list_folders(signed_s3_request, f'{dataset_id}/')
        version = max(folders, default=None, key=semver_key)

        if version is None:
            return 'Dataset not found', 404

        # It doesn't look like it's possible to return a redirect with the query string that has
        # the _exact_ bytes that were received by the server in all cases. If a client sends
        # non-URL-encoded UTF-8 in the query string, the below results (via code in Werkzeug) in
        # returning a redirect to a URL with the equivalent URL-encoded string.
        query_string = ((b'?' + request.query_string)
                        if request.query_string else b'').decode('utf-8')

        return redirect(
            f'/v1/datasets/{dataset_id}/versions/{version}/data{query_string}', code=302)

    app = Flask('app')
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/v<string:version>/data', view_func=proxy)
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/latest/data', view_func=redirect_to_latest)
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
