import json
import ecs_logging
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

from elasticapm.contrib.flask import ElasticAPM
from flask import (
    Flask,
    Response,
    redirect,
    request,
)
from gevent.pywsgi import (
    WSGIServer,
)
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
import urllib3
from werkzeug.middleware.proxy_fix import (
    ProxyFix,
)

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

    def _proxy(dataset_id, major, minor, patch, query_s3_select, headers):
        s3_key = f'{dataset_id}/v{major}.{minor}.{patch}/data.json'
        method, body, params, parse_response = \
            (
                'POST',
                aws_select_post_body(query_s3_select),
                (('select', ''), ('select-type', '2')),
                aws_select_parse_result,
            ) if query_s3_select is not None else \
            (
                'GET',
                b'',
                (),
                lambda x, _: x,
            )

        pre_auth_headers = tuple((
            (key, headers[key])
            for key in proxied_request_headers if key in headers
        ))
        response = signed_s3_request(method, s3_key, pre_auth_headers, params, body)

        logger.debug('Response: %s', response)

        return parse_response(response.stream(65536, decode_content=False), 65536), response

    @validate_format
    def proxy(dataset_id, major, minor, patch):
        logger.debug('Attempt to proxy: %s %s %s %s %s', request, dataset_id, major, minor, patch)

        body_generator, response = _proxy(
            dataset_id, major, minor, patch, request.args.get('query-s3-select'), request.headers)

        allow_proxy = response.status in proxied_response_codes

        logger.debug('Allowing proxy: %s', allow_proxy)

        response_headers_no_content_type = tuple((
            (key, response.headers[key])
            for key in proxied_response_headers if key in response.headers
        ))
        response_headers = response_headers_no_content_type + \
            (('content-type', 'application/json'),)

        if not allow_proxy:
            # Make sure we fetch all response bytes, so the connection can be re-used.
            # There are not likely to be many, since it would just be an error message
            # from S3 at most
            for _ in response.stream(65536, decode_content=False):
                pass
            raise Exception(f'Unexpected code from S3: {response.status}')

        downstream_response = Response(
            body_generator, status=response.status, headers=response_headers,
        )
        downstream_response.call_on_close(response.release_conn)
        return downstream_response

    @validate_format
    def redirect_to_major(dataset_id, major):
        requested_major_str = str(major)

        def predicate(path):
            v_major_str, _, _ = path.split('.')
            return v_major_str[1:] == requested_major_str
        return redirect_to_latest_matching(dataset_id, predicate)

    @validate_format
    def redirect_to_minor(dataset_id, major, minor):
        requested_major_str = str(major)
        requested_minor_str = str(minor)

        def predicate(path):
            v_major_str, minor_str, _ = path.split('.')
            return v_major_str[1:] == requested_major_str and minor_str == requested_minor_str
        return redirect_to_latest_matching(dataset_id, predicate)

    @validate_format
    def redirect_to_latest(dataset_id):
        return redirect_to_latest_matching(dataset_id, lambda _: True)

    def redirect_to_latest_matching(dataset_id, predicate):
        def semver_key(path):
            v_major_str, minor_str, patch_str = path.split('.')
            return (int(v_major_str[1:]), int(minor_str), int(patch_str))

        folders = aws_list_folders(signed_s3_request, f'{dataset_id}/')
        matching_folders = filter(predicate, folders)
        version = max(matching_folders, default=None, key=semver_key)

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

    def healthcheck():
        """
        Healthcheck checks S3 bucket, `healthcheck` as dataset_id and v0.0.1 as version
        containing json string {'status': 'OK'}
        """
        body_generator, s3_response = _proxy('healthcheck', '0', '0', '1', None, request.headers)
        body_bytes = b''.join(chunk for chunk in body_generator)
        body_json = json.loads(body_bytes.decode('utf-8'))

        if s3_response.status == 200 and body_json.get('status') == 'OK':
            pingdom_xml = """<?xml version="1.0" encoding="UTF-8"?>
            <pingdom_http_custom_check>
                <status>OK</status>
            </pingdom_http_custom_check>\n"""

            response = Response(pingdom_xml, status=200, mimetype='application/xml')
            response.headers['Content-Type'] = 'text/xml'
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            return response

        return Response(status=503)

    app = Flask('app')
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

    apm = ElasticAPM()
    apm.init_app(
        app,
        service_name='public-data-api',
        secret_token=os.environ['APM_SECRET_TOKEN'],
        server_url=os.environ['APM_SERVER_URL'],
        environment=os.environ['ENVIRONMENT'],
        server_timeout=os.environ.get('APM_SERVER_TIMEOUT', None),
    )

    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/'
        'v<int:major>.<int:minor>.<int:patch>/data', view_func=proxy
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/'
        'v<int:major>/data', view_func=redirect_to_major
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/'
        'v<int:major>.<int:minor>/data', view_func=redirect_to_minor
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/'
        'latest/data', view_func=redirect_to_latest
    )
    app.add_url_rule(
        '/healthcheck', 'healthcheck', view_func=healthcheck
    )
    server = WSGIServer(('0.0.0.0', port), app, log=app.logger)

    return start, stop


def main():

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ecs_logging.StdlibFormatter())
    logger.addHandler(handler)

    start, stop = proxy_app(
        logger,
        int(os.environ['PORT']),
        os.environ['AWS_ACCESS_KEY_ID'],
        os.environ['AWS_SECRET_ACCESS_KEY'],
        os.environ['AWS_S3_ENDPOINT'],
        os.environ['AWS_S3_REGION'],
    )

    sentry_sdk.init(
        dsn=os.environ['SENTRY_DSN'],
        integrations=[FlaskIntegration()]
    )

    gevent.signal_handler(signal.SIGTERM, stop)
    start()
    gevent.get_hub().join()


if __name__ == '__main__':
    main()
