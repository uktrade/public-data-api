import json
import re
from collections import namedtuple
from itertools import chain

import ecs_logging
from gevent import (
    monkey,
)
monkey.patch_all()
import gevent

import datetime
from email.utils import (
    parsedate,
)
from functools import (
    partial,
    wraps,
)
import logging
import os
import signal
import sys
import urllib.parse
import uuid

import requests

from elasticapm.contrib.flask import ElasticAPM
from flask import (
    Flask,
    Response,
    abort,
    redirect,
    request,
    url_for,
)
from gevent.pywsgi import (
    WSGIServer,
)
from jinja2 import (
    Environment,
    FileSystemLoader,
)
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
import urllib3
from werkzeug.middleware.proxy_fix import (
    ProxyFix,
)

from app_aws import (
    aws_head,
    aws_s3_request,
    aws_select_post_body_csv,
    aws_select_post_body_json,
    aws_select_convert_records_to_csv,
    aws_select_convert_records_to_json,
    aws_select_parse_result,
    aws_list_folders,
)


RE_VERSION_FORMAT = re.compile(
    r'^(?P<version>v(?P<major>\d+)(?:\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?)?|latest)$')


def proxy_app(
        logger,
        port,
        aws_access_key_id,
        aws_secret_access_key,
        endpoint_url,
        region_name,
        ga_tracking_id,
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

    signed_s3_request = partial(aws_s3_request, parsed_endpoint, http,
                                aws_access_key_id, aws_secret_access_key, region_name)
    html_template_environment = Environment(
        loader=FileSystemLoader('./templates'), autoescape=True)

    def start():
        server.serve_forever()

    def stop():
        server.stop()

    def track_analytics(handler):
        """Decorator to send analytics data to google in the background."""
        @wraps(handler)
        def send(*args, **kwargs):
            if ga_tracking_id:
                gevent.spawn(
                    _send_to_google_analytics,
                    request.remote_addr,
                    request.host_url,
                    request.path,
                    request.headers
                )
            return handler(*args, **kwargs)
        return send

    def validate_and_redirect_version(handler):
        """Reads the version from the URL path, validates that it's either `latest` or a
        (simple) SemVer version.
        If not, 404s.

        If it's `latest`, scrapes S3 for the latest version of the dataset and redirects to it.
            If no key exists, 404s.

        If it's a major or minor version, scrapes S3 for the latest (constrained) version and
        redirects to it.
            If no matching key exists, 404s.

        If it's a patch version, passes directly through to the underlying function.
        """
        @wraps(handler)
        def handler_with_validation(*args, **kwargs):
            match = RE_VERSION_FORMAT.match(request.view_args['version'])
            if not match:
                abort(404)

            version, major, minor, patch = [match.group(
                g) for g in ('version', 'major', 'minor', 'patch')]

            if major and minor and patch:
                return handler(*args, **kwargs)

            if version == 'latest':
                def predicate(_):
                    return True
            elif major and not minor and not patch:
                def predicate(path):
                    v_major_str, _, _ = path.split('.')
                    return v_major_str[1:] == str(major)
            else:
                def predicate(path):
                    v_major_str, minor_str, _ = path.split('.')
                    return v_major_str[1:] == str(major) and minor_str == str(minor)

            def semver_key(path):
                v_major_str, minor_str, patch_str = path.split('.')
                return (int(v_major_str[1:]), int(minor_str), int(patch_str))

            folders = aws_list_folders(signed_s3_request, request.view_args['dataset_id'] + '/')
            matching_folders = filter(predicate, folders)
            latest_matching_version = max(matching_folders, default=None, key=semver_key)

            if latest_matching_version is None:
                return 'Dataset not found', 404

            # It doesn't look like it's possible to return a redirect with the query string that
            # has the _exact_ bytes that were received by the server in all cases. If a client
            # sends non-URL-encoded UTF-8 in the query string, the below results (via code in
            # Werkzeug) in returning a redirect to a URL with the equivalent URL-encoded string.
            query_string = ((b'?' + request.query_string)
                            if request.query_string else b'').decode('utf-8')

            updated_view_args = {**request.view_args, 'version': latest_matching_version}
            return redirect(url_for(request.endpoint, **updated_view_args) + query_string)

        return handler_with_validation

    def validate_format(ensure_formats):
        def validate_format_handler(handler):
            @wraps(handler)
            def handler_with_validation(*args, **kwargs):
                try:
                    _format = request.args['format']
                except KeyError:
                    return 'The query string must have a "format" term', 400

                if _format not in ensure_formats:
                    return f'The query string "format" term must be one of "{ensure_formats}"', 400

                return handler(*args, **kwargs)
            return handler_with_validation
        return validate_format_handler

    def _proxy(s3_key, query_s3_select, aws_select_parse_result_for_query, headers):
        method, body, params, parse_response = \
            (
                'POST',
                query_s3_select,
                (('select', ''), ('select-type', '2')),
                aws_select_parse_result_for_query,
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

    def _generate_downstream_response(body_generator, response, content_type, download_filename):
        allow_proxy = response.status in proxied_response_codes

        logger.debug('Allowing proxy: %s', allow_proxy)

        response_headers_no_content_type = tuple((
            (key, response.headers[key])
            for key in proxied_response_headers if key in response.headers
        ))
        download_headers = (
            ('content-disposition', f'attachment; filename="{download_filename}"'),
        ) if 'download' in request.args else ()
        response_headers = response_headers_no_content_type + \
            (('content-type', content_type),) + download_headers

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

    def _convert_csvw_to_html(dataset_id, version, body_generator):
        csvw = json.loads(b''.join(body_generator))
        table_head_status_headers = [
            (table['id'], aws_head(signed_s3_request, key))
            for table in csvw['tables']
            for key in [f'{dataset_id}/{version}/tables/{table["id"]}/data.csv']
        ]
        table_sizes = {
            table_id: headers['content-length']
            for table_id, (_, headers) in table_head_status_headers
        }
        filter_urls = {table['id']: url_for('filter_rows', dataset_id=dataset_id, version=version, table=table['id']) for table in csvw['tables']}
        return html_template_environment.get_template('metadata.html').render(
            version=version,
            version_published_at=max((
                datetime.datetime(*parsedate(headers['last-modified'])[:6])
                for _, (_, headers) in table_head_status_headers)),
            csvw=csvw,
            filter_urls=filter_urls,
            metadata_download_url=url_for('proxy_metadata', dataset_id=dataset_id, version=version)
            + '?format=csvw&download',
            table_sizes=table_sizes)

    @track_analytics
    @validate_and_redirect_version
    @validate_format(('json',))
    def proxy_data(dataset_id, version):
        logger.debug('Attempt to proxy: %s %s %s', request, dataset_id, version)

        s3_key = f'{dataset_id}/{version}/data.json'
        s3_query = request.args.get('query-s3-select')
        body_generator, response = _proxy(
            s3_key,
            aws_select_post_body_json(s3_query) if s3_query is not None else None,
            partial(aws_select_parse_result,
                    aws_select_convert_records_to_json) if s3_query is not None else None,
            request.headers)
        download_filename = f'{dataset_id}--{version}.json'
        content_type = 'application/json'
        return _generate_downstream_response(
            body_generator, response, content_type, download_filename)

    @track_analytics
    @validate_and_redirect_version
    @validate_format(('csv',))
    def proxy_table(dataset_id, version, table):
        logger.debug('Attempt to proxy: %s %s %s %s', request, dataset_id, version, table)
        header_row = None
        s3_key = f'{dataset_id}/{version}/tables/{table}/data.csv'

        if 'query-simple' in request.args:
            _, columns, filterable_columns = _get_table_metadata(
                dataset_id, version, table)
            filters = (
                {c.name: request.args.get(c.name)
                 for c in filterable_columns if request.args.get(c.name)}
            )

            select_columns = request.args.getlist('_columns') or [c.name for c in columns]
            select_clause = ','.join([f's.{c}' for c in select_columns])

            join_term = "','"
            where_clause = ' and '.join(
                [f"s.{name} in ('{join_term.join(value.split(','))}')" for name,
                 value in filters.items()]
            ) or None
            s3_query = f'SELECT {select_clause} FROM s3object s'
            if where_clause:
                s3_query += f' WHERE {where_clause}'
            header_row = [f"{','.join(select_columns)}\n".encode('utf-8')]
        else:
            s3_query = request.args.get('query-s3-select')

        body_generator, response = _proxy(
            s3_key,
            aws_select_post_body_csv(s3_query) if s3_query is not None else None,
            partial(aws_select_parse_result,
                    aws_select_convert_records_to_csv) if s3_query is not None else None,
            request.headers
        )
        if header_row:
            body_generator = chain(header_row, body_generator)

        download_filename = f'{dataset_id}--{version}--{table}.csv'
        content_type = 'text/csv'

        return _generate_downstream_response(
            body_generator, response, content_type, download_filename)

    Column = namedtuple('Column', ['name', 'description', 'filterable'])

    def _get_table_metadata(dataset_id, version, table):
        s3_key = f'{dataset_id}/{version}/metadata--csvw.json'
        body_generator, _ = _proxy(s3_key, None, None, request.headers)

        metadata_tables = json.loads(b''.join(body_generator))['tables']
        metadata_table = next(filter(lambda x: x['url'].split(
            '/')[1] == table, metadata_tables), None)
        columns = [Column(x['name'], x['dc:description'], x['dit:filterable'])
                   for x in metadata_table['tableSchema']['columns']]
        filterable_columns = [c for c in columns if c.filterable]
        return metadata_table, columns, filterable_columns

    @track_analytics
    @validate_and_redirect_version
    def filter_rows(dataset_id, version, table):
        metadata_table, _, filterable_columns = _get_table_metadata(dataset_id, version, table)
        filters = (
            {c.name: request.args.get(c.name)
             for c in filterable_columns if request.args.get(c.name)}
        )

        return html_template_environment.get_template('filter_rows.html').render(
            reset_url=url_for('filter_rows', dataset_id=dataset_id,
                              version=version, table=table),
            submit_url=url_for('filter_columns', dataset_id=dataset_id,
                               version=version, table=table),
            filterable_columns=filterable_columns,
            filters=filters,
            table_name=metadata_table['dc:title'],
        )

    @track_analytics
    @validate_and_redirect_version
    def filter_columns(dataset_id, version, table):
        metadata_table, columns, filterable_columns = _get_table_metadata(
            dataset_id, version, table)
        filters = (
            {c.name: request.args.get(c.name)
             for c in filterable_columns if request.args.get(c.name)}
        )

        return html_template_environment.get_template('filter_columns.html').render(
            back_url=url_for('filter_rows', dataset_id=dataset_id,
                             version=version, table=table, **filters),
            submit_url=url_for('proxy_table', dataset_id=dataset_id,
                               version=version, table=table),
            filters=filters,
            columns=columns,
            table_name=metadata_table['dc:title'],
        )

    @track_analytics
    @validate_and_redirect_version
    @validate_format(('csvw', 'html'))
    def proxy_metadata(dataset_id, version):
        logger.debug('Attempt to proxy: %s %s %s', request, dataset_id, version)

        s3_key = f'{dataset_id}/{version}/metadata--csvw.json'
        body_generator, response = _proxy(s3_key, None, None, request.headers)

        def _csvw():
            download_filename = f'{dataset_id}--{version}--metadata--csvw.json'
            content_type = 'application/csvm+json'
            return _generate_downstream_response(body_generator, response,
                                                 content_type, download_filename)

        def _html():
            download_filename = f'{dataset_id}--{version}--metadata.html'
            content_type = 'text/html'
            return _generate_downstream_response(
                _convert_csvw_to_html(dataset_id, version, body_generator), response,
                content_type, download_filename)

        return _csvw() if request.args['format'] == 'csvw' else _html()

    def healthcheck():
        """
        Healthcheck checks S3 bucket, `healthcheck` as dataset_id and v0.0.1 as version
        containing json string {'status': 'OK'}
        """
        s3_key = 'healthcheck/v0.0.1/data.json'
        body_generator, s3_response = _proxy(s3_key, None, None, request.headers)
        body_bytes = b''.join(chunk for chunk in body_generator)
        body_json = json.loads(body_bytes.decode('utf-8'))

        # v1 healthcheck format
        ok_status = body_json.get('status')

        # v2 healthcheck format
        if isinstance(ok_status, list):
            ok_status = ok_status[0].get('id')

        if s3_response.status == 200 and ok_status:
            pingdom_xml = """<?xml version="1.0" encoding="UTF-8"?>
            <pingdom_http_custom_check>
                <status>OK</status>
            </pingdom_http_custom_check>\n"""

            response = Response(pingdom_xml, status=200, mimetype='application/xml')
            response.headers['Content-Type'] = 'text/xml'
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            return response

        return Response(status=503)

    def _send_to_google_analytics(requester_ip, request_host, request_path, request_headers):
        logger.info('Sending to Google Analytics %s: %s...', request_host, request_path)
        requests.post(
            os.environ.get('GA_ENDPOINT', 'https://www.google-analytics.com/collect'),
            data={
                'v': '1',
                'tid': ga_tracking_id,
                'cid': str(uuid.uuid4()),
                't': 'pageview',
                'uip': requester_ip,
                'aip': '1',
                'dh': request_host,
                'dp': request_path,
                'ds': 'public-data-api',
                'dr': request_headers.get('referer', ''),
                'ua': request_headers.get('user-agent', ''),
            }
        )

    app = Flask('app')

    # If some paths are behing the IP filter, then num_proxies will be higher, because it
    # means requests go through the routing system twice. However, num_proxies is only
    # used for the IP sent to Google Analytics, so we can cope with it being wrong for
    # pre-release datasets
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, num_proxies=3)

    @app.after_request
    def _add_noindex_header(resp):
        resp.headers['X-Robots-Tag'] = 'no-index, no-follow'
        return resp

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
        '/v1/datasets/<string:dataset_id>/versions/<string:version>/tables/<string:table>/data',
        view_func=proxy_table
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/<string:version>/tables/<string:table>'
        '/filter/rows',
        view_func=filter_rows
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/<string:version>/tables/<string:table>'
        '/filter/columns',
        view_func=filter_columns
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/<string:version>/data', view_func=proxy_data
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/<string:version>/metadata',
        view_func=proxy_metadata
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
        os.environ['READONLY_AWS_ACCESS_KEY_ID'],
        os.environ['READONLY_AWS_SECRET_ACCESS_KEY'],
        os.environ['AWS_S3_ENDPOINT'],
        os.environ['AWS_S3_REGION'],
        os.environ.get('GA_TRACKING_ID')
    )

    if os.environ.get('SENTRY_DSN'):
        sentry_sdk.init(
            dsn=os.environ['SENTRY_DSN'],
            integrations=[FlaskIntegration()],
        )

    gevent.signal_handler(signal.SIGTERM, stop)
    start()
    gevent.get_hub().join()


if __name__ == '__main__':
    main()
