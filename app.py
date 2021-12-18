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
    render_template,
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
    aws_list_keys,
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
        apm.client.close()

    def track_analytics(handler):
        """Decorator to send analytics data to google in the background."""

        def _send(requester_ip, request_url, request_headers):
            logger.info('Sending to Google Analytics %s...', request_url)
            requests.post(
                os.environ.get('GA_ENDPOINT', 'https://www.google-analytics.com/collect'),
                data={
                    'v': '1',
                    'tid': ga_tracking_id,
                    'cid': str(uuid.uuid4()),
                    't': 'pageview',
                    'uip': requester_ip,
                    'aip': '1',
                    'dl': request_url,
                    'ds': 'public-data-api',
                    'dr': request_headers.get('referer', ''),
                    'ua': request_headers.get('user-agent', ''),
                }
            )

        @wraps(handler)
        def send(*args, **kwargs):
            if ga_tracking_id:
                gevent.spawn(
                    _send,
                    request.remote_addr,
                    request.url,
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

            folders = aws_list_folders(signed_s3_request,
                                       prefix=request.view_args['dataset_id'] + '/')
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

    def _generate_downstream_response(
            body_generator, response, content_type, download_filename, content_encoding=None
    ):
        allow_proxy = response.status in proxied_response_codes

        logger.debug('Allowing proxy: %s', allow_proxy)

        response_headers_no_content_type = tuple((
            (key, response.headers[key])
            for key in proxied_response_headers if key in response.headers
        ))
        download_headers = (
            ('content-disposition', f'attachment; filename="{download_filename}"'),
        ) if 'download' in request.args else ()
        encoding_headers = (
            ('content-encoding', content_encoding),
        ) if content_encoding else ()

        response_headers = response_headers_no_content_type + \
            (('content-type', content_type),) + download_headers + encoding_headers

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
        csvw_with_id = {
            **csvw,
            'tables': [
                {
                    **table,
                    '_id': table['url'].split('/')[1],
                    '_html_id': f"{table['url'].split('/')[0][:-1]}--{table['url'].split('/')[1]}",
                    '_table_or_report': table['url'].split('/')[0][:-1],
                }
                for table in csvw['tables']
            ]
        }
        table_head_status_headers = [
            (
                table['_html_id'],
                aws_head(signed_s3_request, f'{dataset_id}/{version}/'
                         + f'{table["_table_or_report"]}s/{table["_id"]}/data.csv'),
            )
            for table in csvw_with_id['tables']
        ]
        table_sizes = {
            table_html_id: headers['content-length']
            for table_html_id, (_, headers) in table_head_status_headers
        }
        filter_urls = {table['_html_id']: url_for(
            f'filter_{table["_table_or_report"]}_rows',
            dataset_id=dataset_id, version=version, table=table['_id']
        ) for table in csvw_with_id['tables']}
        return html_template_environment.get_template('metadata.html').render(
            version=version,
            version_published_at=max((
                datetime.datetime(*parsedate(headers['last-modified'])[:6])
                for _, (_, headers) in table_head_status_headers)),
            csvw=csvw_with_id,
            filter_urls=filter_urls,
            metadata_download_url=url_for('proxy_metadata', dataset_id=dataset_id, version=version)
            + '?format=csvw&download',
            table_sizes=table_sizes)

    @track_analytics
    @validate_format(('json',))
    def list_all_datasets():
        folders = aws_list_folders(signed_s3_request)
        versions = {
            'datasets': [
                {'id': dataset} for dataset in folders if dataset != 'healthcheck'
            ]
        }

        return Response(json.dumps(versions), headers={'content-type': 'text/json'}, status=200)

    @track_analytics
    @validate_format(('data.json',))
    def get_metadata_for_dataset(dataset_id):
        def semver_key(path):
            v_major_str, minor_str, patch_str = path.split('.')
            return (int(v_major_str[1:]), int(minor_str), int(patch_str))

        def relative_to_metadata(version, relative_url):
            return urllib.parse.urljoin(url_for('proxy_metadata', dataset_id=dataset_id,
                                                version=version, _external=True), relative_url)

        def flatten(list_of_lists):
            return [item for sublist in list_of_lists for item in sublist]

        # Fetch all metadata files
        metadatas = {}
        for key in aws_list_keys(signed_s3_request, dataset_id + '/'):
            components = key.split('/')
            if len(components) == 2 and components[1] == 'metadata--csvw.json':
                version = components[0]
                body_generator, _ = _proxy(dataset_id + '/' + key, None, None, request.headers)
                metadatas[version] = json.loads(b''.join(body_generator))

        if not metadatas:
            abort(404)

        # Sort metadatas by semver, to have most recent at the start
        metadatas = dict(sorted(metadatas.items(),
                                key=lambda key_value: semver_key(key_value[0]), reverse=True))

        # Choose most recent metadata as the one for the title
        metadata_recent = metadatas[next(iter(metadatas.keys()))]

        # Ideally each identifier is an URL with an HTML page, but doesn't have to be. So for now,
        # it's not. It's also deliberately not a URL to a specific version of this API, since even
        # in later versions, this identifier must be the same
        identifier_root = urllib.parse.urlunsplit(urllib.parse.urlsplit(
            request.base_url)._replace(path='/', query=''))

        return Response(json.dumps({
            'dataset': [
                {

                    'identifier': f'{identifier_root}datasets/{dataset_id}',
                    'title': metadata_recent['dc:title'],
                    'description': metadata_recent['dc:description'],
                    'license': metadata_recent['dc:license'],
                    'publisher': {
                        'name': metadata_recent['dc:creator'],
                    },
                    'distribution': flatten(
                        [
                            {
                                'title': f'{version} - Metadata',
                                'format': 'HTML',
                                'downloadURL': relative_to_metadata(version,
                                                                    'metadata?format=html'),
                            }
                        ]
                        + [
                            {
                                'title': f'{version} - {database["dc:title"]}',
                                'format': 'SQLite',
                                'downloadURL': relative_to_metadata(version, database['url'])
                            }
                            for database in metadata.get('dit:databases', [])
                        ]
                        + [
                            {
                                'title': f'{version} - {table["dc:title"]}',
                                'format': 'CSV',
                                'downloadURL': relative_to_metadata(version, table['url']),
                            }
                            for table in metadata['tables']
                        ]
                        for (version, metadata) in metadatas.items()
                    )
                }
            ]
        }), headers={'content-type': 'text/json'}, status=200)

    @track_analytics
    @validate_format(('json',))
    def list_versions_for_dataset(dataset_id):
        def semver_key(path):
            v_major_str, minor_str, patch_str = path.split('.')
            return (int(v_major_str[1:]), int(minor_str), int(patch_str))

        folders = aws_list_folders(signed_s3_request, prefix=dataset_id + '/')
        sorted_versions = sorted(folders, key=semver_key, reverse=True)
        versions = {'versions': [{'id': version} for version in sorted_versions]}

        return Response(json.dumps(versions), headers={'content-type': 'text/json'}, status=200)

    @track_analytics
    @validate_and_redirect_version
    @validate_format(('json',))
    def list_tables_for_dataset_version(dataset_id, version):
        folders = aws_list_folders(signed_s3_request, prefix=f'{dataset_id}/{version}/tables/')
        tables = {'tables': [{'id': table} for table in folders]}

        return Response(json.dumps(tables), headers={'content-type': 'text/json'}, status=200)

    @track_analytics
    @validate_and_redirect_version
    @validate_format(('json',))
    def list_reports_for_dataset_version(dataset_id, version):
        folders = aws_list_folders(signed_s3_request, prefix=f'{dataset_id}/{version}/reports/')
        reports = {'reports': [{'id': report} for report in folders]}
        return Response(json.dumps(reports), headers={'content-type': 'text/json'}, status=200)

    @track_analytics
    @validate_and_redirect_version
    @validate_format(('json', 'sqlite',))
    def proxy_data(dataset_id, version):
        logger.debug('Attempt to proxy: %s %s %s', request, dataset_id, version)

        s3_query = request.args.get('query-s3-select')
        accepted_encodings = request.headers.get('accept-encoding', '').replace(' ', '').split(',')
        attempt_gzip = 'gzip' in accepted_encodings and s3_query is None

        base_s3_key = f'{dataset_id}/{version}/data.{request.args["format"]}'
        key_content_encodings = () + \
            (((base_s3_key + '.gz', 'gzip'),) if attempt_gzip else ()) + \
            ((base_s3_key, None),)

        for s3_key, content_encoding in key_content_encodings:
            body_generator, response = _proxy(
                s3_key,
                aws_select_post_body_json(s3_query) if s3_query is not None else None,
                partial(aws_select_parse_result,
                        aws_select_convert_records_to_json) if s3_query is not None else None,
                request.headers)
            if response.status in (200, 206):
                break
            for _ in response.stream(65536, decode_content=False):
                pass
        else:
            if response.status == 404:
                abort(404)
            else:
                raise Exception(f'Unexpected code from S3: {response.status}')

        download_filename = f'{dataset_id}--{version}.{request.args["format"]}'
        content_type = \
            'application/vnd.sqlite3' if request.args['format'] == 'sqlite' else \
            'application/json'
        return _generate_downstream_response(
            body_generator, response, content_type, download_filename,
            content_encoding=content_encoding)

    @track_analytics
    @validate_and_redirect_version
    @validate_format(('csv',))
    def proxy_table(dataset_id, version, table):
        return proxy_table_or_report('table', dataset_id, version, table)

    @track_analytics
    @validate_and_redirect_version
    @validate_format(('csv',))
    def proxy_report(dataset_id, version, table):
        return proxy_table_or_report('report', dataset_id, version, table)

    def proxy_table_or_report(table_or_report, dataset_id, version, table):
        logger.debug('Attempt to proxy: %s %s %s %s %s', table_or_report,
                     request, dataset_id, version, table)
        header_row = None
        s3_key = f'{dataset_id}/{version}/{table_or_report}s/{table}/data.csv'

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

        gzip_encode = 'accept-encoding' in request.headers and 'gzip' in request.headers.get(
            'accept-encoding', '').replace(' ', '').split(',') and s3_query is None
        content_encoding = 'gzip' if gzip_encode else None

        body_generator, response = _proxy(
            s3_key + ('.gz' if gzip_encode else ''),
            aws_select_post_body_csv(s3_query) if s3_query is not None else None,
            partial(aws_select_parse_result,
                    aws_select_convert_records_to_csv) if s3_query is not None else None,
            request.headers
        )

        if response.status == 404 and gzip_encode:
            for _ in response.stream(65536, decode_content=False):
                pass
            body_generator, response = _proxy(
                s3_key,
                aws_select_post_body_csv(s3_query) if s3_query is not None else None,
                partial(aws_select_parse_result,
                        aws_select_convert_records_to_csv) if s3_query is not None else None,
                request.headers
            )
            content_encoding = None

        if header_row:
            body_generator = chain(header_row, body_generator)

        download_filename = \
            f'{dataset_id}--{version}--{table}.csv' if table_or_report == 'table' else \
            f'{dataset_id}--{version}--report--{table}.csv'
        content_type = 'text/csv'

        return _generate_downstream_response(
            body_generator, response, content_type, download_filename,
            content_encoding=content_encoding
        )

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
    def filter_table_rows(dataset_id, version, table):
        return filter_table_or_report_rows('table', dataset_id, version, table)

    @track_analytics
    @validate_and_redirect_version
    def filter_report_rows(dataset_id, version, table):
        return filter_table_or_report_rows('report', dataset_id, version, table)

    def filter_table_or_report_rows(table_or_report, dataset_id, version, table):
        metadata_table, _, filterable_columns = _get_table_metadata(dataset_id, version, table)
        filters = (
            {c.name: request.args.get(c.name)
             for c in filterable_columns if request.args.get(c.name)}
        )

        return html_template_environment.get_template('filter_rows.html').render(
            reset_url=url_for(f'filter_{table_or_report}_rows', dataset_id=dataset_id,
                              version=version, table=table),
            submit_url=url_for(f'filter_{table_or_report}_columns', dataset_id=dataset_id,
                               version=version, table=table),
            filterable_columns=filterable_columns,
            filters=filters,
            table_name=metadata_table['dc:title'],
        )

    @track_analytics
    @validate_and_redirect_version
    def filter_table_columns(dataset_id, version, table):
        return filter_table_or_report_columns('table', dataset_id, version, table)

    @track_analytics
    @validate_and_redirect_version
    def filter_report_columns(dataset_id, version, table):
        return filter_table_or_report_columns('report', dataset_id, version, table)

    def filter_table_or_report_columns(table_or_report, dataset_id, version, table):
        metadata_table, columns, filterable_columns = _get_table_metadata(
            dataset_id, version, table)
        filters = (
            {c.name: request.args.get(c.name)
             for c in filterable_columns if request.args.get(c.name)}
        )

        return html_template_environment.get_template('filter_columns.html').render(
            back_url=url_for(f'filter_{table_or_report}_rows', dataset_id=dataset_id,
                             version=version, table=table, **filters),
            submit_url=url_for(f'proxy_{table_or_report}', dataset_id=dataset_id,
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

            return Response(pingdom_xml, headers={
                'content-type': 'text/xml',
                'cache-control': 'no-cache, no-store, must-revalidate'
            }, status=200)

        return Response(status=503)

    @track_analytics
    def docs():
        """
        Documentation homepage
        """
        context = {
            'department_name': os.environ.get('DOCS_DEPARTMENT_NAME'),
            'service_name': os.environ.get('DOCS_SERVICE_NAME'),
            'github_repo_url': os.environ.get('DOCS_GITHUB_REPO_URL'),
            'base_url': request.base_url.rstrip('/'),
            'dataset': os.environ.get('DOCS_SAMPLE_DATASET', 'uk-tariff-2021-01-01'),
            'version': os.environ.get('DOCS_SAMPLE_VERSION', 'v2.1.0'),
            'latest_version': os.environ.get('DOCS_SAMPLE_LATEST_VERSION', 'v2.1.2'),
            'table_name': os.environ.get('DOCS_SAMPLE_TABLE_NAME', 'commodities'),
            'security_email': os.environ.get('DOCS_SECURITY_EMAIL'),
        }
        return render_template('docs/index.html', **context)

    app = Flask('app')

    # If some paths are behing the IP filter, then num_proxies will be higher, because it
    # means requests go through the routing system twice. However, num_proxies is only
    # used for the IP sent to Google Analytics, so we can cope with it being wrong for
    # pre-release datasets
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, num_proxies=3)

    @app.after_request
    def _add_noindex_header(resp):
        resp.headers['access-control-allow-origin'] = '*'
        resp.headers['x-robots-tag'] = 'no-index, no-follow'
        return resp

    apm = ElasticAPM(
        app,
        service_name='public-data-api',
        secret_token=os.environ['APM_SECRET_TOKEN'],
        server_url=os.environ['APM_SERVER_URL'],
        environment=os.environ['ENVIRONMENT'],
        server_timeout=os.environ.get('APM_SERVER_TIMEOUT', None),
    )

    app.add_url_rule(
        '/v1/datasets',
        view_func=list_all_datasets
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/metadata',
        view_func=get_metadata_for_dataset,
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions',
        view_func=list_versions_for_dataset
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/<string:version>/tables',
        view_func=list_tables_for_dataset_version
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/<string:version>/reports',
        view_func=list_reports_for_dataset_version
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/<string:version>/tables/<string:table>/data',
        view_func=proxy_table
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/<string:version>/reports/<string:table>/data',
        view_func=proxy_report
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/<string:version>/tables/<string:table>'
        '/filter/rows',
        view_func=filter_table_rows
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/<string:version>/reports/<string:table>'
        '/filter/rows',
        view_func=filter_report_rows
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/<string:version>/tables/<string:table>'
        '/filter/columns',
        view_func=filter_table_columns
    )
    app.add_url_rule(
        '/v1/datasets/<string:dataset_id>/versions/<string:version>/reports/<string:table>'
        '/filter/columns',
        view_func=filter_report_columns
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
    app.add_url_rule(
        '/', 'docs', view_func=docs
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
        sentry_sdk.init(  # pylint: disable=abstract-class-instantiated
            dsn=os.environ['SENTRY_DSN'],
            integrations=[FlaskIntegration()],
            # Session tracking makes graceful shutdown difficult since it starts a thread but there
            # is no quick way to kill it
            auto_session_tracking=False,
        )

    gevent.signal_handler(signal.SIGTERM, stop)
    start()
    gevent.get_hub().join()
    logger.info('Shut down gracefully')


if __name__ == '__main__':
    main()
