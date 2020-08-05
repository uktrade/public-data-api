from gevent import (
    monkey,
)
monkey.patch_all()
import gevent

from datetime import (
    datetime,
)
import hashlib
import hmac
import logging
import os
import re
import signal
from struct import (
    Struct,
)
import sys
import urllib.parse
from xml.sax.saxutils import escape as escape_xml

from flask import (
    Flask,
    Response,
    request,
)
from gevent.pywsgi import (
    WSGIServer,
)
import urllib3


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
        'accept-ranges', 'content-length', 'content-type', 'date', 'etag', 'last-modified',
        'content-range',
    ]

    def start():
        server.serve_forever()

    def stop():
        server.stop()

    def proxy(path):
        logger.debug('Attempt to proxy: %s', request)

        url = endpoint_url + path
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

        response_headers = tuple((
            (key, response.headers[key])
            for key in proxied_response_headers if key in response.headers
        ))
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

    def aws_sigv4_headers(
            aws_access_key_id, aws_secret_access_key, region_name,
            pre_auth_headers, service, host, method, path, params, body_hash):
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

    def aws_select_post_body(sql):
        sql_xml_escaped = escape_xml(sql)
        return \
            f'''<?xml version="1.0" encoding="UTF-8"?>
                <SelectObjectContentRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                   <Expression>{sql_xml_escaped}</Expression>
                   <ExpressionType>SQL</ExpressionType>
                   <InputSerialization>
                      <JSON>
                         <Type>Document</Type>
                      </JSON>
                   </InputSerialization>
                   <OutputSerialization>
                      <JSON>
                         <RecordDelimiter>,</RecordDelimiter>
                      </JSON>
                   </OutputSerialization>
                </SelectObjectContentRequest>
            '''.encode('utf-8')

    def aws_select_parse_result(input_iterable, output_chunk_size):
        # Returns a iterator that yields payload data in fixed size chunks. It does not depend
        # on the input_stream yielding chunks of any particular size, and internal copying or
        # concatanation of chunks is avoided

        class NoMoreBytes(Exception):
            pass

        def get_byte_readers(_input_iterable):
            chunk = b''
            offset = 0
            it = iter(_input_iterable)

            def _read_multiple_chunks(amt):
                nonlocal chunk
                nonlocal offset

                # Yield anything we already have
                if chunk:
                    to_yield = min(amt, len(chunk) - offset)
                    yield chunk[offset:offset + to_yield]
                    amt -= to_yield
                    offset += to_yield % len(chunk)

                # Yield the rest as it comes in
                while amt:
                    try:
                        chunk = next(it)
                    except StopIteration:
                        raise NoMoreBytes()
                    to_yield = min(amt, len(chunk))
                    yield chunk[:to_yield]
                    amt -= to_yield
                    offset = to_yield % len(chunk)
                    chunk = chunk if offset else b''

            def _read_single_chunk(amt):
                raw = b''.join(chunk for chunk in _read_multiple_chunks(amt))
                if raw:
                    return raw
                raise NoMoreBytes()

            return _read_multiple_chunks, _read_single_chunk

        ################################
        # Extract records from the bytes

        def yield_messages(_read_multiple_chunks, _read_single_chunk):
            # Yields a series of messages. Each is a dict of headers together with a generator that
            # itself yields the bytes of the payload of the message. The payload generator must
            # be read by calling code before the next iteration of this generator
            prelude_struct = Struct('!III')
            byte_struct = Struct('!B')
            header_value_struct = Struct('!H')

            while True:
                try:
                    total_length, header_length, _ = prelude_struct.unpack(_read_single_chunk(12))
                except NoMoreBytes:
                    return
                payload_length = total_length - header_length - 16

                # Read headers. Any given header type can only appear once, so a dict
                # type => value is fine
                headers = {}
                while header_length:
                    header_key_length, = byte_struct.unpack(_read_single_chunk(1))
                    header_key = _read_single_chunk(header_key_length).decode('utf-8')
                    _ = _read_single_chunk(1)  # Header value type is ignored for S3
                    header_value_length, = header_value_struct.unpack(_read_single_chunk(2))
                    header_value = _read_single_chunk(header_value_length).decode('utf-8')
                    header_length -= (1 + header_key_length + 1 + 2 + header_value_length)
                    headers[header_key] = header_value

                def payload():
                    for chunk in _read_multiple_chunks(payload_length):
                        yield chunk

                    # Ignore final CRC
                    final_crc_length = 4
                    for _ in _read_multiple_chunks(final_crc_length):
                        pass

                yield headers, payload()

        def yield_records(_messages):
            for headers, payload in _messages:
                if headers[':message-type'] == 'event' and headers[':event-type'] == 'Records':
                    yield from payload
                else:
                    for _ in payload:
                        pass

        def yield_as_json(_records):
            yield b'{"rows":['

            # Slightly faffy to remove the trailing "," from S3 Select output
            try:
                last = next(_records)
            except StopIteration:
                pass
            else:
                for val in _records:
                    yield last
                    last = val

                yield last[:len(last) - 1]

            yield b']}'

        def yield_as_utf_8(_as_json):
            # The output from S3 Select [at least from minio] appears to include unicode escape
            # sequences, even for characters like > and &. A plain .decode('unicode-escape') isn't
            # enough to convert them, since an excape sequence can be truncated if it crosses into
            # the next chunk, and in fact even using .decode('unicode-escape') where you're sure
            # there is no truncated unicode escape sequence breaks non-ASCII UTF-8 data, since it
            # appears to treat them as Latin-1. So we have to do our own search and and replace.

            def even_slashes_before(_chunk, index):
                count = 0
                index -= 1
                while index >= 0 and _chunk[index:index + 1] == b'\\':
                    count += 1
                    index -= 1
                return count % 2 == 0

            def split_trailing_escape(_chunk):
                # \, \u, \uX, \uXX, \uXXX, with an even number of \ before are trailing escapes
                if _chunk[-1:] == b'\\':
                    if even_slashes_before(_chunk, len(_chunk) - 1):
                        return _chunk[:-1], _chunk[-1:]
                elif _chunk[-2:] == b'\\u':
                    if even_slashes_before(_chunk, len(_chunk) - 2):
                        return _chunk[:-2], _chunk[-2:]
                elif _chunk[-3:-1] == b'\\u':
                    if even_slashes_before(_chunk, len(_chunk) - 3):
                        return _chunk[:-3], _chunk[-3:]
                elif _chunk[-4:-2] == b'\\u':
                    if even_slashes_before(_chunk, len(_chunk) - 4):
                        return _chunk[:-4], _chunk[-4:]
                elif _chunk[-5:-3] == b'\\u':
                    if even_slashes_before(_chunk, len(_chunk) - 5):
                        return _chunk[:-5], _chunk[-5:]
                return _chunk, b''

            def unicode_escapes_to_utf_8(_chunk):
                def to_utf_8(match):
                    group = match.group()
                    if even_slashes_before(_chunk, match.span()[0]):
                        return group.decode('unicode-escape').encode('utf-8')
                    return group

                return re.sub(b'\\\\u[0-9a-fA-F]{4}', to_utf_8, _chunk)

            trailing_escape = b''
            for chunk in as_json:
                chunk, trailing_escape = split_trailing_escape(trailing_escape + chunk)

                if chunk:
                    yield unicode_escapes_to_utf_8(chunk)

        def yield_output(_as_json_utf_8, _output_chunk_size):
            # Typically web servers send an HTTP chunk for every yield of the body generator, which
            # can result in quite small chunks so more packets/bytes over the wire. We avoid this.
            chunks = []
            num_bytes = 0
            for chunk in _as_json_utf_8:
                chunks.append(chunk)
                num_bytes += len(chunk)
                if num_bytes < _output_chunk_size:
                    continue
                chunk = b''.join(chunks)
                output, chunk = chunk[:_output_chunk_size], chunk[_output_chunk_size:]
                yield output
                num_bytes = len(chunk)
                chunks = [chunk] if chunk else []

            if chunks:
                yield b''.join(chunks)

        read_multiple_chunks, read_single_chunk = get_byte_readers(input_iterable)
        messages = yield_messages(read_multiple_chunks, read_single_chunk)
        records = yield_records(messages)
        as_json = yield_as_json(records)
        as_json_utf_8 = yield_as_utf_8(as_json)
        output = yield_output(as_json_utf_8, output_chunk_size)

        return output

    app = Flask('app')

    app.add_url_rule('/<path:path>', view_func=proxy)
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
