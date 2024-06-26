from concurrent.futures import (
    ThreadPoolExecutor,
    wait,
)
from datetime import (
    datetime,
)
import hashlib
import hmac
from queue import Queue
import re
from struct import (
    Struct,
)
import urllib.parse
from xml.etree import (
    ElementTree as ET,
)
from xml.sax.saxutils import (
    escape as escape_xml,
)


MIN_S3_MULTIPART_CHUNK_SIZE = 5_242_880


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


def aws_s3_request(parsed_endpoint, http, aws_access_key_id, aws_secret_access_key, region_name,
                   method, s3_key, pre_auth_headers=(), params=(), body=b''):
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


def aws_select_post_body_json(sql):
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


def aws_select_post_body_csv(sql):
    sql_xml_escaped = escape_xml(sql)
    return \
        f'''<?xml version="1.0" encoding="UTF-8"?>
            <SelectObjectContentRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
               <Expression>{sql_xml_escaped}</Expression>
               <ExpressionType>SQL</ExpressionType>
               <InputSerialization>
                  <CSV>
                     <AllowQuotedRecordDelimiter>True</AllowQuotedRecordDelimiter>
                     <FieldDelimiter>,</FieldDelimiter>
                     <FileHeaderInfo>USE</FileHeaderInfo>
                  </CSV>
               </InputSerialization>
               <OutputSerialization>
                  <CSV>
                     <FieldDelimiter>,</FieldDelimiter>
                  </CSV>
               </OutputSerialization>
            </SelectObjectContentRequest>
        '''.encode('utf-8')


def aws_select_convert_records_to_json(records):

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
        for chunk in _as_json:
            chunk, trailing_escape = split_trailing_escape(trailing_escape + chunk)

            if chunk:
                yield unicode_escapes_to_utf_8(chunk)

    as_json = yield_as_json(records)
    as_json_utf_8 = yield_as_utf_8(as_json)
    yield from as_json_utf_8


def aws_select_convert_records_to_csv(records):
    # Nothing to do for CSV
    yield from records


def aws_select_parse_result(convert_records_to_output, input_iterable, min_output_chunk_size):
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
                chunk = chunk if offset else b''

            # Yield the rest as it comes in
            while amt:
                try:
                    chunk = next(it)
                except StopIteration:
                    raise NoMoreBytes() from None
                to_yield = min(amt, len(chunk))
                yield chunk[:to_yield]
                amt -= to_yield
                offset = to_yield % len(chunk)
                chunk = chunk if offset else b''

        def _read_single_chunk(amt):
            return b''.join(chunk for chunk in _read_multiple_chunks(amt))

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

    def yield_output(_as_output_utf_8, _min_output_chunk_size):
        # Typically web servers send an HTTP chunk for every yield of the body generator, which
        # can result in quite small chunks so more packets/bytes over the wire. We avoid this.
        chunks = []
        num_bytes = 0
        for chunk in _as_output_utf_8:
            chunks.append(chunk)
            num_bytes += len(chunk)
            if num_bytes < _min_output_chunk_size:
                continue
            yield b''.join(chunks)
            chunks = []

        if chunks:
            yield b''.join(chunks)

    read_multiple_chunks, read_single_chunk = get_byte_readers(input_iterable)
    messages = yield_messages(read_multiple_chunks, read_single_chunk)
    records = yield_records(messages)
    as_output = convert_records_to_output(records)
    output = yield_output(as_output, min_output_chunk_size)

    return output


def aws_list_folders(signed_s3_request, prefix=None):
    namespace = '{http://s3.amazonaws.com/doc/2006-03-01/}'
    token = ''

    def _list(extra_query_params=()):
        nonlocal token

        token = ''
        query = (
            ('max-keys', '1000'),
            ('list-type', '2'),
            ('delimiter', '/'),
        ) + \
            ((('prefix', prefix),) if prefix is not None else ()) + \
            extra_query_params
        with signed_s3_request('GET', s3_key='', params=query) as response:
            body_bytes = response.read()

        if response.status != 200:
            raise Exception(response.status, body_bytes)

        for element in ET.fromstring(body_bytes):
            if element.tag == f'{namespace}CommonPrefixes':
                for child in element:
                    yield child.text[len(prefix if prefix is not None else ''):-1]
            if element.tag == f'{namespace}NextContinuationToken':
                token = element.text

    yield from _list()

    while token:
        yield from _list((('continuation-token', token),))


def aws_list_keys(signed_s3_request, prefix=None):
    namespace = '{http://s3.amazonaws.com/doc/2006-03-01/}'
    token = ''

    def _list(extra_query_params=()):
        nonlocal token

        token = ''
        query = (
            ('max-keys', '1000'),
            ('list-type', '2'),
        ) + \
            ((('prefix', prefix),) if prefix is not None else ()) + \
            extra_query_params
        with signed_s3_request('GET', s3_key='', params=query) as response:
            body_bytes = response.read()

        if response.status != 200:
            raise Exception(response.status, body_bytes)

        for element in ET.fromstring(body_bytes):
            if element.tag == f'{namespace}Contents':
                for child in element:
                    if child.tag == f'{namespace}Key':
                        yield child.text[len(prefix if prefix is not None else ''):]
            if element.tag == f'{namespace}NextContinuationToken':
                token = element.text

    yield from _list()

    while token:
        yield from _list((('continuation-token', token),))


def aws_head(signed_s3_request, key):
    with signed_s3_request('HEAD', s3_key=key) as response:
        response.read()

    return response.status, response.headers


def aws_multipart_upload(
        signed_s3_request,
        key,
        chunks,
        max_concurrent=3,
        part_size=MIN_S3_MULTIPART_CHUNK_SIZE,
        max_upload_time=60 * 10):

    def parts():
        queue = []
        queue_length = 0

        for chunk in chunks:
            queue.append(chunk)
            queue_length += len(chunk)

            while queue_length >= part_size:
                to_send_later = b''.join(queue)
                chunk, to_send_later = \
                    to_send_later[:part_size], to_send_later[part_size:]

                queue = \
                    [to_send_later] if to_send_later else \
                    []
                queue_length = len(to_send_later)

                yield chunk

        if queue_length:
            yield b''.join(queue)

    def start():
        with signed_s3_request('POST', key, params=(('uploads', ''),)) as response:
            response_body = response.read()
            if response.status != 200:
                raise Exception(f'Unable to start upload {key} {response.status} {response_body}')
            return re.search(b'<UploadId>(.*)</UploadId>', response_body)[1].decode('utf-8')

    def upload(upload_id, part_number, part):
        params = (('uploadId', upload_id), ('partNumber', str(part_number)))
        with signed_s3_request('PUT', key, params=params, body=part) as response:
            response_body = response.read()
            if response.status != 200:
                raise Exception(f'Unable to upload part {upload_id} {part_number} {response_body}')
            return part_number, response.headers['etag']

    def complete(upload_id, part_numbers_etags):
        body = (
            '<CompleteMultipartUpload>' + ''.join(
                f'<Part><PartNumber>{part_number}</PartNumber><ETag>{part_etag}</ETag></Part>'
                for part_number, part_etag in part_numbers_etags
            ) + '</CompleteMultipartUpload>'
        ).encode('utf-8')
        params = (('uploadId', upload_id),)
        with signed_s3_request('POST', key, params=params, body=body) as response:
            response_body = response.read()
            if response.status != 200:
                raise Exception(f'Upload to complete upload {upload_id} {key} {response_body}')

    # Upload in multiple threads so the iteration over incoming chunks is less likely to stall.
    # We also limit the ThreadPoolExecutor so we block iteration over incoming chunks so we don't
    # buffer all incoming bytes into memory

    upload_id = start()

    class ThreadPoolExecutorSingleItemWorkQueue(ThreadPoolExecutor):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._work_queue = Queue(maxsize=1)

    with ThreadPoolExecutorSingleItemWorkQueue(max_workers=max_concurrent) as executor:
        uploads = [
            executor.submit(upload, upload_id, part_number, part)
            for part_number, part in enumerate(parts(), 1)
        ]
        wait(uploads, timeout=max_upload_time)

    for upload in uploads:
        exception = upload.exception()
        if exception:
            raise exception from None

    part_numbers_etags = [upload.result() for upload in uploads]
    complete(upload_id, part_numbers_etags)
