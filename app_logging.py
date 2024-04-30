import datetime
import json
import logging
import os
from flask import request, has_request_context


class ASIMFormatter(logging.Formatter):
    def format(self, record):
        log_time = datetime.datetime.utcfromtimestamp(record.created).isoformat()
        return json.dumps({
            'EventMessage': record.getMessage(),
            'EventCount': 1,
            'EventStartTime': log_time,
            'EventEndTime': log_time,
            'EventType': record.name,
            'EventResult': 'NA',
            'EventSeverity': {
                'DEBUG': 'Informational',
                'INFO': 'Informational',
                'WARNING': 'Low',
                'ERROR': 'Medium',
                'CRITICAL': 'High',
            }[record.levelname],
            'EventOriginalSeverity': record.levelname,
            'EventSchema': 'ProcessEvent',
            'EventSchemaVersion': '0.1.4',
            'ActingAppType': 'Flask',
            'AdditionalFields': {
                # This _would_ be the version of the library making the log message, but we're
                # using one built right into the Public Data API
                'PublicDataAPIAsimVersion': os.environ.get('GIT_COMMIT'),
                'TraceHeaders': {
                    key: request.headers[key]
                    for key in ('X-Amzn-Trace-Id', 'X-B3-TraceId', 'X-B3-SpanId')
                    if key in request.headers
                } if has_request_context() else {}
            }
        } | ({
            'HttpUserAgent': request.headers.get('User-Agent'),
            'SrcPortNumber': request.environ.get('REMOTE_PORT'),
            'SrcIpAddr': request.remote_addr,
            'IpAddr': request.remote_addr,
            'SrcUserId': None,
            'SrcUsername': 'AnonymousUser',
        } if has_request_context() else {}))
