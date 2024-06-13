'''
Run this using:

pytest migration/test_content.py -v
'''

import hashlib

import httpx
import pytest

@pytest.mark.parametrize(
    'url, expected_digest', (
    (
        'https://data.api.trade.gov.uk/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.246/data?format=sqlite&download',
        '874f3ad4522e250b2fb55acc43fc7d4205a002dea239d7154a3c99ee59b65fe9',
    ),
))
def test(url, expected_digest):
    m = hashlib.sha256()
    with httpx.stream('GET', url) as r:
        for chunk in r.iter_bytes():
            m.update(chunk)

    assert m.hexdigest() == expected_digest
