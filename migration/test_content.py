'''
Run this using:

pytest migration/test_content.py -vv
'''

import hashlib

import httpx
import pytest

@pytest.mark.parametrize(
    'url, expected_digest', (
    # Latest version of UK Tariff
    (
        'https://data.api.trade.gov.uk/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.246/metadata?format=html',
        'b64952629acf8178a4c16c136466d6f38c5ee7026a9c438ad2221381e55bf28e',
    ),
    (
        'https://data.api.trade.gov.uk/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.246/tables/commodities-report/data?format=ods&download',
        '58270f8340b7b31f18d0a855dc9702a86bdd37dce5a9f96cc0b7a86712637c6a',
    ),
    (
        'https://data.api.trade.gov.uk/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.246/tables/measures-as-defined/data?format=ods&download',
        '27ba99cf4a1e0534e458e95f02f5d633e92b3fe5730454fd5e0ffa29c4318c72',
    ),
    (
        'https://data.api.trade.gov.uk/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.246/reports/measures-on-declarable-commodities/data?format=ods&download',
        '539ae57e8df347a20a69ea9c34b1df4c54f54fab5225ee424c0ada583534570e',
    ),
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
