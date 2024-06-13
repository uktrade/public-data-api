'''
Run this using:

pytest migration/test_content.py -vv
'''

import hashlib

import httpx
import pytest

# Run again real prod and one that is in DBT platform so we can use this both for pre and
# post migration tests
bases = (
    'https://data.api.trade.gov.uk',
    'https://data-api.prod.uktrade.digital',
)

@pytest.mark.parametrize(
    'base',
    bases,
)
@pytest.mark.parametrize(
    'path, expected_digest', (
    # Latest version of UK Tariff at the time
    (
        '/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.246/metadata?format=html',
        'b64952629acf8178a4c16c136466d6f38c5ee7026a9c438ad2221381e55bf28e',
    ),
    (
        '/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.246/tables/commodities-report/data?format=ods&download',
        '58270f8340b7b31f18d0a855dc9702a86bdd37dce5a9f96cc0b7a86712637c6a',
    ),
    (
        '/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.246/tables/measures-as-defined/data?format=ods&download',
        '27ba99cf4a1e0534e458e95f02f5d633e92b3fe5730454fd5e0ffa29c4318c72',
    ),
    (
        '/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.246/reports/measures-on-declarable-commodities/data?format=ods&download',
        '539ae57e8df347a20a69ea9c34b1df4c54f54fab5225ee424c0ada583534570e',
    ),
    (
        '/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.246/data?format=sqlite&download',
        '874f3ad4522e250b2fb55acc43fc7d4205a002dea239d7154a3c99ee59b65fe9',
    ),
    # Earliest version with links on https://www.data.gov.uk/dataset/3bee9a8a-e69c-400e-add5-3345a87a8e25/tariffs-to-trade-with-the-uk-from-1-january-2021
    (
        '/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.0/metadata?format=html',
        '3f82f7f34659ed12672dba106604a05193c39c3a50250bfa88be610c4a723adb',
    ),
    (
        '/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.0/tables/commodities-report/data?format=ods&download',
        'b2eaf3a2536da2912cdd62d8fc3fab388315a0cf59256932ef38a91803c1e99b',
    ),
    (
        '/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.0/tables/measures-as-defined/data?format=ods&download',
        '10dcfcf90d0a2e6740669a643c7958d5dbc2d07268520bae7587b415b2786c04',
    ),
    (
        '/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.0/reports/measures-on-declarable-commodities/data?format=ods&download',
        '15d9cd233b5f1e6571a95388e2b8bc8890ce51a2827b9e3ae4bd97416a0f51db',
    ),
    (
        '/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.0/data?format=sqlite&download',
        '71d543ac5b51f115b651e776e2011a6bbe04b0bed77c4a1175873dc9418807e3',
    ),
    # Filtering on latest version
    (
        '/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.246/tables/measures-on-declarable-commodities/data?query-simple=&download=&format=csv&commodity__code=0101210000&_columns=commodity__code&_columns=measure__type__id&_columns=measure__type__description',
        '486d6465597ee143f637be71f84c2fbffafb68000b7e844943ada8f65c69481e',
    ),
))
def test_content_on_public_data_api(base, path, expected_digest):
    m = hashlib.sha256()
    with httpx.stream('GET', base + path) as r:
        for chunk in r.iter_bytes():
            m.update(chunk)

    assert m.hexdigest() == expected_digest
