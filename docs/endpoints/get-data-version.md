---
order: 6
title: GET data in a version
description: All of the data of a dataset version can be accessed using this endpoint
---

```curl
GET /v1/datasets/{dataset_id}/versions/{version_id}/data
```

### Query string parameters
| Syntax    | Required | Description |
| --------- | ----------- | ----------- |
| `format`    | Yes    | 	The requested output format. This must be `sqlite`, `json`, or `ods` |
| `query-s3-select	`    | No    | A query using the S3 Select query language, e.g. `SELECT * FROM S3Object[*]`. </br></br>The response is a JSON object with the query results under the `rows` key, i.e. `{"rows": [...]}`. </br></br>Using `query-s3-select` requires that the `format` parameter be json. |
| `download`    | No    | The presence of this parameter results in a `content-disposition` header so that browsers attempt to download the data rather than display it inline. |

### Range requests

If a `query-s3-select` is not specified, the `range` HTTP header can be passed to select a byte-range of the dataset. See **[HTTP Range Requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests)** for more details.

### Example without a query

##### Request
```js
curl --get https://data.api.trade.gov.uk/v1/datasets/uk-tariff-2021-01-01/versions/v2.1.0/data \
    --data-urlencode "format=json"
```

##### Response (excerpt)
```json
Status: 200 OK
{
    "commodities": [
        {"id": "1", "commodity__code": "0100000000", ...
        ...
    ],
    ...
}
```

### Example with a query

##### Request
```js
curl --get https://data.api.trade.gov.uk/v1/datasets/uk-tariff-2021-01-01/versions/v2.1.0/data \
    --data-urlencode "format=json" \
    --data-urlencode "query-s3-select=
        SELECT
            c.commodity__code, c.commodity__suffix, c.commodity__description
        FROM
            S3Object[*].commodities[*] c
        WHERE
            c.commodity__code = '0101210000'
        LIMIT
            1
    "
```

##### Response
```json
Status: 200 OK
{
    "rows":[
      {"commodity__code": "0101210000", "commodity__suffix": "10", "commodity__description": "Horses"}
    ]
}
```