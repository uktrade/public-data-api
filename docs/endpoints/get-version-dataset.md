---
order: 2
title: GET list of versions of a dataset
description: The list of versions of each dataset can be accessed using this endpoint.
---

```js
GET /v1/datasets/{dataset_id}/versions
```

### Query string parameters
| Syntax    | Required | Description |
| --------- | ----------- | ----------- |
| `format`    | Yes    | 	The requested output format. In all cases, this must be `json` |

### Example

##### Request
```js
curl --get https://data.api.trade.gov.uk/v1/datasets/uk-tariff-2021-01-01/versions \
    --data-urlencode "format=json"
```

##### Response

```json
Status: 200 OK
{
    "versions": [
        {"id": "v2.1.2"}, {"id": "v2.1.0"}
    ]
}
```