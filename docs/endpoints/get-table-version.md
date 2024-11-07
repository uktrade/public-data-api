---
order: 3
title: GET list of tables in a version
description: The list of tables of each dataset version can be accessed using this endpoint.
---

```js
GET /v1/datasets/{dataset_id}/versions/{version_id}/tables
```

### Query string parameters
| Syntax    | Required | Description |
| --------- | ----------- | ----------- |
| `format`    | Yes    | 	The requested output format. In all cases, this must be `json` |

### Example

##### Request
```js
curl --get https://data.api.trade.gov.uk/v1/datasets/uk-tariff-2021-01-01/versions/v2.1.0/tables \
    --data-urlencode "format=json"
```

##### Response
```json
Status: 200 OK
{
    "tables": [
        {"id": "commodities"},
        {"id": "measures-as-defined"},
        {"id": "measures-on-declarable-commodities"}
    ]
}
```