---
order: 1
title: GET list of datasets
description: The list of all datasets available in the Data API can be accessed using this endpoint.
---

```js
GET /v1/datasets
```

### Query string parameters
| Syntax    | Required | Description |
| --------- | ----------- | ----------- |
| `format`    | Yes    | 	The requested output format. In all cases, this must be `json` |

### Example

##### Request
```js
curl --get https://data.api.trade.gov.uk/v1/datasets \
    --data-urlencode "format=json"
```

##### Response

```json
Status: 200 OK
{
    "datasets": [
        {"id": "market-barriers"}, {"id": "uk-tariff-2021-01-01"}
    ]
}
```