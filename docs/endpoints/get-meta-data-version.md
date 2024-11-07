---
order: 5
title: GET metadata of a version
description: The metadata of a dataset version can be accessed using this endpoint.
---

```js
GET /v1/datasets/{dataset_id}/versions/{version_id}/metadata
```

### Query string parameters
| Syntax    | Required | Description |
| --------- | ----------- | ----------- |
| `format`    | Yes    | 	The requested output format. This must be `csvw` or `html`|
| `download`    | No    | 		The presence of this parameter results in a `content-disposition` header so that browsers attempt to download the metadata rather than display it inline |

### Example requesting CSVW

##### Request
```js
curl --get https://data.api.trade.gov.uk/v1/datasets/uk-tariff-2021-01-01/versions/v2.1.0/metadata \
    --data-urlencode "format=csvw"
```

##### Response (excerpt)
```json
Status: 200 OK
{
  "@context": [
    "http://www.w3.org/ns/csvw",
    {"dit": "http://data.api.trade.gov.uk/"}
  ],
  "dc:title": "Tariffs to trade with the UK from 1 January 2021",
  ...
  "tables": [{
    "id": "commodities",
    ...
    "tableSchema": {
      "columns": [{
        "name": "id",
        ...
      }, ...]
    }
  }, ...]
}
```