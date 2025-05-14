---
order: 4
title: GET list of reports in a version
description: The list of reports of each dataset version can be accessed using this endpoint.
---

```js
GET /v1/datasets/{dataset_id}/versions/{version_id}/reports
```

### Query string parameters
| Syntax    | Required | Description |
| --------- | ----------- | ----------- |
| `format`    | Yes    | 	The requested output format. In all cases, this must be `json` |

### Example

##### Request
```js
curl --get https://data.api.trade.gov.uk/v1/datasets/uk-trade-quotas/versions/v1.0.0/reports \
    --data-urlencode "format=json"
```

##### Response
```json
Status: 200 OK
{
    "reports": [
        {"id": "quotas-including-current-volumes"}
    ]
}
```