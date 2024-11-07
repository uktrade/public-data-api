---
order: 7
title: GET data in a table
description: The data of single table in a dataset version can be accessed using this endpoint.
---

```js
GET /v1/datasets/{dataset_id}/versions/{version_id}/tables/{table_id}/data
```

### Query string parameters
| Syntax    | Required | Description |
| --------- | ----------- | ----------- |
| `format`    | Yes    | 	The requested output format. This must be `sqlite`, `json`, or `ods` |
| `query-s3-select	`    | No    | A query using the ***[S3 Select query language](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-select-sql-reference-select.html)***, e.g. `SELECT * FROM S3Object` |
| `query-simple	`    | No    | Enables a "simple" query mode to specify columns to retrieve, and filter rows using exact matching. </br></br> In simple mode, the value of each `_columns` parameter is a single column to include in the output.This parameter can be passed multiple times to include multiple columns. </br> </br>Filtering on rows can then be performed by passing key value pairs `column=value`. The output includes only those rows where column `column` equals `value`.|
| `download`    | No    | The presence of this parameter results in a `content-disposition` header so that browsers attempt to download the data rather than display it inline. |

### Range requests

If `query-s3-select` and `query-simple` are *not* specified, the `range` HTTP header can be passed to select a byte-range of the table. See ***[HTTP Range Requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests)*** for more details.

### Example without a query

##### Request
```js
curl --get https://data.api.trade.gov.uk/v1/datasets/uk-tariff-2021-01-01/versions/v2.1.0/tables/commodities/data \
    --data-urlencode "format=csv"
```

##### Response
```json
Status: 200 OK
"id","commodity__sid","commodity__code","commodity__suffix","commodity__description","commodity__validity_start","commodity__validity_end","parent__sid","parent__code","parent__suffix"
"1","27623","0100000000","80","LIVE ANIMALS","1971-12-31","#NA","#NA","#NA","#NA"
"2","27624","0101000000","80","Live horses, asses, mules and hinnies","1972-01-01","#NA","27623","0100000000","80"
"3","93797","0101210000","10","Horses","2012-01-01","#NA","27624","0101000000","80".
}
```

### Example with an S3 Select query

##### Request
```js
curl --get https://data.api.trade.gov.uk/v1/datasets/uk-tariff-2021-01-01/versions/v2.1.0/tables/commodities/data \
    --data-urlencode "format=csv" \
    --data-urlencode "query-s3-select=
        SELECT
            c.commodity__code, c.commodity__suffix, c.commodity__description
        FROM
            S3Object c
        WHERE
            c.commodity__code = '0101210000'
        LIMIT
            1
    "
```

##### Response
```json
Status: 200 OK
0101210000,10,Horses
```

### Example with a simple query
```js
curl --get https://data.api.trade.gov.uk/v1/datasets/uk-tariff-2021-01-01/versions/v2.1.0/tables/commodities/data \
    --data-urlencode "format=csv" \
    --data-urlencode "query-simple" \
    --data-urlencode "commodity__code=0101210000" \
    --data-urlencode "_columns=commodity__code" \
    --data-urlencode "_columns=commodity__suffix" \
    --data-urlencode "_columns=commodity__description"
```

##### Response
```json
Status: 200 OK
commodity__code,commodity__suffix,commodity__description
0101210000,10,Horses
0101210000,80,Pure-bred breeding animals
```