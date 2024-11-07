---
order: 8
title: GET data in a report
description: The data of a single report in a dataset version can be accessed using this endpoint.
---


```curl
GET /v1/datasets/{dataset_id}/versions/{version_id}/reports/{report_id}/data
```

### Query string parameters
| Syntax    | Required | Description |
| --------- | ----------- | ----------- |
| `format`    | Yes    | 	The requested output format. This must be `csv` or `ods` |
| `query-s3-select	`    | No    | A query using the ***[S3 Select query language](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-select-sql-reference-select.html)***, e.g. `SELECT * FROM S3Object` |
| `query-simple	`    | No    | Enables a "simple" query mode to specify columns to retrieve, and filter rows using exact matching. <br><br> In simple mode, the value of each `_columns` parameter is a single column to include in the output.This parameter can be passed multiple times to include multiple columns. <br> <br>Filtering on rows can then be performed by passing key value pairs `column=value`. The output includes only those rows where column `column` equals `value`.|
| `download`    | No    | The presence of this parameter results in a `content-disposition` header so that browsers attempt to download the data rather than display it inline. |

### Range requests
If `query-s3-select` and `query-simple` are *not* specified, the `range` HTTP header can be passed to select a byte-range of the report. See ***[HTTP Range Requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests)*** for more details.

### Example without a query

##### Request
```curl
curl --get https://data.api.trade.gov.uk/v1/datasets/uk-trade-quotas/versions/v1.0.0/reports/quotas-including-current-volumes/data \
    --data-urlencode "format=csv"
```

##### Response (excerpt)
```json
Status: 200 OK
"quota_definition__sid","quota__order_number","quota__geographical_areas","quota__headings","quota__commodities","quota__measurement_unit","quota__monetary_unit","quota_definition__description","quota_definition__validity_start_date","quota_definition__validity_end_date","quota_definition__suspension_periods","quota_definition__blocking_periods","quota_definition__status","quota_definition__last_allocation_date","quota_definition__initial_volume","quota_definition__balance","quota_definition__fill_rate"
20815,50006,"ERGA OMNES","0302 – Fish, fresh or chilled, excluding fish fillets and other fish meat of heading|0304|0303 – Fish, frozen, excluding fish fillets and other fish meat of heading 0304|0304 – Fish fillets and other fish meat (whether or not minced), fresh, chilled or frozen","0302410000|0303510000|0304595000|0304599010|0304992300","Kilogram (kg)","#NA","#NA","2021-01-01","2021-02-14","#NA","#NA","Closed","2021-01-28",2022900,2022900.0,0.0
20814,50006,"ERGA OMNES","0302 – Fish, fresh or chilled, excluding fish fillets and other fish meat of heading|0304|0303 – Fish, frozen, excluding fish fillets and other fish meat of heading 0304|0304 – Fish fillets and other fish meat (whether or not minced), fresh, chilled or frozen","0302410000|0303510000|0304595000|0304599010|0304992300","Kilogram (kg)","#NA","#NA","2021-06-16","2022-02-14","#NA","#NA","Open","#NA",2112000,2112000.0,0.0

```

### Example with an S3 Select query

##### Request
```curl
curl --get https://data.api.trade.gov.uk/v1/datasets/uk-trade-quotas/versions/v1.0.0/reports/quotas-including-current-volumes/data \
    --data-urlencode "format=csv" \
    --data-urlencode "query-s3-select=
        SELECT
            q.quota__order_number, q.quota_definition__validity_start_date, q.quota_definition__status, q.quota_definition__initial_volume, q.quota_definition__balance
        FROM
            S3Object q
        WHERE
            q.quota__commodities LIKE '%0203195900%'
    "
```

##### Response
```json
Status: 200 OK
50123,2021-01-01,Exhausted,2000,0.0
50123,2021-07-01,Open,1349000,1349000.0
51921,2021-01-01,Open,1632000,1632000.0
51944,2021-01-01,Critical,167000,147000.0
57220,2021-01-01,Open,494000,494000.0
59282,2021-01-01,Open,4838000,4838000.0
```

### Example with a simple query
```curl
curl --get https://data.api.trade.gov.uk/v1/datasets/uk-trade-quotas/versions/v1.0.0/reports/quotas-including-current-volumes/data \
    --data-urlencode "format=csv" \
    --data-urlencode "query-simple" \
    --data-urlencode "quota__order_number=50123" \
    --data-urlencode "_columns=quota__order_number" \
    --data-urlencode "_columns=quota_definition__validity_start_date" \
    --data-urlencode "_columns=quota_definition__status" \
    --data-urlencode "_columns=quota_definition__initial_volume" \
    --data-urlencode "_columns=quota_definition__balance"
```

##### Response
```json
Status: 200 OK
quota__order_number,quota_definition__validity_start_date,quota_definition__status,quota_definition__initial_volume,quota_definition__balance
50123,2021-01-01,Exhausted,2000,0.0
50123,2021-07-01,Open,1349000,1349000.0
```