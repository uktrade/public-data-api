---
title: Common Parameters
layout: sub-navigation
order: 5
description: Parameters Description
---
Several URL parameters are applicable to multiple API endpoints.

| Name    | Description |
| --------- | ----------- |
| `dataset_id`       | 	A human-readable identifier of a dataset, e.g. `uk-tariff-2021-01-01` |
| `version_id`       | 	A version identifier in the format `vX.Y.Z`, where `X.Y.Z` is the ***[Semver 2.0](https://semver.org/)*** version of the dataset, e.g. `v2.1.0` <br><br> or <br><br>A version in the format `vX.Y`. In this case, a HTTP 302 redirect is returned to the URL requested, but with `version_id` equal to the latest version of the dataset with major and minor components matching vX.Y <br><br> or <br><br> A version in the format `vX`. In this case, a HTTP 302 redirect is returned to the URL requested, but with version_id equal to the latest version of the dataset with major component matching vX <br><br> or <br><br> The literal `latest`. In this case, a HTTP 302 redirect is returned to the URL requested, but with `version_id` equal to the latest version of the dataset|
| `table_id`       | 	A human-readable identifier of a table, e.g. `commodities` |
| `report_id`       | A human-readable identifier of a report, e.g. `quotas-including-current-volumes` |