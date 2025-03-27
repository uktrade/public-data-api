---
title: Versioning
layout: sub-navigation
order: 3
description: Version Description
---

Datasets are versioned according to a subset of the ***[Semver 2.0](https://semver.org/)*** specification. Each version is of the form X.Y.Z, where X is the major version, Y is the minor version, and Z is the patch version. Each release of a dataset increments the version according to the following rules.

- Patch: incremented when data is added or changed, but the structure of the data is the same.
- Minor: incremented when new fields or tables are added to the data, but existing ones are unchanged.
- Major: incremented when existing fields are removed or change type.