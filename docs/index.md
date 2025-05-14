---
homepage: true
layout: product
title: Data API
# image:
#   src: /assets/placeholder.png
#   alt: Data API bar charts
description: The Department for Business and Trade Data API supplies datasets via ***[HTTPS](https://en.wikipedia.org/wiki/HTTPS)*** without authentication. 
startButton: 
  text: Get started
  href: "start"
---
- Datasets are versioned
- Each dataset version is immutable
- Each dataset version has one or more tables
- Each dataset version has zero or more reports - a report contains filtered or aggregated table data
- Metadata for each dataset version is available as ***[HTML](https://en.wikipedia.org/wiki/HTML)*** or ***[CSVW](https://www.w3.org/TR/tabular-data-primer/)*** (CSV on the Web)
- Data can be filtered or aggregated using the ***[S3 Select query language](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-select-sql-reference-select.html)***
- Data is supplied as ***[SQLite](https://www.sqlite.org/)***, ***[JSON](https://en.wikipedia.org/wiki/JSON)***, ***[CSV](https://www.gov.uk/government/publications/recommended-open-standards-for-government/tabular-data-standard)***, or ***[ODS (OpenDocument Spreadsheet)](https://www.gov.uk/guidance/using-open-document-formats-odf-in-your-organisation)***.
<br>
The source code for the Data API is available in its ***[GitHub repository](https://github.com/uktrade/public-data-api)***.

<div class="govuk-grid-row">
{% for item in collections.homepage %}
  <section class="govuk-grid-column-one-third-from-desktop govuk-!-margin-bottom-8">
    <h2 class="govuk-heading-m govuk-!-margin-bottom-2">
      <a class="govuk-link govuk-link--no-visited-state" href="{{ item.url }}">{{ item.data.title | smart }}</a>
    </h2>
    <p class="govuk-body">{{ item.data.description | markdown("inline") }}</p>
  </section>
{% endfor %}
  <section class="govuk-grid-column-full">
    <hr class="govuk-section-break govuk-section-break--visible govuk-section-break--xl govuk-!-margin-top-0">
    <h2 class="govuk-heading-m">Contribute</h2>
    <p class="govuk-body">The project repository is public and we welcome contributions from anyone.</p>
    <p class="govuk-body"><a class="govuk-link govuk-link--no-visited-state" href="{{ pkg.repository.url | replace(".git", "") }}">View this project on GitHub</a></p>
  </section>
</div>
