---
homepage: true
layout: product
title: Data API
# image:
#   src: /assets/placeholder.png
#   alt: Data API bar charts
startButton: 
  text: Get started
  href: "start"

---

<div class="govuk-grid-row">
  {% for item in collections.homepage %}
    <section class="govuk-grid-column-one-third-from-desktop govuk-!-margin-bottom-8">
      <h2 class="govuk-heading-m govuk-!-margin-bottom-2">
        <a class="govuk-link govuk-link--no-visited-state" href="{{ item.url }}">{{ item.data.title | smart }}</a>
      </h2>
      <p class="govuk-body">{{ item.data.description | markdown("inline") }}</p>
    </section>
  {% endfor %}
</div>

