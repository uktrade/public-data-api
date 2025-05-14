const govukEleventyPlugin = require("@x-govuk/govuk-eleventy-plugin");

module.exports = function (eleventyConfig) {
  // Register the plugin
  eleventyConfig.addPlugin(govukEleventyPlugin, {
    header: {
      search: {
        indexPath: "/docs/search.json",
        sitemapPath: "/sitemap",
      },
    },
    footer: {
      meta: {
        items: [
          {
            href: "/sitemap/",
            text: "Sitemap",
          },
        ],
      },
    },
  });

  //adds collection to use
  eleventyConfig.addCollection("homepage", (collection) =>
    collection
      .getFilteredByGlob([
        "docs/baseurl.md",
        "docs/versioning.md",
        "docs/reports.md",
        "docs/paramenters.md",
        "docs/endpoints.md",
        "docs/security.md",
        "docs/support.md",
        "docs/accessibility.md",
      ])
      .sort((a, b) => (a.data.order || 0) - (b.data.order || 0))
  );

  eleventyConfig.addCollection("endpoints", (collection) =>
    collection
      .getFilteredByGlob(["docs/endpoints/*.md"])
      .sort((a, b) => (a.data.order || 0) - (b.data.order || 0))
  );

  return {
    header: {
      productName: "Public data API",
    },
    dataTemplateEngine: "njk",
    htmlTemplateEngine: "njk",
    markdownTemplateEngine: "njk",
    dir: {
      // Use layouts from the plugin
      input: "docs",
      layouts: "../node_modules/@x-govuk/govuk-eleventy-plugin/layouts",
    },
  };
};
