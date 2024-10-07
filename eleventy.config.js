const govukEleventyPlugin = require("@x-govuk/govuk-eleventy-plugin");

module.exports = function (eleventyConfig) {
  // Register the plugin
  eleventyConfig.addPlugin(govukEleventyPlugin);

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
