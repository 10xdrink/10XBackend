// services/seoService.js

const SEOSettings = require('../models/SEOSettings');
const logger = require('../utils/logger');

/**
 * Retrieve SEO settings for a specific page.
 * @param {string} page - The identifier for the page (e.g., 'home', 'product', 'about').
 * @returns {Promise<Object>} - The SEO settings for the page.
 */
const getSEOSettingsForPage = async (page) => {
  try {
    const settings = await SEOSettings.findOne({ page });
    if (!settings) {
      logger.warn(`No SEO settings found for page: ${page}`);
      return null;
    }
    return settings;
  } catch (error) {
    logger.error(`Failed to retrieve SEO settings for page ${page}: ${error.message}`);
    throw new Error('Error retrieving SEO settings');
  }
};

/**
 * Update SEO settings for a specific page.
 * @param {string} page - The identifier for the page.
 * @param {Object} updates - The SEO updates, e.g., { title, metaDescription, keywords, ogImage }.
 * @returns {Promise<Object>} - The updated SEO settings.
 */
const updateSEOSettingsForPage = async (page, updates) => {
  try {
    const options = { new: true, upsert: true };
    const updatedSettings = await SEOSettings.findOneAndUpdate({ page }, updates, options);

    logger.info(`SEO settings updated for page: ${page}`);
    return updatedSettings;
  } catch (error) {
    logger.error(`Failed to update SEO settings for page ${page}: ${error.message}`);
    throw new Error('Error updating SEO settings');
  }
};

/**
 * Generate default SEO settings for pages without specific configurations.
 * @param {Array<string>} pages - List of page identifiers.
 * @returns {Promise<void>}
 */
const generateDefaultSEOSettings = async (pages) => {
  try {
    const defaultSettings = {
      title: 'Default Title',
      metaDescription: 'Default meta description for SEO optimization.',
      keywords: ['default', 'seo', 'website'],
      ogImage: '/images/default-og-image.jpg',
    };

    for (const page of pages) {
      const exists = await SEOSettings.exists({ page });
      if (!exists) {
        await SEOSettings.create({ page, ...defaultSettings });
        logger.info(`Default SEO settings created for page: ${page}`);
      }
    }
  } catch (error) {
    logger.error(`Failed to generate default SEO settings: ${error.message}`);
    throw new Error('Error generating default SEO settings');
  }
};

module.exports = {
  getSEOSettingsForPage,
  updateSEOSettingsForPage,
  generateDefaultSEOSettings,
};
