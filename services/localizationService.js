// services/localizationService.js

const LocalizationSettings = require('../models/LocalizationSettings');
const logger = require('../utils/logger');

/**
 * Retrieve localization settings for a specific region.
 * @param {string} region - The identifier for the region (e.g., 'US', 'IN', 'FR').
 * @returns {Promise<Object>} - The localization settings for the region.
 */
const getLocalizationSettingsForRegion = async (region) => {
  try {
    const settings = await LocalizationSettings.findOne({ region });
    if (!settings) {
      logger.warn(`No localization settings found for region: ${region}`);
      return null;
    }
    return settings;
  } catch (error) {
    logger.error(`Failed to retrieve localization settings for region ${region}: ${error.message}`);
    throw new Error('Error retrieving localization settings');
  }
};

/**
 * Update localization settings for a specific region.
 * @param {string} region - The identifier for the region.
 * @param {Object} updates - The localization updates, e.g., { currency, language, dateFormat }.
 * @returns {Promise<Object>} - The updated localization settings.
 */
const updateLocalizationSettingsForRegion = async (region, updates) => {
  try {
    const options = { new: true, upsert: true };
    const updatedSettings = await LocalizationSettings.findOneAndUpdate({ region }, updates, options);

    logger.info(`Localization settings updated for region: ${region}`);
    return updatedSettings;
  } catch (error) {
    logger.error(`Failed to update localization settings for region ${region}: ${error.message}`);
    throw new Error('Error updating localization settings');
  }
};

/**
 * Generate default localization settings for regions without specific configurations.
 * @param {Array<string>} regions - List of region identifiers.
 * @returns {Promise<void>}
 */
const generateDefaultLocalizationSettings = async (regions) => {
  try {
    const defaultSettings = {
      currency: 'USD',
      language: 'en',
      dateFormat: 'MM/DD/YYYY',
    };

    for (const region of regions) {
      const exists = await LocalizationSettings.exists({ region });
      if (!exists) {
        await LocalizationSettings.create({ region, ...defaultSettings });
        logger.info(`Default localization settings created for region: ${region}`);
      }
    }
  } catch (error) {
    logger.error(`Failed to generate default localization settings: ${error.message}`);
    throw new Error('Error generating default localization settings');
  }
};

module.exports = {
  getLocalizationSettingsForRegion,
  updateLocalizationSettingsForRegion,
  generateDefaultLocalizationSettings,
};
