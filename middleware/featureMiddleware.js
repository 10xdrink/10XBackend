// middleware/featureMiddleware.js

const Settings = require('../models/Settings');

/**
 * Middleware to check if a specific feature is enabled.
 * @param {string} featureKey - The key of the feature to check in the settings.
 * @returns {Function} - Express middleware function.
 */
const featureMiddleware = (featureKey) => {
  return async (req, res, next) => {
    try {
      // Find the feature setting by key
      const featureSetting = await Settings.findOne({ key: featureKey, isActive: true });

      // If the feature is not enabled, return a 403 Forbidden response
      if (!featureSetting || featureSetting.value !== true) {
        return res.status(403).json({
          success: false,
          message: 'This feature is currently disabled.',
        });
      }

      // If the feature is enabled, proceed to the next middleware
      next();
    } catch (error) {
      console.error('Feature middleware error:', error);
      next(error);
    }
  };
};

module.exports = featureMiddleware;
