const express = require('express');
const { body, param } = require('express-validator');
const settingsController = require('../controllers/settingsController');
const authMiddleware = require('../middleware/authMiddleware');
const adminMiddleware = require('../middleware/adminMiddleware');
const validateMiddleware = require('../middleware/validateMiddleware');
const USER_ROLES = require('../constants/userRoles');

const router = express.Router();

// Retrieve all settings
router.get(
  '/',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  settingsController.getSettings
);

// Update a specific setting
router.put(
  '/',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  [
    body('key').isString().withMessage('Key is required and must be a string'),
    body('value').exists().withMessage('Value is required'),
  ],
  validateMiddleware,
  settingsController.updateSettings
);

// Get version history for a specific setting
router.get(
  '/history/:key',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  [
    param('key').isString().withMessage('Key parameter is required'),
  ],
  validateMiddleware,
  settingsController.getSettingHistory
);

// Retrieve SEO settings for a specific page
router.get(
  '/seo/:page',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  [
    param('page').isString().withMessage('Page parameter is required'),
  ],
  validateMiddleware,
  settingsController.getSEOSettings
);

// Update SEO settings for a specific page
router.put(
  '/seo/:page',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  [
    param('page').isString().withMessage('Page parameter is required'),
  ],
  validateMiddleware,
  settingsController.updateSEOSettings
);

// Toggle a feature on or off
router.put(
  '/toggle-feature',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  [
    body('featureKey').isString().withMessage('Feature key is required'),
    body('enable').isBoolean().withMessage('Enable must be a boolean'),
  ],
  validateMiddleware,
  settingsController.toggleFeature
);

// Retrieve all notification templates
router.get(
  '/notifications',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  settingsController.getNotificationTemplates
);

// Update a specific notification template
router.put(
  '/notifications/:id',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  [
    param('id').isMongoId().withMessage('Notification template ID is invalid'),
    body('subject').optional().isString().withMessage('Subject must be a string'),
    body('body').optional().isString().withMessage('Body must be a string'),
  ],
  validateMiddleware,
  settingsController.updateNotificationTemplate
);

module.exports = router;
