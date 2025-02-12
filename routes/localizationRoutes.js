// routes/localizationRoutes.js

const express = require('express');
const router = express.Router();
const { body, param } = require('express-validator');
const localizationController = require('../controllers/localizationController');
const authMiddleware = require('../middleware/authMiddleware');
const adminMiddleware = require('../middleware/adminMiddleware');

// Validation rules
const localizationValidation = [
  body('region').isString().isLength({ min: 2, max: 5 }).withMessage('Region must be a valid code'),
  body('currency').optional().isString().withMessage('Currency must be a string'),
  body('language').optional().isString().withMessage('Language must be a string'),
  body('taxRate').optional().isFloat({ min: 0 }).withMessage('Tax rate must be a positive number'),
];

// Routes

// Get localization settings for a specific region
router.get(
  '/:region',
  [param('region').isString().isLength({ min: 2, max: 5 }).withMessage('Region must be a valid code')],
  localizationController.getLocalizationSettings
);

// Update localization settings for a specific region
router.put(
  '/:region',
  authMiddleware,
  adminMiddleware,
  [param('region').isString().isLength({ min: 2, max: 5 }).withMessage('Region must be a valid code'), ...localizationValidation],
  localizationController.updateLocalizationSettings
);

// Create new localization settings
router.post(
  '/',
  authMiddleware,
  adminMiddleware,
  localizationValidation,
  localizationController.createLocalizationSettings
);

// List all localization settings (for admin use)
router.get(
  '/',
  authMiddleware,
  adminMiddleware,
  localizationController.listAllLocalizationSettings
);

module.exports = router;
