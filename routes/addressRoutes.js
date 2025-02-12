// routes/addressRoutes.js

const express = require('express');
const router = express.Router();
const { body, param } = require('express-validator');
const addressController = require('../controllers/addressController');
const authMiddleware = require('../middleware/authMiddleware');
const validateMiddleware = require('../middleware/validateMiddleware');

// Validation rules for address
const addressValidation = [
  body('street')
    .notEmpty()
    .withMessage('Street address is required'),
  body('city')
    .notEmpty()
    .withMessage('City is required'),
  body('state')
    .notEmpty()
    .withMessage('State is required'),
  body('zip')
    .isLength({ min: 3, max: 10 })
    .withMessage('ZIP code must be between 3 and 10 characters')
    .matches(/^[A-Za-z0-9\s-]+$/)
    .withMessage('ZIP code can only contain letters, numbers, spaces, and hyphens'),
  body('country')
    .notEmpty()
    .withMessage('Country is required'),
];

// Get all addresses
router.get(
  '/',
  authMiddleware,
  addressController.getAddresses
);

// Add a new address
router.post(
  '/',
  authMiddleware,
  addressValidation,
  validateMiddleware,
  addressController.addAddress
);

// Update an address
router.put(
  '/:id',
  authMiddleware,
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid address ID'),
    // Optional fields to update
    body('street')
      .optional()
      .notEmpty()
      .withMessage('Street address cannot be empty'),
    body('city')
      .optional()
      .notEmpty()
      .withMessage('City cannot be empty'),
    body('state')
      .optional()
      .notEmpty()
      .withMessage('State cannot be empty'),
    body('zip')
      .optional()
      .isLength({ min: 3, max: 10 })
      .withMessage('ZIP code must be between 3 and 10 characters')
      .matches(/^[A-Za-z0-9\s-]+$/)
      .withMessage('ZIP code can only contain letters, numbers, spaces, and hyphens'),
    body('country')
      .optional()
      .notEmpty()
      .withMessage('Country cannot be empty'),
  ],
  validateMiddleware,
  addressController.updateAddress
);

// Delete an address
router.delete(
  '/:id',
  authMiddleware,
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid address ID'),
  ],
  validateMiddleware,
  addressController.deleteAddress
);

module.exports = router;
