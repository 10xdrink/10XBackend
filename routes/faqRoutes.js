const express = require('express');
const router = express.Router();
const { body, param } = require('express-validator');
const faqController = require('../controllers/faqController');
const authMiddleware = require('../middleware/authMiddleware');
const adminMiddleware = require('../middleware/adminMiddleware');
const validateMiddleware = require('../middleware/validateMiddleware');
const USER_ROLES = require('../constants/userRoles');

// Validation rules for creating an FAQ
const createFAQValidation = [
  body('question')
    .isString()
    .withMessage('Question must be a string')
    .isLength({ min: 5 })
    .withMessage('Question must be at least 5 characters long'),
  body('answer')
    .isString()
    .withMessage('Answer must be a string')
    .isLength({ min: 10 })
    .withMessage('Answer must be at least 10 characters long'),
];

// Validation rules for updating an FAQ
const updateFAQValidation = [
  body('question')
    .optional()
    .isString()
    .withMessage('Question must be a string')
    .isLength({ min: 5 })
    .withMessage('Question must be at least 5 characters long'),
  body('answer')
    .optional()
    .isString()
    .withMessage('Answer must be a string')
    .isLength({ min: 10 })
    .withMessage('Answer must be at least 10 characters long'),
];

// Routes

// Create a new FAQ
router.post(
  '/',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.CONTENT_MANAGER]),
  createFAQValidation,
  validateMiddleware,
  faqController.createFAQ
);

// Get all FAQs
router.get(
  '/',
  faqController.getAllFAQs
);

// Get FAQ by ID
router.get(
  '/:id',
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid FAQ ID'),
    validateMiddleware,
  ],
  faqController.getFAQById
);

// Update FAQ
router.put(
  '/:id',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.CONTENT_MANAGER]),
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid FAQ ID'),
    updateFAQValidation,
    validateMiddleware,
  ],
  faqController.updateFAQ
);

// Delete FAQ
router.delete(
  '/:id',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.CONTENT_MANAGER]),
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid FAQ ID'),
    validateMiddleware,
  ],
  faqController.deleteFAQ
);

module.exports = router;
