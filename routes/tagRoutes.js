// routes/tagRoutes.js

const express = require('express');
const router = express.Router();
const { body, param, query } = require('express-validator');
const tagController = require('../controllers/tagController');
const authMiddleware = require('../middleware/authMiddleware');
const adminMiddleware = require('../middleware/adminMiddleware');
const validateMiddleware = require('../middleware/validateMiddleware');
const USER_ROLES = require('../constants/userRoles');

// Validation rules for creating a tag
const createTagValidation = [
  body('name')
    .isString()
    .isLength({ min: 2, max: 50 })
    .withMessage('Tag name must be between 2 and 50 characters long')
    .matches(/^[a-zA-Z0-9-_ ]+$/)
    .withMessage('Tag name can only contain alphanumeric characters, dashes, underscores, and spaces'),
  body('description')
    .optional()
    .isString()
    .isLength({ max: 200 })
    .withMessage('Description cannot exceed 200 characters'),
  validateMiddleware,
];

// Validation rules for updating a tag
const updateTagValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid Tag ID'),
  body('name')
    .optional()
    .isString()
    .isLength({ min: 2, max: 50 })
    .withMessage('Tag name must be between 2 and 50 characters long')
    .matches(/^[a-zA-Z0-9-_ ]+$/)
    .withMessage('Tag name can only contain alphanumeric characters, dashes, underscores, and spaces'),
  body('description')
    .optional()
    .isString()
    .isLength({ max: 200 })
    .withMessage('Description cannot exceed 200 characters'),
  body('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive must be a boolean'),
  validateMiddleware,
];

// Validation rules for activating/deactivating a tag
const toggleTagValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid Tag ID'),
  validateMiddleware,
];

// Validation rules for fetching tags with filters
const fetchTagsValidation = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('search')
    .optional()
    .isString()
    .withMessage('Search query must be a string'),
  query('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive must be a boolean'),
  query('sortField')
    .optional()
    .isString()
    .withMessage('Sort field must be a string'),
  query('sortOrder')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('Sort order must be either "asc" or "desc"'),
  validateMiddleware,
];

// Routes

// Create a new tag
router.post(
  '/',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  createTagValidation,
  tagController.createTag
);

// Get all tags with optional filters
router.get(
  '/',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  fetchTagsValidation,
  tagController.getAllTags
);

// Get a single tag by ID
router.get(
  '/:id',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid Tag ID'),
    validateMiddleware,
  ],
  tagController.getTagById
);

// Update a tag by ID
router.put(
  '/:id',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  updateTagValidation,
  tagController.updateTag
);

// Soft delete (deactivate) a tag by ID
router.delete(
  '/:id',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  toggleTagValidation,
  tagController.deleteTag
);

router.delete(
  '/:id/permanent',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid Tag ID'),
    validateMiddleware,
  ],
  tagController.permanentDeleteTag
);


// Activate a tag by ID
router.post(
  '/:id/activate',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  toggleTagValidation,
  tagController.activateTag
);

// Additional routes (e.g., bulk operations) can be added here

module.exports = router;
