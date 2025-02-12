// routes/blogRoutes.js

const express = require('express');
const router = express.Router();
const { body, param, query } = require('express-validator');
const blogController = require('../controllers/blogController');
const authMiddleware = require('../middleware/authMiddleware');
const adminMiddleware = require('../middleware/adminMiddleware');
const validateMiddleware = require('../middleware/validateMiddleware');
const USER_ROLES = require('../constants/userRoles');
const existingUploadMiddleware = require('../middleware/uploadMiddleware'); // Existing upload middleware
const blogUploadMiddleware = require('../middleware/blogUploadMiddleware'); // New blog upload middleware

// Validation rules for creating a blog post
const createBlogPostValidation = [
  body('title')
    .isString()
    .isLength({ min: 5 })
    .withMessage('Title must be at least 5 characters long'),
  body('content')
    .isString()
    .withMessage('Content is required'),
  body('categories')
    .isArray({ min: 1 })
    .withMessage('Categories must be an array of IDs with at least one category'),
  body('categories.*')
    .isMongoId()
    .withMessage('Invalid category ID'),
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array of IDs'),
  body('tags.*')
    .isMongoId()
    .withMessage('Invalid tag ID'),
  body('status')
    .optional()
    .isIn(['draft', 'published'])
    .withMessage('Invalid status'),
  body('images')
    .optional()
    .isArray()
    .withMessage('Images must be an array of URLs'),
  body('images.*')
    .isURL()
    .withMessage('Invalid image URL'),
];

// Validation rules for updating a blog post
const updateBlogPostValidation = [
  body('title')
    .optional()
    .isString()
    .isLength({ min: 5 })
    .withMessage('Title must be at least 5 characters long'),
  body('content')
    .optional()
    .isString()
    .withMessage('Content must be a string'),
  body('categories')
    .optional()
    .isArray()
    .withMessage('Categories must be an array of IDs'),
  body('categories.*')
    .optional()
    .isMongoId()
    .withMessage('Invalid category ID'),
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array of IDs'),
  body('tags.*')
    .optional()
    .isMongoId()
    .withMessage('Invalid tag ID'),
  body('status')
    .optional()
    .isIn(['draft', 'published'])
    .withMessage('Invalid status'),
  body('images')
    .optional()
    .isArray()
    .withMessage('Images must be an array of URLs'),
  body('images.*')
    .isURL()
    .withMessage('Invalid image URL'),
];

// Routes

// Get a single blog post by slug (specific route first)
router.get(
  '/slug/:slug',
  [
    param('slug')
      .isString()
      .withMessage('Slug must be a string'),
    validateMiddleware,
  ],
  blogController.getBlogPostBySlug
);

// Get a single blog post by ID
router.get(
  '/:id',
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid blog post ID'),
    validateMiddleware,
  ],
  blogController.getBlogPostById
);

// Create a new blog post
router.post(
  '/',
  authMiddleware,
  adminMiddleware([
    USER_ROLES.SUPER_ADMIN,
    USER_ROLES.CONTENT_MANAGER,
  ]),
  createBlogPostValidation,
  validateMiddleware,
  blogController.createBlogPost
);

// Get all blog posts with optional filters
router.get(
  '/',
  [
    query('status')
      .optional()
      .isIn(['draft', 'published'])
      .withMessage('Invalid status'),
    query('category')
      .optional()
      .isString()
      .withMessage('Category must be a string'),
    query('tags')
      .optional()
      .isString()
      .withMessage('Tags must be a comma-separated string of tag names'),
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Page must be at least 1'),
    query('limit')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Limit must be at least 1'),
    validateMiddleware,
  ],
  blogController.getAllBlogPosts
);

// Update an existing blog post
router.put(
  '/:id',
  authMiddleware,
  adminMiddleware([
    USER_ROLES.SUPER_ADMIN,
    USER_ROLES.CONTENT_MANAGER,
  ]),
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid blog post ID'),
    updateBlogPostValidation,
    validateMiddleware,
  ],
  blogController.updateBlogPost
);

// Delete a blog post
router.delete(
  '/:id',
  authMiddleware,
  adminMiddleware([
    USER_ROLES.SUPER_ADMIN,
    USER_ROLES.CONTENT_MANAGER,
  ]),
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid blog post ID'),
    validateMiddleware,
  ],
  blogController.deleteBlogPost
);

// Upload blog post image with the new blog upload middleware
router.post(
  '/upload-image',
  authMiddleware,
  adminMiddleware([
    USER_ROLES.SUPER_ADMIN,
    USER_ROLES.CONTENT_MANAGER,
  ]),
  ...blogUploadMiddleware, // Spread the array to apply both middlewares
  blogController.uploadBlogImage
);

module.exports = router;
