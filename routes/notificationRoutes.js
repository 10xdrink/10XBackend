// routes/notificationRoutes.js

const express = require('express');
const { body, param } = require('express-validator');
const notificationController = require('../controllers/notificationController');
const authMiddleware = require('../middleware/authMiddleware');
const adminMiddleware = require('../middleware/adminMiddleware');
const validateMiddleware = require('../middleware/validateMiddleware');
const USER_ROLES = require('../constants/userRoles');

const router = express.Router();

// Get all notification templates
router.get(
  '/',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  notificationController.getAllNotificationTemplates
);

// Get a specific notification template by ID
router.get(
  '/:id',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  [
    param('id').isMongoId().withMessage('Invalid notification template ID'),
    validateMiddleware,
  ],
  notificationController.getNotificationTemplateById
);

// Create a new notification template
router.post(
  '/',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  [
    body('title').isString().withMessage('Title is required and must be a string'),
    body('subject').isString().withMessage('Subject is required and must be a string'),
    body('body').isString().withMessage('Body content is required'),
  ],
  validateMiddleware,
  notificationController.createNotificationTemplate
);

// Update an existing notification template
router.put(
  '/:id',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  [
    param('id').isMongoId().withMessage('Invalid notification template ID'),
    body('title').optional().isString().withMessage('Title must be a string'),
    body('subject').optional().isString().withMessage('Subject must be a string'),
    body('body').optional().isString().withMessage('Body content must be a string'),
    validateMiddleware,
  ],
  notificationController.updateNotificationTemplate
);

// Delete a notification template
router.delete(
  '/:id',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  [
    param('id').isMongoId().withMessage('Invalid notification template ID'),
    validateMiddleware,
  ],
  notificationController.deleteNotificationTemplate
);

module.exports = router;
