// routes/auditRoutes.js

const express = require('express');
const { param } = require('express-validator');
const auditController = require('../controllers/auditController');
const authMiddleware = require('../middleware/authMiddleware');
const adminMiddleware = require('../middleware/adminMiddleware');
const validateMiddleware = require('../middleware/validateMiddleware');
const USER_ROLES = require('../constants/userRoles');

const router = express.Router();

// Get all audit logs with optional filters (e.g., by user, action type)
router.get(
  '/',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  auditController.getAllAuditLogs
);

// Get audit log by ID
router.get(
  '/:id',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  [
    param('id').isMongoId().withMessage('Invalid audit log ID'),
    validateMiddleware,
  ],
  auditController.getAuditLogById
);

// Get audit logs by specific user ID
router.get(
  '/user/:userId',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  [
    param('userId').isMongoId().withMessage('Invalid user ID'),
    validateMiddleware,
  ],
  auditController.getAuditLogsByUser
);

// Get audit logs by action type
router.get(
  '/action/:actionType',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  auditController.getAuditLogsByActionType
);

module.exports = router;
