// routes/reportRoutes.js
const express = require('express');
const router = express.Router();
const { query } = require('express-validator');
const reportController = require('../controllers/reportController');
const authMiddleware = require('../middleware/authMiddleware');
const adminMiddleware = require('../middleware/adminMiddleware');
const validateMiddleware = require('../middleware/validateMiddleware');
const USER_ROLES = require('../constants/userRoles');

// Validation rules
const salesSummaryValidation = [];
const topProductsValidation = [
  query('limit').optional().isInt({ min: 1 }).withMessage('limit must be at least 1'),
];
const customerAnalyticsValidation = [];
const exportSalesReportValidation = [
  query('type').isIn(['csv', 'excel']).withMessage('Invalid export type'),
];

// Routes

// Get sales summary
router.get(
  '/sales-summary',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.ANALYTICS_VIEWER]),
  salesSummaryValidation,
  validateMiddleware,
  reportController.getSalesSummary
);

// Get top-selling products
router.get(
  '/top-products',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.ANALYTICS_VIEWER]),
  topProductsValidation,
  validateMiddleware,
  reportController.getTopProducts
);

// Get customer analytics
router.get(
  '/customer-analytics',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.ANALYTICS_VIEWER]),
  customerAnalyticsValidation,
  validateMiddleware,
  reportController.getCustomerAnalytics
);

// Export sales report
router.get(
  '/export',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.ANALYTICS_VIEWER]),
  exportSalesReportValidation,
  validateMiddleware,
  reportController.exportSalesReport
);

module.exports = router;
