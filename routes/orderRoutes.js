// routes/orderRoutes.js

const express = require('express');
const router = express.Router();
const { body, param, query } = require('express-validator');
const orderController = require('../controllers/orderController');
const authMiddleware = require('../middleware/authMiddleware');
const adminMiddleware = require('../middleware/adminMiddleware');
const validateMiddleware = require('../middleware/validateMiddleware');
const USER_ROLES = require('../constants/userRoles');
const Joi = require('joi'); // Ensure Joi is installed: npm install joi

// Validation rules for creating an order
const createOrderValidation = [
  body('items')
    .isArray({ min: 1 })
    .withMessage('Items must be a non-empty array'),
  body('items.*.product')
    .isMongoId()
    .withMessage('Invalid product ID'),
  body('items.*.quantity')
    .isInt({ min: 1 })
    .withMessage('Quantity must be at least 1'),
  body('items.*.variant')
    .isString()
    .withMessage('Variant must be a string'),
  body('items.*.packaging')
    .isString()
    .withMessage('Packaging must be a string'),
  body('shippingAddress.street')
    .notEmpty()
    .withMessage('Street address is required'),
  body('shippingAddress.city')
    .notEmpty()
    .withMessage('City is required'),
  body('shippingAddress.state')
    .notEmpty()
    .withMessage('State is required'),
  body('shippingAddress.zip')
    .isLength({ min: 3, max: 10 })
    .withMessage('ZIP code must be between 3 and 10 characters')
    .matches(/^[A-Za-z0-9\s-]+$/)
    .withMessage('ZIP code can only contain letters, numbers, spaces, and hyphens'),
  body('shippingAddress.country')
    .notEmpty()
    .withMessage('Country is required'),
  body('billingAddress.street')
    .notEmpty()
    .withMessage('Billing street address is required'),
  body('billingAddress.city')
    .notEmpty()
    .withMessage('Billing city is required'),
  body('billingAddress.state')
    .notEmpty()
    .withMessage('Billing state is required'),
  body('billingAddress.zip')
    .isLength({ min: 3, max: 10 })
    .withMessage('Billing ZIP code must be between 3 and 10 characters')
    .matches(/^[A-Za-z0-9\s-]+$/)
    .withMessage('Billing ZIP code can only contain letters, numbers, spaces, and hyphens'),
  body('billingAddress.country')
    .notEmpty()
    .withMessage('Billing country is required'),
  body('paymentMethod')
    .isString()
    .withMessage('Payment method is required'),
  // Optional: Add couponCode validations if needed
];

// Validation rules for updating order status
const updateOrderStatusValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid order ID'),
  body('status')
    .isIn([
      'pending',
      'processing',
      'shipped',
      'delivered',
      'cancelled',
      'refunded',
    ])
    .withMessage('Invalid order status'),
];

// Validation rules for cancelling an order
const cancelOrderValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid order ID'),
  body('reason')
    .optional()
    .isString()
    .withMessage('Reason must be a string'),
];

// Validation rules for getting all orders (Admin)
const getAllOrdersValidation = [
  query('status')
    .optional()
    .isIn([
      'pending',
      'processing',
      'shipped',
      'delivered',
      'cancelled',
      'refunded',
    ])
    .withMessage('Invalid status'),
  query('dateFrom')
    .optional()
    .isISO8601()
    .toDate()
    .withMessage('Invalid dateFrom'),
  query('dateTo')
    .optional()
    .isISO8601()
    .toDate()
    .withMessage('Invalid dateTo'),
  query('customer')
    .optional()
    .isMongoId()
    .withMessage('Invalid customer ID'),
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('page must be at least 1'),
  query('limit')
    .optional()
    .isInt({ min: 1 })
    .withMessage('limit must be at least 1'),
];

// Validation rules for getting authenticated user's orders
const getMyOrdersValidation = [
  query('status')
    .optional()
    .isIn(['pending', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'])
    .withMessage('Invalid status'),
  query('dateFrom')
    .optional()
    .isISO8601()
    .toDate()
    .withMessage('Invalid dateFrom'),
  query('dateTo')
    .optional()
    .isISO8601()
    .toDate()
    .withMessage('Invalid dateTo'),
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be at least 1'),
  query('limit')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Limit must be at least 1'),
];

// Validation rules for updating tracking details
const updateTrackingValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid order ID'),
  body('trackingId')
    .isString()
    .withMessage('Tracking ID must be a string')
    .notEmpty()
    .withMessage('Tracking ID is required'),
  body('carrier')
    .isString()
    .withMessage('Carrier must be a string')
    .notEmpty()
    .withMessage('Carrier is required'),
];

// Validation rules for refunding an order
const refundOrderValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid order ID'),
  body('amount')
    .isFloat({ min: 0.01 })
    .withMessage('Refund amount must be at least 0.01'),
  body('reason')
    .optional()
    .isString()
    .withMessage('Reason must be a string'),
];

// Validation rules for returning an order
const returnOrderValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid order ID'),
  body('items')
    .isArray({ min: 1 })
    .withMessage('Items must be a non-empty array'),
  body('items.*.productId')
    .isMongoId()
    .withMessage('Invalid product ID'),
  body('items.*.quantity')
    .isInt({ min: 1 })
    .withMessage('Quantity must be at least 1'),
  body('reason')
    .optional()
    .isString()
    .withMessage('Reason must be a string'),
];

// Validation rules for bulk updating orders
const bulkUpdateOrdersValidation = [
  body('orderIds')
    .isArray({ min: 1 })
    .withMessage('orderIds must be a non-empty array'),
  body('orderIds.*')
    .isMongoId()
    .withMessage('Each orderId must be a valid Mongo ID'),
  body('status')
    .isIn(['pending', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'])
    .withMessage('Invalid order status'),
];

// Validation rules for fetching cached metrics
const getMetricsCacheValidation = [
  query('dateFrom')
    .optional()
    .isISO8601()
    .toDate()
    .withMessage('Invalid dateFrom'),
  query('dateTo')
    .optional()
    .isISO8601()
    .toDate()
    .withMessage('Invalid dateTo'),
];

// Routes

// Create a new order
router.post(
  '/',
  authMiddleware,
  createOrderValidation,
  validateMiddleware,
  orderController.createOrder
);

// Get authenticated user's orders
router.get(
  '/my-orders',
  authMiddleware,
  getMyOrdersValidation,
  validateMiddleware,
  orderController.getMyOrders
);

// Get Order Metrics (Admin)
router.get(
  '/metrics',
  authMiddleware,
  adminMiddleware([
    USER_ROLES.SUPER_ADMIN,
    USER_ROLES.ORDER_MANAGER,
    USER_ROLES.ANALYTICS_VIEWER,
  ]),
  orderController.getOrderMetrics
);

// Get cached order metrics (Admin)
router.get(
  '/metrics-cache',
  authMiddleware,
  adminMiddleware([
    USER_ROLES.SUPER_ADMIN,
    USER_ROLES.ORDER_MANAGER,
    USER_ROLES.ANALYTICS_VIEWER,
  ]),
  getMetricsCacheValidation,
  validateMiddleware,
  orderController.getMetricsCache
);

// Get all orders with filters (Admin)
router.get(
  '/',
  authMiddleware,
  adminMiddleware([
    USER_ROLES.SUPER_ADMIN,
    USER_ROLES.ORDER_MANAGER,
    USER_ROLES.ANALYTICS_VIEWER,
  ]),
  getAllOrdersValidation,
  validateMiddleware,
  orderController.getAllOrders
);

// Get order by ID
router.get(
  '/:id',
  authMiddleware,
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid order ID'),
  ],
  validateMiddleware,
  orderController.getOrderById
);

// Update order status (Admin)
router.put(
  '/:id/status',
  authMiddleware,
  adminMiddleware([
    USER_ROLES.SUPER_ADMIN,
    USER_ROLES.ORDER_MANAGER,
  ]),
  updateOrderStatusValidation,
  validateMiddleware,
  orderController.updateOrderStatus
);

// Cancel an order (Admin)
router.post(
  '/:id/cancel',
  authMiddleware,
  adminMiddleware([
    USER_ROLES.SUPER_ADMIN,
    USER_ROLES.ORDER_MANAGER,
  ]),
  cancelOrderValidation,
  validateMiddleware,
  orderController.cancelOrder
);

// Update tracking details for a shipped order (Admin)
router.put(
  '/:id/tracking',
  authMiddleware,
  adminMiddleware([
    USER_ROLES.SUPER_ADMIN,
    USER_ROLES.ORDER_MANAGER,
  ]),
  updateTrackingValidation,
  validateMiddleware,
  orderController.updateTracking
);

// Request a return for an order (Customer)
router.post(
  '/:id/return',
  authMiddleware,
  returnOrderValidation,
  validateMiddleware,
  orderController.returnOrder
);

// Process a refund for an order (Admin)
router.post(
  '/:id/refund',
  authMiddleware,
  adminMiddleware([
    USER_ROLES.SUPER_ADMIN,
    USER_ROLES.ORDER_MANAGER,
  ]),
  refundOrderValidation,
  validateMiddleware,
  orderController.refundOrder
);

// Bulk update orders (Admin)
router.put(
  '/bulk-update',
  authMiddleware,
  adminMiddleware([
    USER_ROLES.SUPER_ADMIN,
    USER_ROLES.ORDER_MANAGER,
  ]),
  bulkUpdateOrdersValidation,
  validateMiddleware,
  orderController.bulkUpdateOrders
);

module.exports = router;
