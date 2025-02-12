// routes/couponRoutes.js

const express = require('express');
const router = express.Router();
const { body, param, query } = require('express-validator');
const couponController = require('../controllers/couponController');
const authMiddleware = require('../middleware/authMiddleware');
const adminMiddleware = require('../middleware/adminMiddleware');
const validateMiddleware = require('../middleware/validateMiddleware');
const USER_ROLES = require('../constants/userRoles');

// Validation rules for creating a coupon
const createCouponValidation = [
  body('code')
    .isString()
    .isLength({ min: 3 })
    .withMessage('Code must be at least 3 characters long'),
  body('discount')
    .isFloat({ gt: 0 })
    .withMessage('Discount must be a positive number'),
  body('discountType')
    .isIn(['percentage', 'fixed'])
    .withMessage('Invalid discount type'),
  body('expirationDate')
    .isISO8601()
    .toDate()
    .withMessage('Invalid expiration date'),
  body('maxUses')
    .optional()
    .isInt({ min: 1 })
    .withMessage('maxUses must be at least 1'),
];

// Validation rules for updating a coupon
const updateCouponValidation = [
  body('discount')
    .optional()
    .isFloat({ gt: 0 })
    .withMessage('Discount must be a positive number'),
  body('discountType')
    .optional()
    .isIn(['percentage', 'fixed'])
    .withMessage('Invalid discount type'),
  body('expirationDate')
    .optional()
    .isISO8601()
    .toDate()
    .withMessage('Invalid expiration date'),
  body('maxUses')
    .optional()
    .isInt({ min: 1 })
    .withMessage('maxUses must be at least 1'),
  body('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive must be a boolean'),
];

// Validation rules for deactivating or activating a coupon
const toggleCouponValidation = [
  param('id')
    .isMongoId()
    .withMessage('Invalid coupon ID'),
  validateMiddleware,
];

// Validation rules for applying a coupon
const applyCouponValidation = [
  body('code')
    .isString()
    .withMessage('Coupon code is required'),
  body('orderTotal')
    .isFloat({ gt: 0 })
    .withMessage('Order total must be a positive number'),
  validateMiddleware,
];

// Routes

// Create a new coupon
router.post(
  '/',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  createCouponValidation,
  validateMiddleware,
  couponController.createCoupon
);

// Get all coupons with optional filters
router.get(
  '/',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  [
    query('expired')
      .optional()
      .isBoolean()
      .withMessage('expired must be a boolean'),
    query('active')
      .optional()
      .isBoolean()
      .withMessage('active must be a boolean'),
    validateMiddleware,
  ],
  couponController.getAllCoupons
);

// Get coupon by ID
router.get(
  '/:id',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid coupon ID'),
    validateMiddleware,
  ],
  couponController.getCouponById
);

// Update a coupon by ID
router.put(
  '/:id',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid coupon ID'),
    updateCouponValidation,
    validateMiddleware,
  ],
  couponController.updateCoupon
);

// Delete (permanently remove) a coupon by ID
router.delete(
  '/:id',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  [
    param('id')
      .isMongoId()
      .withMessage('Invalid coupon ID'),
    validateMiddleware,
  ],
  couponController.deleteCoupon
);

// Deactivate a coupon by ID
router.post(
  '/:id/deactivate',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  toggleCouponValidation,
  couponController.deactivateCoupon
);

// Activate a coupon by ID
router.post(
  '/:id/activate',
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  toggleCouponValidation,
  couponController.activateCoupon
);

// Apply a coupon to an order
router.post(
  '/apply',
  authMiddleware,
  applyCouponValidation,
  couponController.applyCoupon
);

module.exports = router;
