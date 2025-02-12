// routes/paymentRoutes.js

const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const paymentController = require('../controllers/paymentController');
const authMiddleware = require('../middleware/authMiddleware');
const validateMiddleware = require('../middleware/validateMiddleware');

/**
 * @route   POST /api/payments/verify-razorpay
 * @desc    Verify Razorpay payment after user completes payment
 * @access  Private/Customer
 */
const verifyRazorpayValidation = [
  body('orderId').isMongoId().withMessage('Invalid order ID'),
  body('paymentId').notEmpty().withMessage('Payment ID is required'),
  body('signature').notEmpty().withMessage('Signature is required'),
];

router.post(
  '/verify-razorpay',
  authMiddleware,
  verifyRazorpayValidation,
  validateMiddleware,
  paymentController.verifyRazorpayPayment
);

/**
 * @route   POST /api/payments/webhook/razorpay
 * @desc    Handle Razorpay webhook events
 * @access  Public
 */
router.post(
  '/webhook/razorpay',
  express.raw({ type: 'application/json' }), // Razorpay sends raw body
  paymentController.handleRazorpayWebhook
);

/**
 * @route   POST /api/payments/verify-stripe
 * @desc    Verify Stripe payment after user completes payment
 * @access  Private/Customer
 */
const verifyStripeValidation = [
  body('paymentIntentId').notEmpty().withMessage('Payment Intent ID is required'),
  body('orderId').isMongoId().withMessage('Invalid order ID'),
];

router.post(
  '/verify-stripe',
  authMiddleware,
  verifyStripeValidation,
  validateMiddleware,
  paymentController.verifyStripePayment
);

/**
 * @route   POST /api/payments/webhook/stripe
 * @desc    Handle Stripe webhook events
 * @access  Public
 */
router.post(
  '/webhook/stripe',
  express.raw({ type: 'application/json' }), // Stripe sends raw body
  paymentController.handleStripeWebhook
);

/**
 * @route   POST /api/payments/verify-paypal
 * @desc    Verify PayPal payment after user completes payment
 * @access  Private/Customer
 */
const verifyPayPalValidation = [
  body('orderId').isMongoId().withMessage('Invalid order ID'),
  body('paymentId').notEmpty().withMessage('Payment ID is required'),
];

router.post(
  '/verify-paypal',
  authMiddleware,
  verifyPayPalValidation,
  validateMiddleware,
  paymentController.verifyPayPalPayment
);

/**
 * @route   POST /api/payments/webhook/paypal
 * @desc    Handle PayPal webhook events
 * @access  Public
 */
router.post(
  '/webhook/paypal',
  express.raw({ type: 'application/json' }), // PayPal sends raw body
  paymentController.handlePayPalWebhook
);

module.exports = router;
