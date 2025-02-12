// routes/cartRoutes.js
const express = require('express');
const { body } = require('express-validator');
const authMiddleware = require('../middleware/authMiddleware');
const cartController = require('../controllers/CartController');

const router = express.Router();

// Add item to cart
router.post(
  '/add',
  authMiddleware,
  [
    body('productId', 'Product ID is required').notEmpty(),
    body('variant', 'Variant is required').notEmpty(),
    body('packaging', 'Packaging is required').notEmpty(),
    body('quantity', 'Quantity must be a positive integer').isInt({ min: 1 }),
  ],
  cartController.addItemToCart
);

// Update quantity in cart
router.put(
  '/update',
  authMiddleware,
  [
    body('productId', 'Product ID is required').notEmpty(),
    body('variant', 'Variant is required').notEmpty(),
    body('packaging', 'Packaging is required').notEmpty(),
    body('quantity', 'Quantity must be a positive integer').isInt({ min: 1 }),
  ],
  cartController.updateCartItemQuantity
);

// Remove item from cart
router.delete(
  '/remove',
  authMiddleware,
  [
    body('productId', 'Product ID is required').notEmpty(),
    body('variant', 'Variant is required').notEmpty(),
    body('packaging', 'Packaging is required').notEmpty(),
  ],
  cartController.removeItemFromCart
);

// Get cart details
router.get('/', authMiddleware, cartController.getCart);

// Clear cart
router.delete('/clear', authMiddleware, cartController.clearCart);

module.exports = router;