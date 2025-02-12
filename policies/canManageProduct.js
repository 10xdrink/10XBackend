// policies/canManageProduct.js
const Product = require('../models/Product');
const MESSAGES = require('../messages/en');
const asyncHandler = require('express-async-handler');

/**
 * Middleware to check if the authenticated user can manage a specific product.
 * Users with roles 'super-admin' or 'product-manager' can manage any product.
 * Additional logic can be added to verify if the user owns or manages the product.
 */
const canManageProduct = asyncHandler(async (req, res, next) => {
  const user = req.user;
  const productId = req.params.id;

  if (!user) {
    return res.status(401).json({
      success: false,
      message: MESSAGES.GENERAL.UNAUTHORIZED,
    });
  }

  // Roles that are allowed to manage products
  const managerRoles = ['super-admin', 'product-manager'];

  if (managerRoles.includes(user.role)) {
    return next();
  }

  // Optional: Check if the user is the owner or manager of the product
  // Uncomment and modify the following lines if your Product model has an 'owner' or 'manager' field

  /*
  const product = await Product.findById(productId);
  if (!product) {
    return res.status(404).json({
      success: false,
      message: MESSAGES.PRODUCT.PRODUCT_NOT_FOUND,
    });
  }

  if (String(product.owner) === String(user._id)) {
    return next();
  }

  return res.status(403).json({
    success: false,
    message: MESSAGES.GENERAL.FORBIDDEN,
  });
  */

  // If no ownership logic is required, and only specific roles can manage products
  return res.status(403).json({
    success: false,
    message: MESSAGES.GENERAL.FORBIDDEN,
  });
});

module.exports = canManageProduct;
