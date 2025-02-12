// policies/isAdminPolicy.js
const MESSAGES = require('../messages/en');
const asyncHandler = require('express-async-handler');

/**
 * Middleware to check if the authenticated user has an admin role.
 * Roles considered as admin can be expanded based on requirements.
 */
const isAdminPolicy = asyncHandler(async (req, res, next) => {
  const user = req.user;

  if (!user) {
    return res.status(401).json({
      success: false,
      message: MESSAGES.GENERAL.UNAUTHORIZED,
    });
  }

  const adminRoles = ['super-admin', 'order-manager', 'product-manager', 'content-manager', 'marketing-manager'];

  if (adminRoles.includes(user.role)) {
    return next();
  }

  return res.status(403).json({
    success: false,
    message: MESSAGES.GENERAL.FORBIDDEN,
  });
});

module.exports = isAdminPolicy;
