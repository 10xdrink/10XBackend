const jwt = require('jsonwebtoken');
const User = require('../models/User');
const asyncHandler = require('express-async-handler');
const ERROR_CODES = require('../constants/errorCodes');
const logger = require('../utils/logger');
const sessionService = require('../services/sessionService'); // Assuming session management service

// Middleware to protect routes
const authMiddleware = asyncHandler(async (req, res, next) => {
  let token;

  // Extract token from the Authorization header
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  // If no token, respond with Unauthorized status
  if (!token) {
    logger.warn('No token provided');
    return res.status(401).json({ success: false, message: ERROR_CODES.UNAUTHORIZED });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');

    // If user not found, respond with Not Found status
    if (!user) {
      logger.warn(`User not found for token: ${decoded.id}`);
      return res.status(404).json({ success: false, message: ERROR_CODES.NOT_FOUND });
    }

    // Check if session has expired due to inactivity
    const sessionExpired = sessionService.isSessionExpired(user.lastActivity);
    if (sessionExpired) {
      logger.warn('Session expired due to inactivity');
      return res.status(401).json({ success: false, message: 'Session expired due to inactivity' });
    }

    // Refresh token if it's approaching expiration
    const shouldRefreshToken = sessionService.shouldRefreshToken(decoded.iat);
    if (shouldRefreshToken) {
      const newToken = sessionService.generateAccessToken(user);
      res.setHeader('Authorization', `Bearer ${newToken}`);
      logger.info(`Token refreshed for user: ${user._id}`);
    }

    // Update user's last activity timestamp to keep the session active
    await sessionService.updateLastActivity(user._id);

    // Attach user to request object for route access
    req.user = user;
    next();
  } catch (error) {
    // Handle specific JWT errors
    if (error.name === 'TokenExpiredError') {
      logger.warn('Token expired');
      return res.status(401).json({ success: false, message: 'Token expired' });
    } else if (error.name === 'JsonWebTokenError') {
      logger.error('Invalid token:', error);
      return res.status(401).json({ success: false, message: ERROR_CODES.UNAUTHORIZED });
    }

    // Catch-all for other errors
    logger.error('Auth Middleware Error:', error);
    return res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
});

module.exports = authMiddleware;
