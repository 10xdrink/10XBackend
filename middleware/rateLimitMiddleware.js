const rateLimit = require('express-rate-limit');
const ERROR_CODES = require('../constants/errorCodes');
const logger = require('../utils/logger');

const rateLimitMiddleware = rateLimit({
  windowMs: 100 * 60 * 1000, // 100 requests per minute
  max: (req, res) => {
    if (req.user && req.user.role === 'super-admin') {
      return 200;
    }
    return 100;
  },
  message: { success: false, message: ERROR_CODES.RATE_LIMIT_EXCEEDED },
  standardHeaders: true,
  legacyHeaders: false,
});

const logRateLimitExceeded = (req, res, next) => {
  if (res.headersSent && res.getHeader('Retry-After')) {
    logger.warn('Rate limit exceeded', {
      ip: req.ip,
      method: req.method,
      route: req.originalUrl,
    });
  }
  next();
};

module.exports = { rateLimitMiddleware, logRateLimitExceeded };
