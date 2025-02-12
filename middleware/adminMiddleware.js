// middleware/adminMiddleware.js

const USER_ROLES = require('../constants/userRoles');
const ERROR_CODES = require('../constants/errorCodes');
const logger = require('../utils/logger');

const adminMiddleware = (requiredRoles = []) => {
  return (req, res, next) => {
    const user = req.user;

    if (!user) {
      logger.warn('Unauthorized access attempt without authentication');
      return res.status(401).json({ success: false, message: ERROR_CODES.UNAUTHORIZED });
    }

    if (requiredRoles.length && !requiredRoles.includes(user.role)) {
      logger.warn(`User role '${user.role}' does not have the required permissions. Required roles: ${requiredRoles}`);
      return res.status(403).json({ success: false, message: ERROR_CODES.FORBIDDEN });
    }

    logger.info(`Access granted for user with role: ${user.role}`);
    next();
  };
};

module.exports = adminMiddleware;
