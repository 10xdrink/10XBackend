// middleware/auditMiddleware.js

const AuditLog = require('../models/AuditLog');

/**
 * Middleware to log actions for auditing purposes.
 * @param {string} action - Description of the action performed.
 * @param {string} entity - The entity affected (e.g., "user", "settings").
 * @returns {Function} - Express middleware function.
 */
const auditMiddleware = (action, entity) => {
  return async (req, res, next) => {
    try {
      // Record the audit log entry
      await AuditLog.create({
        user: req.user ? req.user.id : null, // Ensure user is logged in
        action,
        entity,
        entityId: req.params.id || req.body.id || null,
        previousData: req.previousData || null, // If provided by a controller
        newData: req.body || null,
        timestamp: new Date(),
      });

      next();
    } catch (error) {
      console.error('Audit logging error:', error);
      next(error);
    }
  };
};

module.exports = auditMiddleware;
