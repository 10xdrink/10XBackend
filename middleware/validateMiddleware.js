const { validationResult } = require('express-validator');
const ERROR_CODES = require('../constants/errorCodes');
const logger = require('../utils/logger');

const validateMiddleware = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    const extractedErrors = errors.array().map(err => ({
      field: err.path || err.param || 'unknown_field', // Use `err.path` if `param` is missing
      message: err.msg,
    }));

    logger.warn('Validation failed', {
      requestBody: req.body,
      validationErrors: extractedErrors,
    });

    return res.status(422).json({
      success: false,
      message: ERROR_CODES.INVALID_INPUT,
      errors: extractedErrors,
    });
  }

  next();
};

module.exports = validateMiddleware;
