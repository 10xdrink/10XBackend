const logger = require('../utils/logger');
const ERROR_CODES = require('../constants/errorCodes');

const errorMiddleware = (err, req, res, next) => {
  logger.error(`Error: ${err.message}`, {
    stack: err.stack,
    path: req.originalUrl,
    method: req.method,
    body: req.body,
    params: req.params,
    query: req.query,
  });

  const statusCode = err.statusCode || 500;
  let message = err.message || 'Server Error';

  if (err.name === 'ValidationError') {
    message = ERROR_CODES.INVALID_INPUT;
  } else if (err.name === 'UnauthorizedError') {
    message = ERROR_CODES.UNAUTHORIZED;
  }

  res.status(statusCode).json({
    success: false,
    message,
    errorDetails: err.details || null,
  });
};

module.exports = errorMiddleware;
