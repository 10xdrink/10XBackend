// utils/logger.js
const { createLogger, format, transports } = require('winston');
const path = require('path');

// Helper function to mask sensitive information
const maskSensitiveInfo = (info) => {
  if (typeof info === 'string') {
    // Mask credit card numbers, emails, etc.
    return info.replace(/\b(?:\d[ -]*?){13,16}\b/g, '****-****-****-****')
               .replace(/(\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b)/gi, '***@***');
  }
  if (typeof info === 'object') {
    for (let key in info) {
      if (['password', 'transactionId', 'email'].includes(key)) {
        info[key] = '****'; // Mask specific sensitive fields
      } else if (typeof info[key] === 'object') {
        info[key] = maskSensitiveInfo(info[key]);
      }
    }
  }
  return info;
};

// Define log format with masking
const logFormat = format.combine(
  format((info) => {
    info.message = maskSensitiveInfo(info.message);
    info = maskSensitiveInfo(info); // Mask any other fields in the log entry
    return info;
  })(),
  format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  format.errors({ stack: true }),
  format.splat(),
  format.json()
);

// Create logger instance
const logger = createLogger({
  level: 'info',
  format: logFormat,
  transports: [
    // Console transport for development
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.simple()
      ),
      handleExceptions: true, // Handle exceptions in the console
    }),
    // File transport for errors
    new transports.File({
      filename: path.join(__dirname, '../logs/error.log'),
      level: 'error',
      handleExceptions: true, // Handle exceptions in error.log
    }),
    // File transport for combined logs
    new transports.File({
      filename: path.join(__dirname, '../logs/combined.log'),
    }),
  ],
  exitOnError: false, // Do not exit on handled exceptions
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', maskSensitiveInfo(reason));
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', maskSensitiveInfo(error));
});

// Stream for Morgan integration
logger.stream = {
  write: function(message) {
    logger.info(maskSensitiveInfo(message.trim()));
  },
};

module.exports = logger;
