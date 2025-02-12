// constants/errorCodes.js

const ERROR_CODES = {
  INVALID_INPUT: 'Invalid input. Please ensure all fields are filled out correctly and try again.',
  AUTHENTICATION_FAILED: 'Authentication failed. Please check your email and password, and ensure your account is active.',
  UNAUTHORIZED: 'Unauthorized access. You do not have the necessary permissions to view this resource.',
  FORBIDDEN: 'Access forbidden. You do not have permission to perform this action.',
  NOT_FOUND: 'Resource not found. The item you are looking for does not exist.',
  SERVER_ERROR: 'Internal server error. Something went wrong on our end. Please try again later.',
  PAYMENT_FAILED: 'Payment processing failed. Please check your payment details and try again.',
  RESOURCE_CONFLICT: 'Resource conflict. This action cannot be completed due to a conflict with existing data (e.g., duplicate entries).',
  RATE_LIMIT_EXCEEDED: 'Rate limit exceeded. You have made too many requests in a short period. Please try again later.',
  TOKEN_EXPIRED: 'Session expired. Please log in again to continue your session.',
  INVALID_TOKEN: 'Invalid authentication token. Please log in again to receive a valid token.',
  SERVICE_UNAVAILABLE: 'Service unavailable. The system is currently undergoing maintenance or is experiencing downtime.',
  DATABASE_ERROR: 'Database error. We encountered an issue while accessing our database. Please try again later.',
  EMAIL_NOT_SENT: 'Email sending failed. Please check your email address and try again, or contact support if the issue persists.',
  VALIDATION_ERROR: 'Validation error. Please ensure all provided information meets the required criteria and try again.',
  ACTION_NOT_ALLOWED: 'Action not allowed. You cannot perform this action due to current system restrictions.',
  INSUFFICIENT_PERMISSIONS: 'Insufficient permissions. You do not have the necessary rights to perform this operation.',
  RESOURCE_LOCKED: 'Resource locked. This item is currently in use or locked for editing. Please try again later.',
  DUPLICATE_ENTRY: 'Duplicate entry. This item already exists in the database. Please check your entries and try again.',
  FILE_UPLOAD_ERROR: 'File upload error. Please ensure the file meets the required specifications and try again.',
  INSUFFICIENT_FUNDS: 'Payment failed due to insufficient funds. Please check your account balance and try again.',
  CART_EMPTY: 'Your cart is empty. Add items to your cart before proceeding to checkout.',
  PRODUCT_OUT_OF_STOCK: 'Product out of stock. The item you are trying to purchase is currently unavailable.',
  INVALID_COUPON: 'Invalid coupon. Please check the coupon code for accuracy or ensure it has not expired.'  
};

module.exports = ERROR_CODES