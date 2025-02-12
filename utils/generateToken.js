// utils/generateToken.js

const jwt = require('jsonwebtoken');

/**
 * Generate a JWT token.
 * @param {Object} payload - Payload to encode in the token.
 * @param {String} secret - Secret key for signing the token.
 * @param {String} expiresIn - Token expiration time (e.g., '1d', '7d').
 * @returns {String} - Signed JWT token.
 */
const generateToken = (payload, secret, expiresIn = '1d') => {
  return jwt.sign(payload, secret, { expiresIn });
};

/**
 * Generate an access token (expires in 1 hour).
 * @param {Object} user - User object.
 * @returns {String} - JWT access token.
 */
const generateAccessToken = (user) => {
  return jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
};

/**
 * Generate a refresh token (expires in 7 days).
 * @param {Object} user - User object.
 * @returns {String} - JWT refresh token.
 */
const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );
};

module.exports = {
  generateToken,
  generateAccessToken,
  generateRefreshToken,
};
