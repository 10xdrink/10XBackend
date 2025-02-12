const redisClient = require('../config/redis');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Define session expiration time in milliseconds
const SESSION_EXPIRATION_TIME = 30 * 60 * 1000; // 30 minutes
const TOKEN_REFRESH_THRESHOLD = 15 * 60 * 1000; // Refresh token if it's within 15 minutes of expiration

// Set session expiration time in Redis
const setSessionExpiration = (sessionId, ttl) => {
  redisClient.expire(sessionId, ttl / 1000, (err) => {
    if (err) {
      console.error('Error setting session expiration:', err);
    }
  });
};

// Regenerate session token for long sessions
const regenerateSessionToken = (user, existingSessionId, callback) => {
  const newToken = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '15m' });
  
  // Replace the existing session ID with the new one in Redis
  redisClient.set(existingSessionId, newToken, 'EX', SESSION_EXPIRATION_TIME / 1000, (err) => {
    if (err) {
      console.error('Error regenerating session token:', err);
      callback(err, null);
    } else {
      callback(null, newToken);
    }
  });
};

// Check active session status
const checkActiveSession = (sessionId, callback) => {
  redisClient.get(sessionId, (err, result) => {
    if (err) {
      console.error('Error checking active session:', err);
      callback(err, false);
    } else {
      callback(null, result !== null);
    }
  });
};

/**
 * Checks if a session is expired based on the last activity time.
 * @param {Date} lastActivity - The timestamp of the user's last activity.
 * @returns {boolean} - True if the session is expired, false otherwise.
 */
const isSessionExpired = (lastActivity) => {
  const now = Date.now();
  return now - new Date(lastActivity).getTime() > SESSION_EXPIRATION_TIME;
};

/**
 * Determines if a token should be refreshed based on the issued at (iat) time.
 * @param {number} iat - The issued at time of the token in seconds.
 * @returns {boolean} - True if the token should be refreshed, false otherwise.
 */
const shouldRefreshToken = (iat) => {
  const tokenAge = Date.now() - iat * 1000;
  return tokenAge >= SESSION_EXPIRATION_TIME - TOKEN_REFRESH_THRESHOLD;
};

/**
 * Updates the user's last activity timestamp in the database.
 * @param {string} userId - The ID of the user.
 */
const updateLastActivity = async (userId) => {
  await User.findByIdAndUpdate(userId, { lastActivity: new Date() });
};

/**
 * Generates a new access token for a user.
 * @param {Object} user - The user object containing user ID and role.
 * @returns {string} - The generated JWT token.
 */
const generateAccessToken = (user) => {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

module.exports = {
  setSessionExpiration,
  regenerateSessionToken,
  checkActiveSession,
  isSessionExpired,
  shouldRefreshToken,
  updateLastActivity,
  generateAccessToken, // Add this function to the exports
};
 