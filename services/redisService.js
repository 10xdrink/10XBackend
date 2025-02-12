// services/redisService.js
const redisClient = require('../config/redis');
const logger = require('../utils/logger');

/**
 * Sets a value in Redis cache.
 * @param {string} key - The key under which the value is stored.
 * @param {any} value - The value to store (will be stringified).
 * @param {number} expirationInSeconds - Time to live in seconds.
 */
const setCache = async (key, value, expirationInSeconds) => {
  try {
    const serializedValue = JSON.stringify(value);
    await redisClient.set(key, serializedValue, {
      EX: expirationInSeconds,
    });
    logger.info(`Cache set for key: ${key}`);
  } catch (error) {
    logger.error('Redis Set Cache Error:', error);
  }
};

/**
 * Retrieves a value from Redis cache.
 * @param {string} key - The key to retrieve.
 * @returns {any|null} - The parsed value or null if not found.
 */
const getCache = async (key) => {
  try {
    const data = await redisClient.get(key);
    if (data) {
      logger.info(`Cache hit for key: ${key}`);
      return JSON.parse(data);
    }
    logger.info(`Cache miss for key: ${key}`);
    return null;
  } catch (error) {
    logger.error('Redis Get Cache Error:', error);
    return null;
  }
};

/**
 * Deletes a value from Redis cache.
 * @param {string} key - The key to delete.
 */
const deleteCache = async (key) => {
  try {
    const result = await redisClient.del(key);
    if (result === 1) {
      logger.info(`Cache deleted for key: ${key}`);
    } else {
      logger.info(`No cache found for key: ${key} to delete`);
    }
  } catch (error) {
    logger.error('Redis Delete Cache Error:', error);
  }
};

module.exports = {
  setCache,
  getCache,
  deleteCache,
};
