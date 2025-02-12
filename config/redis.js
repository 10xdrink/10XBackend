// config/redis.js
const redis = require('redis');
const logger = require('../utils/logger');
require('dotenv').config();

const {
  REDIS_HOST,
  REDIS_PORT,
  REDIS_PASSWORD
  
} = process.env;

const redisClient = redis.createClient({
  socket: {
    host: REDIS_HOST,
    port: REDIS_PORT,
    tls: {}, // Add this line to enable TLS if required
  },
  password: REDIS_PASSWORD,
});

// Handle Redis client errors
redisClient.on('error', (err) => {
  logger.error('Redis Client Error:', err);
});

// Log Redis connection attempt
redisClient.on('connect', () => {
  logger.info('Connecting to Redis...');
});

// Log successful Redis connection
redisClient.on('ready', () => {
  logger.info('Connected to Redis successfully!');
});

// Connect to Redis server asynchronously
(async () => {
  try {
    await redisClient.connect();
  } catch (error) {
    logger.error('Could not establish a connection with Redis. ' + error);
  }
})();

// Graceful shutdown handling
const gracefulShutdown = async () => {
  try {
    await redisClient.quit();
    logger.info('Redis client disconnected successfully.');
    process.exit(0);
  } catch (error) {
    logger.error('Error during Redis client disconnection:', error);
    process.exit(1);
  }
};

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

module.exports = redisClient;
