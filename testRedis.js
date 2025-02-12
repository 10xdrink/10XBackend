// testRedis.js
const redisClient = require('./config/redis'); // Adjust path if needed
const logger = require('./utils/logger');

async function testRedis() {
  try {
    await redisClient.set('testKey', 'testValue', 'EX', 60); // Set key with 60 seconds expiration
    logger.info('Value set in Redis');
    
    const value = await redisClient.get('testKey'); // Get the value from Redis
    logger.info(`Retrieved value from Redis: ${value}`);
    
    await redisClient.del('testKey'); // Delete the key
    logger.info('Key deleted from Redis');
  } catch (error) {
    logger.error('Redis Test Error:', error);
  }
}

testRedis();
