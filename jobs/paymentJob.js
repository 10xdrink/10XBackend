// jobs/paymentJob.js
const { Queue, Worker } = require('bullmq');
const paymentService = require('../services/paymentService');
const Order = require('../models/Order');
const logger = require('../utils/logger');
const redisClient = require('../config/redis');

// Initialize Payment Queue
const paymentQueue = new Queue('paymentQueue', {
  connection: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
  },
});

// Worker to process payment retry jobs
const paymentWorker = new Worker('paymentQueue', async job => {
  const { orderId } = job.data;
  const order = await Order.findById(orderId);
  
  if (!order) {
    throw new Error('Order not found');
  }
  
  if (order.paymentStatus === 'failed') {
    try {
      await paymentService.processPayment(order, { /* payment details */ });
      order.paymentStatus = 'completed';
      await order.save();
      logger.info(`Payment retried and completed for order ${orderId}`);
    } catch (error) {
      logger.error(`Payment retry failed for order ${orderId}: ${error.message}`);
      throw error;
    }
  } else {
    logger.info(`Order ${orderId} payment status is not failed. No action taken.`);
  }
}, {
  connection: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
  },
  attempts: 3,
  backoff: {
    type: 'exponential',
    delay: 60000, // 1 minute
  },
});

// Handle Worker Errors
paymentWorker.on('failed', (job, err) => {
  logger.error(`Payment job failed for order ${job.data.orderId}: ${err.message}`);
});

module.exports = paymentQueue;
