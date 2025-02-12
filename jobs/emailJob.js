// jobs/emailJob.js
const { Queue, Worker } = require('bullmq');
const sendEmail = require('../utils/sendEmail');
const logger = require('../utils/logger');
const redisClient = require('../config/redis');

// Initialize Email Queue
const emailQueue = new Queue('emailQueue', {
  connection: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
  },
});

// Worker to process email jobs
const emailWorker = new Worker(
  'emailQueue',
  async (job) => {
    const { email, subject, message } = job.data;
    await sendEmail({ email, subject, message });
    logger.info(`Email sent to ${email}`);
  },
  {
    connection: {
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT,
    },
  }
);

// Handle Worker Errors
emailWorker.on('failed', (job, err) => {
  logger.error(`Email job failed for ${job.data.email}: ${err.message}`);
});

module.exports = emailQueue;
