// jobs/reportJob.js
const { Queue, Worker } = require('bullmq');
const generateReport = require('../controllers/reportController').generateSalesReport; // Assume this function exists
const logger = require('../utils/logger');
const redisClient = require('../config/redis');

// Initialize Report Queue
const reportQueue = new Queue('reportQueue', {
  connection: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
  },
});

// Worker to process report jobs
const reportWorker = new Worker('reportQueue', async job => {
  const { reportType, params } = job.data;
  const report = await generateReport(reportType, params);
  // Handle the generated report (e.g., save to storage or send via email)
  logger.info(`Report generated: ${reportType}`);
}, {
  connection: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
  },
});

// Handle Worker Errors
reportWorker.on('failed', (job, err) => {
  logger.error(`Report job failed for type ${job.data.reportType}: ${err.message}`);
});

module.exports = reportQueue;
