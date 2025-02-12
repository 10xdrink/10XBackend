// config/mail.js
const sgMail = require('@sendgrid/mail');
const AWS = require('aws-sdk');
const logger = require('../utils/logger');

const emailService = process.env.EMAIL_SERVICE; // 'sendgrid' or 'ses'

if (emailService === 'sendgrid') {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  logger.info('SendGrid configured successfully.');
} else if (emailService === 'ses') {
  AWS.config.update({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION,
  });
  logger.info('AWS SES configured successfully.');
} else {
  logger.warn('No valid email service configured. Defaulting to SendGrid.');
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
}

module.exports = emailService;
