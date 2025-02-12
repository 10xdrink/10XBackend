const sendEmailService = require('../services/emailService');
const logger = require('./logger');

/**
 * Send an email
 * @param {Object} options - Email options
 * @param {string} options.email - Recipient email address
 * @param {string} options.subject - Email subject
 * @param {string} options.message - Plain text message content
 * @param {string} options.html - HTML message content
 * @returns {Promise<void>}
 */
const sendEmail = async ({ email, subject, message, html }) => {
  try {
    await sendEmailService({ email, subject, message, html });
    logger.info(`Email sent to ${email} with subject: "${subject}"`);
  } catch (error) {
    // Log additional error details if available
    if (error.response && error.response.body && error.response.body.errors) {
      logger.error(`Failed to send email to ${email}: ${JSON.stringify(error.response.body.errors)}`);
    } else {
      logger.error(`Failed to send email to ${email}: ${error.message}`);
    }
    throw new Error('Email could not be sent');
  }
};

module.exports = sendEmail;
