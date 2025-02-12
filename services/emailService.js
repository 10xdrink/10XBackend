// utils/sendEmail.js

const sgMail = require('@sendgrid/mail');
const logger = require('../utils/logger');

const emailService = process.env.EMAIL_SERVICE; // Should be 'sendgrid'

// Validate that the email service is set to 'sendgrid'
if (emailService !== 'sendgrid') {
  logger.error(`Unsupported email service: ${emailService}`);
  throw new Error('Unsupported email service. Please set EMAIL_SERVICE=sendgrid in your .env file.');
}

// Ensure SENDGRID_API_KEY is set
if (!process.env.SENDGRID_API_KEY) {
  logger.error('SENDGRID_API_KEY is not defined in environment variables');
  throw new Error('SENDGRID_API_KEY is not defined in environment variables');
}

// Ensure FROM_EMAIL is set
if (!process.env.FROM_EMAIL) {
  logger.error('FROM_EMAIL is not defined in environment variables');
  throw new Error('FROM_EMAIL is not defined in environment variables');
}

// Configure SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

/**
 * Send an email using SendGrid
 * @param {Object} options - Email options
 * @param {string} options.email - Recipient email address
 * @param {string} options.subject - Email subject
 * @param {string} options.message - Plain text message content
 * @param {string} options.html - HTML message content
 * @returns {Promise<void>}
 */
const sendEmail = async ({ email, subject, message, html }) => {
  if (!email) {
    logger.error('sendEmail: Recipient email is undefined');
    throw new Error('Recipient email is required');
  }

  try {
    // Send email using SendGrid
    const msg = {
      to: email,
      from: process.env.FROM_EMAIL, // Must be a verified sender in SendGrid
      subject,
      text: message,
      html, // Add the HTML content
    };
    await sgMail.send(msg);
    logger.info(`Email sent to ${email} via SendGrid`);
  } catch (error) {
    if (error.response && error.response.body && error.response.body.errors) {
      logger.error(`SendGrid Error: ${JSON.stringify(error.response.body.errors)}`);
    } else {
      logger.error(`Failed to send email to ${email} via SendGrid: ${error.message}`);
    }
    throw new Error('Email could not be sent');
  }
};

module.exports = sendEmail;
