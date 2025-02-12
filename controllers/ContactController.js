// controllers/contactController.js

const path = require("path");
const handlebars = require("handlebars");
const fs = require("fs");
const sendEmail = require("../utils/sendEmail");
const logger = require("../utils/logger");
const ERROR_CODES = require("../constants/errorCodes");

/**
 * @desc    Handle contact form submission
 * @route   POST /api/contact
 * @access  Public
 */
exports.submitContactMessage = async (req, res, next) => {
  try {
    const { name, email, message } = req.body;

    // Basic validation
    if (!name || !email || !message) {
      logger.warn("Contact Submission: Missing required fields", { name, email, message });
      return res.status(400).json({
        success: false,
        message: "Please provide name, email, and message",
      });
    }

    // Check if SUPPORT_EMAIL is defined
    if (!process.env.SUPPORT_EMAIL) {
      logger.error("SUPPORT_EMAIL is not defined in environment variables");
      return res.status(500).json({
        success: false,
        message: "Server configuration error: Support email not set",
      });
    }

    // Load and compile the contact message HTML template
    const templatePath = path.join(__dirname, "../templates/contactMessage.html");
    if (!fs.existsSync(templatePath)) {
      logger.error(`Contact Message Template not found at path: ${templatePath}`);
      return res.status(500).json({
        success: false,
        message: "Server configuration error: Email template missing",
      });
    }

    const templateSource = fs.readFileSync(templatePath, "utf8");
    const template = handlebars.compile(templateSource);

    const htmlContent = template({
      name,
      email,
      message,
      supportUrl: process.env.SUPPORT_URL || "https://yourcompany.com/contact",
    });

    // Define plain text message as a fallback
    const plainTextMessage = `
You have received a new contact message from your website:

Name: ${name}
Email: ${email}
Message:
${message}

Please review and respond to this message at your earliest convenience.

Best regards,
Your Company Team
    `;

    // Send the contact message to support email
    await sendEmail({
      email: process.env.SUPPORT_EMAIL, // Support email from environment variables
      subject: `New Contact Message from ${name}`,
      message: plainTextMessage,
      html: htmlContent, // Send the HTML content
    });

    logger.info(`Contact message sent from ${email}`);

    // Optionally, send acknowledgment email to the user
    // Check if FROM_EMAIL is set for sending acknowledgment
    if (!process.env.FROM_EMAIL) {
      logger.error("FROM_EMAIL is not defined in environment variables");
      return res.status(500).json({
        success: false,
        message: "Server configuration error: From email not set",
      });
    }

    // Load and compile the acknowledgment email template
    const ackTemplatePath = path.join(__dirname, "../templates/contactAcknowledgment.html");
    if (!fs.existsSync(ackTemplatePath)) {
      logger.error(`Contact Acknowledgment Template not found at path: ${ackTemplatePath}`);
      return res.status(500).json({
        success: false,
        message: "Server configuration error: Email template missing",
      });
    }

    const ackTemplateSource = fs.readFileSync(ackTemplatePath, "utf8");
    const ackTemplate = handlebars.compile(ackTemplateSource);

    const ackHtmlContent = ackTemplate({
      name,
      supportUrl: process.env.SUPPORT_URL || "https://yourcompany.com/contact",
    });

    const ackPlainTextMessage = `
Hello ${name},

Thank you for reaching out to us. We have received your message and will get back to you shortly.

Best regards,
Your Company Team
    `;

    await sendEmail({
      email: email,
      subject: "Thank You for Contacting Us",
      message: ackPlainTextMessage,
      html: ackHtmlContent,
    });

    logger.info(`Acknowledgment email sent to ${email}`);

    res.status(200).json({
      success: true,
      message: "Your message has been sent successfully.",
    });
  } catch (error) {
    logger.error("Contact Submission Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};
