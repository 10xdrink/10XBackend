// controllers/chatbotController.js

const Submission = require('../models/Submission');
const sendEmail = require('../utils/sendEmail'); // Import the sendEmail function
const path = require('path');
const fs = require('fs');
const handlebars = require('handlebars');

const submitForm = async (req, res) => {
  const { name, mobile, email, message, consent } = req.body;

  // Validate input fields
  if (!name || !mobile || !email || !message || consent === undefined) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    // Save submission to the database
    const newSubmission = new Submission({ name, mobile, email, message, consent });
    await newSubmission.save();
    console.log('Submission saved to database:', newSubmission);

    // Load and compile the email template
    const templatePath = path.join(__dirname, '../templates/chatbotSubmission.html');
    const templateSource = fs.readFileSync(templatePath, 'utf8');
    const template = handlebars.compile(templateSource);

    const htmlContent = template({
      name,
      mobile,
      email,
      message,
    });

    // Define plain text message as a fallback
    const plainTextMessage = `New Chatbot Contact Form Submission:\n\nName: ${name}\nMobile: ${mobile}\nEmail: ${email}\nMessage: ${message}`;

    // Send email using SendGrid
    await sendEmail({
      email: 'tenexformula7@gmail.com', // Recipient email address
      subject: 'New Chatbot Contact Form Submission',
      message: plainTextMessage,
      html: htmlContent, // Send the HTML content
    });

    console.log('Email sent successfully');

    res.status(200).json({ message: 'Your message has been sent successfully!' });
  } catch (error) {
    console.error('Error in submitForm:', error);
    res.status(500).json({ error: 'Server error, please try again later.' });
  }
};

module.exports = { submitForm };
