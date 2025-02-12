// testSendEmail.js

const sendEmail = require('./utils/sendEmail');

const testEmail = async () => {
  try {
    await sendEmail({
      email: 'recipient@example.com', // Replace with your email for testing
      subject: 'Test Email',
      message: 'This is a test email from your backend.',
    });
    console.log('Test email sent successfully.');
  } catch (error) {
    console.error('Failed to send test email:', error.message);
  }
};

testEmail();
