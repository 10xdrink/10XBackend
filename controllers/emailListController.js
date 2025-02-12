// controllers/emailListController.js

const EmailList = require('../models/EmailList');
const asyncHandler = require('express-async-handler');

/**
 * @desc    Add a new subscriber to the email list
 * @route   POST /api/email-list
 * @access  Public
 */
exports.addSubscriber = asyncHandler(async (req, res, next) => {
  const { name, email } = req.body;

  // Validate input
  if (!name || !email) {
    res.status(400);
    throw new Error('Please provide both name and email');
  }

  // Check if the email already exists
  const existingSubscriber = await EmailList.findOne({ email });

  if (existingSubscriber) {
    res.status(400);
    throw new Error('This email is already subscribed');
  }

  // Create a new subscriber
  const subscriber = await EmailList.create({ name, email });

  res.status(201).json({
    success: true,
    data: subscriber,
    message: 'Subscription successful',
  });
});
