// controllers/faqController.js

const asyncHandler = require('express-async-handler');
const mongoose = require('mongoose');
const FAQ = require('../models/FAQ');
const MESSAGES = require('../messages/en');

/**
 * @desc    Get all FAQs
 * @route   GET /api/faqs
 * @access  Public
 */
exports.getAllFAQs = asyncHandler(async (req, res, next) => {
  const { page = 1, limit = 10, search = '', sortField = 'question', sortOrder = 'asc' } = req.query;

  const query = {
    isActive: true,
    $or: [
      { question: { $regex: search, $options: 'i' } },
      { answer: { $regex: search, $options: 'i' } },
    ],
  };

  const sortOptions = {};
  sortOptions[sortField] = sortOrder === 'asc' ? 1 : -1;

  const faqs = await FAQ.find(query)
    .sort(sortOptions)
    .skip((page - 1) * limit)
    .limit(parseInt(limit));

  const count = await FAQ.countDocuments(query);

  res.status(200).json({
    success: true,
    data: faqs,
    count,
    message: MESSAGES.FAQ.FETCH_SUCCESS,
  });
});

/**
 * @desc    Get a single FAQ by ID
 * @route   GET /api/faqs/:id
 * @access  Public
 */
exports.getFAQById = asyncHandler(async (req, res, next) => {
  const { id } = req.params;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: MESSAGES.FAQ.INVALID_ID });
  }

  const faq = await FAQ.findById(id);

  if (!faq) {
    return res.status(404).json({ success: false, message: MESSAGES.FAQ.FAQ_NOT_FOUND });
  }

  res.status(200).json({
    success: true,
    data: faq,
    message: MESSAGES.FAQ.FETCH_SUCCESS,
  });
});

/**
 * @desc    Create a new FAQ
 * @route   POST /api/faqs
 * @access  Private/Admin/Content Manager
 */
exports.createFAQ = asyncHandler(async (req, res, next) => {
  const { question, answer, tags, isActive } = req.body;

  try {
    const faq = await FAQ.create({
      question,
      answer,
      tags,
      isActive,
    });

    res.status(201).json({
      success: true,
      data: faq,
      message: MESSAGES.FAQ.CREATE_SUCCESS,
    });
  } catch (err) {
    if (err.code === 11000) { // Duplicate key error
      return res.status(400).json({ success: false, message: MESSAGES.FAQ.DUPLICATE_QUESTION });
    }
    // For other errors, rethrow to be handled by asyncHandler
    throw err;
  }
});

/**
 * @desc    Update a FAQ by ID
 * @route   PUT /api/faqs/:id
 * @access  Private/Admin/Content Manager
 */
exports.updateFAQ = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const { question, answer, tags, isActive } = req.body;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: MESSAGES.FAQ.INVALID_ID });
  }

  try {
    const faq = await FAQ.findById(id);

    if (!faq) {
      return res.status(404).json({ success: false, message: MESSAGES.FAQ.FAQ_NOT_FOUND });
    }

    // Update fields if provided
    if (question !== undefined) faq.question = question;
    if (answer !== undefined) faq.answer = answer;
    if (tags !== undefined) faq.tags = tags;
    if (isActive !== undefined) faq.isActive = isActive;

    await faq.save();

    res.status(200).json({
      success: true,
      data: faq,
      message: MESSAGES.FAQ.UPDATE_SUCCESS,
    });
  } catch (err) {
    if (err.code === 11000) { // Duplicate key error
      return res.status(400).json({ success: false, message: MESSAGES.FAQ.DUPLICATE_QUESTION });
    }
    throw err;
  }
});

/**
 * @desc    Delete a FAQ
 * @route   DELETE /api/faqs/:id
 * @access  Private/Admin/Content Manager
 */
exports.deleteFAQ = asyncHandler(async (req, res, next) => {
  const { id } = req.params;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: MESSAGES.FAQ.INVALID_ID });
  }

  const faq = await FAQ.findByIdAndDelete(id);

  if (!faq) {
    return res.status(404).json({ success: false, message: MESSAGES.FAQ.FAQ_NOT_FOUND });
  }

  res.status(200).json({
    success: true,
    data: {},
    message: MESSAGES.FAQ.DELETE_SUCCESS,
  });
});
