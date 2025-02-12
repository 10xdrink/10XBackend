// controllers/tagController.js

const asyncHandler = require('express-async-handler');
const mongoose = require('mongoose');
const Tag = require('../models/Tag'); // Ensure this path is correct
const MESSAGES = require('../messages/en');

/**
 * @desc    Get all tags with optional filters (e.g., active, search)
 * @route   GET /api/tags
 * @access  Private/Admin/Marketing Manager
 */
exports.getAllTags = asyncHandler(async (req, res, next) => {
  // Debugging: Verify the Tag model
  if (!Tag || typeof Tag.find !== 'function') {
    console.error('Tag model is not correctly imported or defined.');
    return res.status(500).json({
      success: false,
      message: 'Server Error: Tag model is not defined correctly.',
    });
  }

  const {
    page = 1,
    limit = 10,
    search = '',
    isActive,
    sortField = 'name',
    sortOrder = 'asc',
  } = req.query;

  const query = {};

  if (isActive !== undefined) {
    query.isActive = isActive === 'true';
  }

  if (search) {
    query.name = { $regex: search.toLowerCase(), $options: 'i' };
  }

  const sortOptions = {};
  sortOptions[sortField] = sortOrder === 'asc' ? 1 : -1;

  const tags = await Tag.find(query)
    .sort(sortOptions)
    .skip((page - 1) * limit)
    .limit(parseInt(limit, 10));

  const count = await Tag.countDocuments(query);

  res.status(200).json({
    success: true,
    data: tags,
    count,
    message: MESSAGES.Tag.FETCH_SUCCESS,
  });
});

/**
 * @desc    Get a single tag by ID
 * @route   GET /api/tags/:id
 * @access  Private/Admin/Marketing Manager
 */
exports.getTagById = asyncHandler(async (req, res, next) => {
  const { id } = req.params;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: MESSAGES.Tag.INVALID_ID });
  }

  const tag = await Tag.findById(id);

  if (!tag) {
    return res.status(404).json({ success: false, message: MESSAGES.Tag.TAG_NOT_FOUND });
  }

  res.status(200).json({
    success: true,
    data: tag,
    message: MESSAGES.Tag.FETCH_SUCCESS,
  });
});

/**
 * @desc    Create a new tag
 * @route   POST /api/tags
 * @access  Private/Admin/Marketing Manager
 */
exports.createTag = asyncHandler(async (req, res, next) => {
  const { name, description } = req.body;

  try {
    const tag = await Tag.create({
      name,
      description,
    });

    res.status(201).json({
      success: true,
      data: tag,
      message: MESSAGES.Tag.CREATE_SUCCESS,
    });
  } catch (err) {
    if (err.code === 11000) { // Duplicate key error
      return res.status(400).json({ success: false, message: MESSAGES.Tag.DUPLICATE_NAME });
    }
    // Validation errors
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map(val => val.message);
      return res.status(400).json({ success: false, message: messages.join('. ') });
    }
    throw err;
  }
});

/**
 * @desc    Update a tag by ID
 * @route   PUT /api/tags/:id
 * @access  Private/Admin/Marketing Manager
 */
exports.updateTag = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const { name, description, isActive } = req.body;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: MESSAGES.Tag.INVALID_ID });
  }

  try {
    let tag = await Tag.findById(id);

    if (!tag) {
      return res.status(404).json({ success: false, message: MESSAGES.Tag.TAG_NOT_FOUND });
    }

    // Update fields if provided
    if (name !== undefined) tag.name = name;
    if (description !== undefined) tag.description = description;
    if (isActive !== undefined) tag.isActive = isActive;

    await tag.save();

    res.status(200).json({
      success: true,
      data: tag,
      message: MESSAGES.Tag.UPDATE_SUCCESS,
    });
  } catch (err) {
    if (err.code === 11000) { // Duplicate key error
      return res.status(400).json({ success: false, message: MESSAGES.Tag.DUPLICATE_NAME });
    }
    // Validation errors
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map(val => val.message);
      return res.status(400).json({ success: false, message: messages.join('. ') });
    }
    throw err;
  }
});

/**
 * @desc    Soft delete (deactivate) a tag by ID
 * @route   DELETE /api/tags/:id
 * @access  Private/Admin/Marketing Manager
 */
exports.deleteTag = asyncHandler(async (req, res, next) => {
  const { id } = req.params;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: MESSAGES.Tag.INVALID_ID });
  }

  const tag = await Tag.findById(id);

  if (!tag) {
    return res.status(404).json({ success: false, message: MESSAGES.Tag.TAG_NOT_FOUND });
  }

  if (!tag.isActive) {
    return res.status(400).json({ success: false, message: MESSAGES.Tag.ALREADY_INACTIVE });
  }

  tag.isActive = false;
  await tag.save();

  res.status(200).json({
    success: true,
    data: tag,
    message: MESSAGES.Tag.DELETE_SUCCESS,
  });
});

/**
 * @desc    Permanently delete a tag by ID
 * @route   DELETE /api/tags/:id/permanent
 * @access  Private/Admin/Marketing Manager
 */
exports.permanentDeleteTag = asyncHandler(async (req, res, next) => {
  const { id } = req.params;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: MESSAGES.Tag.INVALID_ID });
  }

  const tag = await Tag.findById(id);

  if (!tag) {
    return res.status(404).json({ success: false, message: MESSAGES.Tag.TAG_NOT_FOUND });
  }

  await tag.deleteOne(); // Permanently remove the tag from the database

  res.status(200).json({
    success: true,
    message: MESSAGES.Tag.PERMANENT_DELETE_SUCCESS,
  });
});

/**
 * @desc    Activate a tag by ID
 * @route   POST /api/tags/:id/activate
 * @access  Private/Admin/Marketing Manager
 */
exports.activateTag = asyncHandler(async (req, res, next) => {
  const { id } = req.params;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: MESSAGES.Tag.INVALID_ID });
  }

  const tag = await Tag.findById(id);

  if (!tag) {
    return res.status(404).json({ success: false, message: MESSAGES.Tag.TAG_NOT_FOUND });
  }

  if (tag.isActive) {
    return res.status(400).json({ success: false, message: MESSAGES.Tag.ALREADY_ACTIVE });
  }

  tag.isActive = true;
  await tag.save();

  res.status(200).json({
    success: true,
    data: tag,
    message: MESSAGES.Tag.ACTIVATE_SUCCESS,
  });
});
