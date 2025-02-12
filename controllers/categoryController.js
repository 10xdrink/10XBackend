// src/controllers/categoryController.js

const Category = require('../models/Category');
const BlogPost = require('../models/BlogPost'); // Ensure this model exists and is correctly defined
const asyncHandler = require('express-async-handler');
const logger = require('../utils/logger'); // Ensure you have a logger utility
const ERROR_CODES = require('../constants/errorCodes'); // Define your error codes

// @desc    Create a new category
// @route   POST /api/categories
// @access  Private/Admin
exports.createCategory = asyncHandler(async (req, res, next) => {
  try {
    const { name, type, description, parent } = req.body; // type: 'product' or 'blog'

    // Check if category already exists
    const existingCategory = await Category.findOne({ name: name.trim() });
    if (existingCategory) {
      return res.status(400).json({
        success: false,
        message: 'Category with this name already exists',
      });
    }

    // Convert empty string to null for 'parent' field
    const parentId = parent && parent.trim() !== "" ? parent : null;

    const category = new Category({ name, type, description, parent: parentId });
    await category.save();

    res.status(201).json({
      success: true,
      data: category,
      message: 'Category created successfully',
    });
  } catch (error) {
    logger.error('Create Category Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR || 'Server Error' });
  }
});

// @desc    Get all categories with pagination and search
// @route   GET /api/categories
// @access  Public
exports.getAllCategories = asyncHandler(async (req, res, next) => {
  try {
    const { type, page = 1, limit = 10, search = '', exclude } = req.query; // Optional filter by type, pagination, search
    let query = {};

    if (type) {
      query.type = type;
    }

    if (search) {
      // Perform case-insensitive search on name
      query.name = { $regex: search, $options: 'i' };
    }

    if (exclude) {
      query._id = { $ne: exclude };
    }

    const skip = (page - 1) * limit;
    const total = await Category.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    const categories = await Category.find(query)
      .populate('parent', 'name slug type isActive') // Populate parent
      .populate('subcategories', 'name slug type isActive') // Populate subcategories
      .sort({ name: 1 })
      .skip(Number(skip))
      .limit(Number(limit));

    res.status(200).json({
      success: true,
      count: categories.length,
      data: categories,
      totalPages,
      currentPage: Number(page),
      message: 'Categories fetched successfully',
    });
  } catch (error) {
    logger.error('Get All Categories Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR || 'Server Error' });
  }
});

// @desc    Get category by ID
// @route   GET /api/categories/:id
// @access  Public
exports.getCategoryById = asyncHandler(async (req, res, next) => {
  try {
    const category = await Category.findById(req.params.id)
      .populate('parent', 'name slug type isActive') // Populate parent
      .populate('subcategories', 'name slug type isActive'); // Populate subcategories

    if (!category) {
      return res.status(404).json({ success: false, message: 'Category not found' });
    }

    res.status(200).json({
      success: true,
      data: category,
      message: 'Category fetched successfully',
    });
  } catch (error) {
    logger.error('Get Category By ID Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR || 'Server Error' });
  }
});

// @desc    Update category details
// @route   PUT /api/categories/:id
// @access  Private/Admin
exports.updateCategory = asyncHandler(async (req, res, next) => {
  try {
    const updates = req.body;

    let category = await Category.findById(req.params.id);
    if (!category) {
      return res.status(404).json({ success: false, message: 'Category not found' });
    }

    // If updating the name, check for duplicates
    if (updates.name && updates.name.trim() !== category.name) {
      const existingCategory = await Category.findOne({ name: updates.name.trim() });
      if (existingCategory) {
        return res.status(400).json({
          success: false,
          message: 'Another category with this name already exists',
        });
      }
      category.name = updates.name.trim();
    }

    // Handle 'parent' field: convert empty string to null
    if (updates.parent !== undefined) {
      category.parent = updates.parent && updates.parent.trim() !== "" ? updates.parent : null;
    }

    // Update other fields
    if (updates.type) category.type = updates.type;
    if (updates.description !== undefined) category.description = updates.description;
    if (updates.isActive !== undefined) category.isActive = updates.isActive;

    await category.save();

    res.status(200).json({
      success: true,
      data: category,
      message: 'Category updated successfully',
    });
  } catch (error) {
    logger.error('Update Category Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR || 'Server Error' });
  }
});

// @desc    Delete a category
// @route   DELETE /api/categories/:id
// @access  Private/Admin
exports.deleteCategory = asyncHandler(async (req, res, next) => {
  try {
    const categoryId = req.params.id;

    // Validate category ID format
    if (!categoryId.match(/^[0-9a-fA-F]{24}$/)) {
      return res.status(400).json({ success: false, message: 'Invalid category ID format' });
    }

    const category = await Category.findById(categoryId);

    if (!category) {
      return res.status(404).json({ success: false, message: 'Category not found' });
    }

    // Check if any blog posts are associated with this category
    const associatedPosts = await BlogPost.find({ categories: categoryId });
    if (associatedPosts.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete category because it is associated with blog posts',
      });
    }

    // Check for subcategories
    const subcategories = await Category.find({ parent: categoryId });
    if (subcategories.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Cannot delete category because it has subcategories',
      });
    }

    // Delete the category using findByIdAndDelete to avoid deprecation warnings
    await Category.findByIdAndDelete(categoryId);

    res.status(200).json({
      success: true,
      message: 'Category deleted successfully',
    });
  } catch (error) {
    logger.error('Delete Category Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR || 'Internal Server Error' });
  }
});
