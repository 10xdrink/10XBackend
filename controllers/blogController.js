// controllers/blogController.js

const BlogPost = require('../models/BlogPost');
const Category = require('../models/Category');
const Tag = require('../models/Tag');
const asyncHandler = require('express-async-handler');
const slugify = require('slugify');
const { uploadToCloudinary } = require('../services/uploadService');
const MESSAGES = require('../messages/en');
const logger = require('../utils/logger');

/**
 * @desc    Create a new blog post
 * @route   POST /api/blogs
 * @access  Private/Admin/Content Manager
 */
exports.createBlogPost = asyncHandler(async (req, res, next) => {
  const { title, content, categories, tags, status, images } = req.body;

  // Validate categories
  if (categories && categories.length > 0) {
    const validCategories = await Category.find({ _id: { $in: categories }, type: 'blog' });
    if (validCategories.length !== categories.length) {
      return res.status(400).json({ success: false, message: 'One or more categories are invalid.' });
    }
  }

  // Validate tags
  if (tags && tags.length > 0) {
    const validTags = await Tag.find({ _id: { $in: tags } });
    if (validTags.length !== tags.length) {
      return res.status(400).json({ success: false, message: 'One or more tags are invalid.' });
    }
  }

  const slug = slugify(title, { lower: true, strict: true });

  const categoryNames = await getCategoryNames(categories); // Returns an array

  const blogPost = await BlogPost.create({
    title,
    slug,
    content,
    categories,
    tags,
    status,
    images,
    author: req.user._id,
    meta: {
      title,
      description: `${title} - A blog post on ${categoryNames.join(', ')}.`,
      keywords: [title, 'blog', ...categoryNames],
    },
  });

  res.status(201).json({
    success: true,
    data: blogPost,
    message: MESSAGES.BLOG.CREATE_SUCCESS,
  });
});

/**
 * Helper function to retrieve category names.
 * @param {Array} categoryIds - Array of category IDs.
 * @returns {Array} - Array of category names.
 */
const getCategoryNames = async (categoryIds) => {
  if (!categoryIds || categoryIds.length === 0) return [];
  const categories = await Category.find({ _id: { $in: categoryIds } });
  return categories.map(cat => cat.name);
};

/**
 * @desc    Get all blog posts with optional filters
 * @route   GET /api/blogs
 * @access  Public
 */
exports.getAllBlogPosts = asyncHandler(async (req, res, next) => {
  const { status, category, tags, page = 1, limit = 10 } = req.query;
  let filter = {};

  if (status) {
    filter.status = status;
  }

  if (category) {
    // Assuming 'category' is the category name
    const categoryDoc = await Category.findOne({ name: category, type: 'blog' });
    if (categoryDoc) {
      filter.categories = categoryDoc._id;
    } else {
      // If category not found, return empty results
      return res.status(200).json({
        success: true,
        count: 0,
        total: 0,
        data: [],
        message: MESSAGES.BLOG.FETCH_SUCCESS,
      });
    }
  }

  if (tags) {
    const tagsArray = tags.split(',').map(tag => tag.trim());
    // Assuming 'tags' are tag names
    const tagDocs = await Tag.find({ name: { $in: tagsArray } });
    const tagIds = tagDocs.map(tag => tag._id);
    filter.tags = { $in: tagIds };
  }

  const skip = (page - 1) * limit;

  const blogPosts = await BlogPost.find(filter)
    .populate('categories', 'name')
    .populate('tags', 'name')
    .populate('author', 'name email')
    .sort({ createdAt: -1 })
    .skip(parseInt(skip))
    .limit(parseInt(limit));

  const total = await BlogPost.countDocuments(filter);

  res.status(200).json({
    success: true,
    count: blogPosts.length,
    total,
    data: blogPosts,
    message: MESSAGES.BLOG.FETCH_SUCCESS,
  });
});

/**
 * @desc    Get a single blog post by ID
 * @route   GET /api/blogs/:id
 * @access  Public
 */
exports.getBlogPostById = asyncHandler(async (req, res, next) => {
  const blogPost = await BlogPost.findById(req.params.id)
    .populate('categories', 'name')
    .populate('tags', 'name')
    .populate('author', 'name email');

  if (!blogPost) {
    return res.status(404).json({ success: false, message: MESSAGES.BLOG.BLOG_NOT_FOUND });
  }

  res.status(200).json({
    success: true,
    data: blogPost,
    message: MESSAGES.BLOG.FETCH_SUCCESS,
  });
});

/**
 * @desc    Get a single blog post by slug
 * @route   GET /api/blogs/slug/:slug
 * @access  Public
 */
exports.getBlogPostBySlug = asyncHandler(async (req, res, next) => {
  const blogPost = await BlogPost.findOne({ slug: req.params.slug })
    .populate('categories', 'name')
    .populate('tags', 'name')
    .populate('author', 'name email');

  if (!blogPost) {
    return res.status(404).json({ success: false, message: MESSAGES.BLOG.BLOG_NOT_FOUND });
  }

  res.status(200).json({
    success: true,
    data: blogPost,
    message: MESSAGES.BLOG.FETCH_SUCCESS,
  });
});

/**
 * @desc    Update an existing blog post
 * @route   PUT /api/blogs/:id
 * @access  Private/Admin/Content Manager
 */
exports.updateBlogPost = asyncHandler(async (req, res, next) => {
  const { title, content, categories, tags, status, images } = req.body;

  const blogPost = await BlogPost.findById(req.params.id);

  if (!blogPost) {
    return res.status(404).json({ success: false, message: MESSAGES.BLOG.BLOG_NOT_FOUND });
  }

  // Validate and update categories if provided
  if (categories && categories.length > 0) {
    const validCategories = await Category.find({ _id: { $in: categories }, type: 'blog' });
    if (validCategories.length !== categories.length) {
      return res.status(400).json({ success: false, message: 'One or more categories are invalid.' });
    }
    blogPost.categories = categories;
  }

  // Validate and update tags if provided
  if (tags && tags.length > 0) {
    const validTags = await Tag.find({ _id: { $in: tags } });
    if (validTags.length !== tags.length) {
      return res.status(400).json({ success: false, message: 'One or more tags are invalid.' });
    }
    blogPost.tags = tags;
  }

  if (title) {
    blogPost.title = title;
    blogPost.slug = slugify(title, { lower: true, strict: true });
  }
  if (content) blogPost.content = content;
  if (status) blogPost.status = status;
  if (images) blogPost.images = images;

  // Update meta fields if categories or title have changed
  if (title || categories) {
    const categoryNames = await getCategoryNames(blogPost.categories); // returns array
    blogPost.meta.title = title || blogPost.meta.title;
    blogPost.meta.description = `${blogPost.title} - A blog post on ${categoryNames.join(', ')}.`;
    blogPost.meta.keywords = [blogPost.title, 'blog', ...categoryNames];
  }

  await blogPost.save();

  res.status(200).json({
    success: true,
    data: blogPost,
    message: MESSAGES.BLOG.UPDATE_SUCCESS,
  });
});

/**
 * @desc    Delete a blog post
 * @route   DELETE /api/blogs/:id
 * @access  Private/Admin/Content Manager
 */
exports.deleteBlogPost = asyncHandler(async (req, res, next) => {
  const blogPost = await BlogPost.findById(req.params.id);

  if (!blogPost) {
    return res.status(404).json({ success: false, message: MESSAGES.BLOG.BLOG_NOT_FOUND });
  }

  // Updated deletion method
  await blogPost.deleteOne();

  res.status(200).json({
    success: true,
    message: MESSAGES.BLOG.DELETE_SUCCESS,
  });
});

/**
 * @desc    Upload an image for a blog post
 * @route   POST /api/blogs/upload-image
 * @access  Private/Admin/Content Manager
 */
exports.uploadBlogImage = asyncHandler(async (req, res, next) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No image file provided.' });
  }

  const folder = 'blog_images';
  try {
    const imageUrl = await uploadToCloudinary(req.file.buffer, folder);
    res.status(200).json({
      success: true,
      data: { imageUrl },
      message: MESSAGES.BLOG.UPLOAD_SUCCESS,
    });
  } catch (error) {
    logger.error('Image Upload Error:', error);
    res.status(500).json({ success: false, message: 'Image upload failed.' });
  }
});
