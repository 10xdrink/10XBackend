// controllers/productController.js

const mongoose = require('mongoose');
const Product = require('../models/Product');
const Tag = require('../models/Tag'); // Assuming you have a Tag model
const cloudinary = require('../config/cloudinary');
const logger = require('../utils/logger');
const ERROR_CODES = require('../constants/errorCodes');

/**
 * @desc    Create a new product
 * @route   POST /api/products
 * @access  Private/Admin/Product Manager
 */
exports.createProduct = async (req, res) => {
  try {
    // Destructure fields from the request body
    const {
      title,
      price,
      stock,
      description,
      category,
      tags, // Expected to be an array of Tag IDs
      discountPercentage,
      brand,
      accordion,
      productBG, // URL to the product background image
      thumbnail, // URL to the thumbnail image
      variants, // Array of variant objects
    } = req.body;

    // Validate required fields
    if (!productBG) {
      return res.status(400).json({
        success: false,
        message: 'Product background image (productBG) is required.',
      });
    }

    if (!thumbnail) {
      return res.status(400).json({
        success: false,
        message: 'Thumbnail image URL is required.',
      });
    }

    if (!Array.isArray(variants) || variants.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'At least one variant is required.',
      });
    }

    // Validate and convert tags to ObjectIds
    let tagIds = [];
    if (tags && Array.isArray(tags)) {
      // Now, assuming tags are sent as IDs
      const foundTags = await Tag.find({ _id: { $in: tags } });
      if (foundTags.length !== tags.length) {
        return res.status(400).json({
          success: false,
          message: 'One or more tags are invalid.',
        });
      }
      tagIds = foundTags.map(tag => tag._id);
    }

    // Create a new product instance with validated and formatted data
    const product = new Product({
      title,
      price,
      stock,
      description,
      category,
      tags: tagIds, // Use the array of ObjectIds
      discountPercentage,
      brand,
      accordion,
      productBG,
      thumbnail,
      images: [], // Initialize as empty; can be updated later
      variants, // Ensure variants array has at least one variant
    });

    // Save the product to the database
    await product.save();

    // Optional: Log the creation in AuditLog
    // await AuditLog.create({
    //   performedBy: req.user._id, // Assuming you have user info in req.user
    //   entityId: product._id,
    //   entity: 'Product',
    //   action: 'CREATE',
    //   details: `Created product with title: ${product.title}`,
    // });

    res.status(201).json({
      success: true,
      data: product,
    });
  } catch (error) {
    logger.error('Create Product Error:', error);

    // Handle specific Mongoose validation errors
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({
        success: false,
        message: 'Validation Error',
        errors,
      });
    }

    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Upload product image
 * @route   POST /api/products/upload-image
 * @access  Private/Admin/Product Manager
 */
exports.uploadProductImage = async (req, res) => {
  try {
    // Log the received file for debugging
    logger.debug('Received file:', req.file);

    // Ensure that the file was uploaded
    if (!req.file) {
      logger.warn('No file uploaded');
      return res.status(400).json({
        success: false,
        message: 'No file uploaded. Please upload an image with the field name "image".',
      });
    }

    const file = req.file;

    // Optional: Additional file validation can be done here

    // Upload the image buffer to Cloudinary
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        {
          folder: 'products',
          width: 800,
          height: 800,
          crop: 'fill',
        },
        (error, result) => {
          if (error) return reject(error);
          resolve(result);
        }
      );
      stream.end(file.buffer);
    });

    logger.info('Image uploaded to Cloudinary:', result.secure_url);

    res.status(200).json({
      success: true,
      data: result.secure_url,
    });
  } catch (error) {
    logger.error('Upload Product Image Error:', error);

    // Handle Cloudinary errors specifically
    if (error.name === 'Error' && error.http_code) {
      return res.status(error.http_code).json({
        success: false,
        message: error.message || ERROR_CODES.SERVER_ERROR,
      });
    }

    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Get a single product by ID
 * @route   GET /api/products/:id
 * @access  Public/Admin
 */
exports.getProductById = async (req, res) => {
  try {
    const product = await Product.findById(req.params.id).populate('tags'); // Populating 'tags' as it's defined in the schema

    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    res.status(200).json({
      success: true,
      data: product,
    });
  } catch (error) {
    logger.error('Get Product By ID Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Get a single product by Slug
 * @route   GET /api/products/slug/:slug
 * @access  Public
 */
exports.getProductBySlug = async (req, res) => {
  try {
    const product = await Product.findOne({ slug: req.params.slug }).populate('tags'); // Populating 'tags'

    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    res.status(200).json({
      success: true,
      data: product,
    });
  } catch (error) {
    logger.error('Get Product By Slug Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Search products by query
 * @route   GET /api/products/search
 * @access  Public
 */
exports.searchProducts = async (req, res) => {
  try {
    const { query } = req.query;

    if (!query) {
      return res.status(400).json({ success: false, message: 'Search query is required.' });
    }

    // Perform case-insensitive search on product titles
    const regex = new RegExp(query, 'i');

    const products = await Product.find({ title: regex, isActive: true })
      .limit(10)
      .populate('tags');

    res.status(200).json({
      success: true,
      products,
    });
  } catch (error) {
    logger.error('Search Products Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Get all products with filters and pagination
 * @route   GET /api/products
 * @access  Public/Admin
 */
exports.getAllProducts = async (req, res) => {
  try {
    const {
      category,
      tags,
      priceMin,
      priceMax,
      inStock,
      variants,
      packaging,
      page = 1,
      limit = 100,
    } = req.query; // Set default limit to 100

    let query = {};

    // Filter by category if provided and not 'All'
    if (category && category !== 'All') {
      query.category = category;
    }

    // Filter by tags if provided
    if (tags) {
      const tagsArray = tags.split(',').map(tag => tag.trim());
      query.tags = { $in: tagsArray };
    }

    // Filter by variants if provided
    if (variants) {
      const variantsArray = variants.split(',').map(v => v.trim());
      query['variants.size'] = { $in: variantsArray };
    }

    // Filter by packaging if provided and not 'All'
    if (packaging && packaging !== 'All') {
      query.packaging = packaging;
    }

    // Filter by price range if provided
    if (priceMin || priceMax) {
      query.price = {};
      if (priceMin) query.price.$gte = Number(priceMin);
      if (priceMax) query.price.$lte = Number(priceMax);
    }

    // Filter by stock status if provided
    if (inStock !== undefined) {
      query.stock = inStock === 'true' ? { $gt: 0 } : { $eq: 0 };
    }

    // Pagination calculations
    const total = await Product.countDocuments(query);
    const totalPages = Math.ceil(total / limit);
    const products = await Product.find(query)
      .populate('tags')
      .skip((page - 1) * limit)
      .limit(Number(limit));

    res.status(200).json({
      success: true,
      total, // Total number of matching products
      count: products.length,
      totalPages,
      currentPage: Number(page),
      products, // Changed from 'data' to 'products' for consistency
    });
  } catch (error) {
    logger.error('Get All Products Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Update a product by ID
 * @route   PUT /api/products/:id
 * @access  Private/Admin/Product Manager
 */
exports.updateProduct = async (req, res) => {
  try {
    const updates = req.body;
    const productId = req.params.id;

    let product = await Product.findById(productId);

    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    // If tags are being updated, convert them to ObjectIds
    if (updates.tags && Array.isArray(updates.tags)) {
      // Now, assuming tags are sent as IDs
      const foundTags = await Tag.find({ _id: { $in: updates.tags } });
      if (foundTags.length !== updates.tags.length) {
        return res.status(400).json({
          success: false,
          message: 'One or more tags are invalid.',
        });
      }
      updates.tags = foundTags.map(tag => tag._id);
    }

    // If variants are being updated, ensure there's at least one variant
    if (updates.variants) {
      if (!Array.isArray(updates.variants) || updates.variants.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'At least one variant is required.',
        });
      }
    }

    // Update each field if provided
    Object.keys(updates).forEach((key) => {
      if (key === 'accordion' && typeof updates[key] === 'object') {
        product.accordion = { ...product.accordion, ...updates[key] };
      } else {
        product[key] = updates[key];
      }
    });

    await product.save();

    // Optional: Log the update in AuditLog
    // await AuditLog.create({
    //   performedBy: req.user._id,
    //   entityId: product._id,
    //   entity: 'Product',
    //   action: 'UPDATE',
    //   details: `Updated product with title: ${product.title}`,
    // });

    res.status(200).json({
      success: true,
      data: product,
    });
  } catch (error) {
    logger.error('Update Product Error:', error);

    // Handle specific Mongoose validation errors
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => ({
        field: err.path,
        message: err.message,
      }));
      return res.status(400).json({
        success: false,
        message: 'Validation Error',
        errors,
      });
    }

    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Delete (deactivate) a product by ID
 * @route   DELETE /api/products/:id
 * @access  Private/Admin/Product Manager
 */
exports.deleteProduct = async (req, res) => {
  try {
    const productId = req.params.id;

    let product = await Product.findById(productId);

    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    product.isActive = false; // Soft delete
    await product.save();

    // Optional: Log the deletion in AuditLog
    // await AuditLog.create({
    //   performedBy: req.user._id,
    //   entityId: product._id,
    //   entity: 'Product',
    //   action: 'DELETE',
    //   details: `Deactivated product with title: ${product.title}`,
    // });

    res.status(200).json({
      success: true,
      message: 'Product deactivated successfully',
    });
  } catch (error) {
    logger.error('Delete Product Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Update product stock level
 * @route   PUT /api/products/:id/stock
 * @access  Private/Admin/Product Manager
 */
exports.updateProductStock = async (req, res) => {
  try {
    const { stock } = req.body;
    const productId = req.params.id;

    let product = await Product.findById(productId);

    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    product.stock = stock;
    await product.save();

    // Optional: Log the stock update in AuditLog
    // await AuditLog.create({
    //   performedBy: req.user._id,
    //   entityId: product._id,
    //   entity: 'Product',
    //   action: 'UPDATE',
    //   details: `Updated stock for product with title: ${product.title} to ${stock}`,
    // });

    res.status(200).json({
      success: true,
      data: product,
    });
  } catch (error) {
    logger.error('Update Product Stock Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Bulk update products
 * @route   POST /api/products/bulk-update
 * @access  Private/Admin/Product Manager
 */
exports.bulkUpdateProducts = async (req, res) => {
  try {
    const { updates } = req.body; // Array of { id, fields to update }

    if (!Array.isArray(updates) || updates.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Updates must be a non-empty array.',
      });
    }

    // Prepare bulk operations
    const bulkOps = [];

    for (const update of updates) {
      const { id, fields } = update;

      if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: `Invalid product ID: ${id}`,
        });
      }

      // If tags are being updated, convert them to ObjectIds
      if (fields.tags && Array.isArray(fields.tags)) {
        // Now, assuming tags are sent as IDs
        const foundTags = await Tag.find({ _id: { $in: fields.tags } });
        if (foundTags.length !== fields.tags.length) {
          return res.status(400).json({
            success: false,
            message: `One or more tags are invalid for product ID: ${id}`,
          });
        }
        fields.tags = foundTags.map(tag => tag._id);
      }

      // If variants are being updated, ensure there's at least one variant
      if (fields.variants) {
        if (!Array.isArray(fields.variants) || fields.variants.length === 0) {
          return res.status(400).json({
            success: false,
            message: `At least one variant is required for product ID: ${id}`,
          });
        }
      }

      bulkOps.push({
        updateOne: {
          filter: { _id: id },
          update: { $set: fields },
        },
      });
    }

    // Execute bulk operations
    const result = await Product.bulkWrite(bulkOps);

    // Optional: Log the bulk update in AuditLog
    // await AuditLog.create({
    //   performedBy: req.user._id,
    //   entityId: null, // Since multiple products are updated
    //   entity: 'Product',
    //   action: 'UPDATE',
    //   details: `Bulk updated ${result.modifiedCount} products.`,
    // });

    res.status(200).json({
      success: true,
      message: `${result.modifiedCount} products updated successfully.`,
      result,
    });
  } catch (error) {
    logger.error('Bulk Update Products Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};
