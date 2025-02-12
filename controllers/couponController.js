// controllers/couponController.js

const asyncHandler = require('express-async-handler');
const mongoose = require('mongoose');
const Coupon = require('../models/Coupon');
const MESSAGES = require('../messages/en');

/**
 * @desc    Get all coupons with optional filters
 * @route   GET /api/coupons
 * @access  Private/Admin/Marketing Manager
 */
exports.getAllCoupons = asyncHandler(async (req, res, next) => {
  const {
    page = 1,
    limit = 10,
    search = '',
    expired,
    active,
    sortField = 'code',
    sortOrder = 'asc',
  } = req.query;

  const query = {};

  if (active !== undefined) {
    query.isActive = active === 'true';
  }

  if (expired !== undefined) {
    const currentDate = new Date();
    if (expired === 'true') {
      query.expirationDate = { $lt: currentDate };
    } else if (expired === 'false') {
      query.expirationDate = { $gte: currentDate };
    }
  }

  if (search) {
    query.code = { $regex: search, $options: 'i' };
  }

  const sortOptions = {};
  sortOptions[sortField] = sortOrder === 'asc' ? 1 : -1;

  const coupons = await Coupon.find(query)
    .sort(sortOptions)
    .skip((page - 1) * limit)
    .limit(parseInt(limit, 10));

  const count = await Coupon.countDocuments(query);

  res.status(200).json({
    success: true,
    data: coupons,
    count,
    message: MESSAGES.Coupon.FETCH_SUCCESS,
  });
});

/**
 * @desc    Get a single coupon by ID
 * @route   GET /api/coupons/:id
 * @access  Private/Admin/Marketing Manager
 */
exports.getCouponById = asyncHandler(async (req, res, next) => {
  const { id } = req.params;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: MESSAGES.Coupon.INVALID_ID });
  }

  const coupon = await Coupon.findById(id);

  if (!coupon) {
    return res.status(404).json({ success: false, message: MESSAGES.Coupon.Coupon_NOT_FOUND });
  }

  res.status(200).json({
    success: true,
    data: coupon,
    message: MESSAGES.Coupon.FETCH_SUCCESS,
  });
});

/**
 * @desc    Create a new coupon
 * @route   POST /api/coupons
 * @access  Private/Admin/Marketing Manager
 */
exports.createCoupon = asyncHandler(async (req, res, next) => {
  const { code, discount, discountType, expirationDate, maxUses, isActive } = req.body;

  try {
    const coupon = await Coupon.create({
      code,
      discount,
      discountType,
      expirationDate,
      maxUses,
      isActive,
    });

    res.status(201).json({
      success: true,
      data: coupon,
      message: MESSAGES.Coupon.CREATE_SUCCESS,
    });
  } catch (err) {
    if (err.code === 11000) { // Duplicate key error
      return res.status(400).json({ success: false, message: MESSAGES.Coupon.DUPLICATE_CODE });
    }
    throw err;
  }
});

/**
 * @desc    Update a coupon by ID
 * @route   PUT /api/coupons/:id
 * @access  Private/Admin/Marketing Manager
 */
exports.updateCoupon = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const { code, discount, discountType, expirationDate, maxUses, isActive } = req.body;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: MESSAGES.Coupon.INVALID_ID });
  }

  try {
    const coupon = await Coupon.findById(id);

    if (!coupon) {
      return res.status(404).json({ success: false, message: MESSAGES.Coupon.Coupon_NOT_FOUND });
    }

    // Update fields if provided
    if (code !== undefined) coupon.code = code;
    if (discount !== undefined) coupon.discount = discount;
    if (discountType !== undefined) coupon.discountType = discountType;
    if (expirationDate !== undefined) coupon.expirationDate = expirationDate;
    if (maxUses !== undefined) coupon.maxUses = maxUses;
    if (isActive !== undefined) coupon.isActive = isActive;

    await coupon.save();

    res.status(200).json({
      success: true,
      data: coupon,
      message: MESSAGES.Coupon.UPDATE_SUCCESS,
    });
  } catch (err) {
    if (err.code === 11000) { // Duplicate key error
      return res.status(400).json({ success: false, message: MESSAGES.Coupon.DUPLICATE_CODE });
    }
    throw err;
  }
});

/**
 * @desc    Permanently delete a coupon by ID
 * @route   DELETE /api/coupons/:id
 * @access  Private/Admin/Marketing Manager
 */
exports.deleteCoupon = asyncHandler(async (req, res, next) => {
  const { id } = req.params;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: MESSAGES.Coupon.INVALID_ID });
  }

  const coupon = await Coupon.findByIdAndDelete(id);

  if (!coupon) {
    return res.status(404).json({ success: false, message: MESSAGES.Coupon.Coupon_NOT_FOUND });
  }

  res.status(200).json({
    success: true,
    data: {},
    message: MESSAGES.Coupon.DELETE_SUCCESS,
  });
});

/**
 * @desc    Deactivate a coupon by ID
 * @route   POST /api/coupons/:id/deactivate
 * @access  Private/Admin/Marketing Manager
 */
exports.deactivateCoupon = asyncHandler(async (req, res, next) => {
  const { id } = req.params;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: MESSAGES.Coupon.INVALID_ID });
  }

  const coupon = await Coupon.findById(id);

  if (!coupon) {
    return res.status(404).json({ success: false, message: MESSAGES.Coupon.Coupon_NOT_FOUND });
  }

  if (!coupon.isActive) {
    return res.status(400).json({ success: false, message: MESSAGES.Coupon.ALREADY_INACTIVE });
  }

  coupon.isActive = false;
  await coupon.save();

  res.status(200).json({
    success: true,
    data: coupon,
    message: MESSAGES.Coupon.DEACTIVATE_SUCCESS,
  });
});

/**
 * @desc    Activate a coupon by ID
 * @route   POST /api/coupons/:id/activate
 * @access  Private/Admin/Marketing Manager
 */
exports.activateCoupon = asyncHandler(async (req, res, next) => {
  const { id } = req.params;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ success: false, message: MESSAGES.Coupon.INVALID_ID });
  }

  const coupon = await Coupon.findById(id);

  if (!coupon) {
    return res.status(404).json({ success: false, message: MESSAGES.Coupon.Coupon_NOT_FOUND });
  }

  if (coupon.isActive) {
    return res.status(400).json({ success: false, message: MESSAGES.Coupon.ALREADY_ACTIVE });
  }

  coupon.isActive = true;
  await coupon.save();

  res.status(200).json({
    success: true,
    data: coupon,
    message: MESSAGES.Coupon.ACTIVATE_SUCCESS,
  });
});

/**
 * @desc    Apply a coupon to an order
 * @route   POST /api/coupons/apply
 * @access  Public
 */
exports.applyCoupon = asyncHandler(async (req, res, next) => {
  const { code, orderTotal } = req.body;

  // Find the coupon
  const coupon = await Coupon.findOne({ code: code.toUpperCase() });

  if (!coupon) {
    return res.status(404).json({ success: false, message: MESSAGES.Coupon.Coupon_NOT_FOUND });
  }

  if (!coupon.isActive) {
    return res.status(400).json({ success: false, message: MESSAGES.Coupon.ALREADY_INACTIVE });
  }

  const currentDate = new Date();
  if (coupon.expirationDate < currentDate) {
    return res.status(400).json({ success: false, message: MESSAGES.Coupon.COUPON_EXPIRED });
  }

  if (coupon.maxUses !== null && coupon.usedCount >= coupon.maxUses) {
    return res.status(400).json({ success: false, message: MESSAGES.Coupon.APPLY_FAILED });
  }

  // Calculate discount
  let discountAmount = 0;
  if (coupon.discountType === 'percentage') {
    discountAmount = (coupon.discount / 100) * orderTotal;
  } else if (coupon.discountType === 'fixed') {
    discountAmount = coupon.discount;
  }

  discountAmount = Math.min(discountAmount, orderTotal); // Ensure discount does not exceed order total

  // Increment usedCount
  coupon.usedCount += 1;
  await coupon.save();

  res.status(200).json({
    success: true,
    discount: discountAmount,
    message: MESSAGES.Coupon.APPLY_SUCCESS,
  });
});
