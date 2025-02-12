const asyncHandler = require('express-async-handler');
const User = require('../models/User');
const logger = require('../utils/logger');
const mongoose = require('mongoose'); // Import mongoose

/**
 * @desc    Get all addresses of the authenticated user
 * @route   GET /api/users/addresses
 * @access  Private/User
 */
exports.getAddresses = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user._id).select('addresses');

  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found.',
    });
  }

  res.status(200).json({
    success: true,
    count: user.addresses.length,
    data: user.addresses,
    message: 'Addresses fetched successfully.',
  });
});

/**
 * @desc    Add a new address for the authenticated user
 * @route   POST /api/users/addresses
 * @access  Private/User
 */
exports.addAddress = asyncHandler(async (req, res, next) => {
  const { street, city, state, zip, country } = req.body;

  if (!street || !city || !state || !zip || !country) {
    return res.status(400).json({
      success: false,
      message: 'All address fields are required.',
    });
  }

  const user = await User.findById(req.user._id);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found.',
    });
  }

  const newAddress = { street, city, state, zip, country };
  user.addresses.push(newAddress);
  await user.save();

  res.status(201).json({
    success: true,
    data: newAddress,
    message: 'Address added successfully.',
  });
});

/**
 * @desc    Update an existing address for the authenticated user
 * @route   PUT /api/users/addresses/:id
 * @access  Private/User
 */
exports.updateAddress = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const { street, city, state, zip, country } = req.body;

  const user = await User.findById(req.user._id).select('addresses');

  if (!user) {
    return res.status(404).json({
      success: false,
      message: 'User not found.',
    });
  }

  const address = user.addresses.id(id);

  if (!address) {
    return res.status(404).json({
      success: false,
      message: 'Address not found.',
    });
  }

  if (street) address.street = street;
  if (city) address.city = city;
  if (state) address.state = state;
  if (zip) address.zip = zip;
  if (country) address.country = country;

  await user.save();

  res.status(200).json({
    success: true,
    data: address,
    message: 'Address updated successfully.',
  });
});

/**
 * @desc    Delete an address for the authenticated user
 * @route   DELETE /api/users/addresses/:id
 * @access  Private/User
 */
exports.deleteAddress = asyncHandler(async (req, res, next) => {
    const { id } = req.params;
  
    const user = await User.findById(req.user._id).select('addresses');
  
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found.',
      });
    }
  
    const address = user.addresses.id(id);
  
    if (!address) {
      return res.status(404).json({
        success: false,
        message: 'Address not found.',
      });
    }
  
    // Use pull to remove the address by ID
    user.addresses.pull(id);
    await user.save();
  
    res.status(200).json({
      success: true,
      message: 'Address deleted successfully.',
    });
  });
  