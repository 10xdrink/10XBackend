// controllers/orderController.js

const mongoose = require('mongoose'); // Added for ObjectId validation
const Order = require('../models/Order');
const Product = require('../models/Product');
const Coupon = require('../models/Coupon');
const Transaction = require('../models/Transaction');
const logger = require('../utils/logger');
const MESSAGES = require('../messages/en'); // Ensure this path is correct
const ERROR_CODES = require('../constants/errorCodes');
const asyncHandler = require('express-async-handler');
const { processPayment } = require('../services/paymentService');
const { setCache, getCache, deleteCache } = require('../services/redisService');
const crypto = require('crypto');
const sendEmail = require('../services/emailService'); // Ensure the correct path
const Joi = require('joi'); // **Added Import for Joi**

// Encryption key for sensitive data
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'defaultEncryptionKey123456'; // Replace with a secure key in production
const IV_LENGTH = 16;

// Helper function to encrypt sensitive fields
const encrypt = (text) => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
};

// Helper function to validate MongoDB ObjectId
const isValidObjectId = (id) => mongoose.Types.ObjectId.isValid(id);

// Helper function to capitalize the first letter of a string
const capitalize = (s) => {
  if (typeof s !== 'string') return '';
  return s.charAt(0).toUpperCase() + s.slice(1);
};

/**
 * @desc    Create a new order
 * @route   POST /api/orders
 * @access  Private/Customer
 */
exports.createOrder = asyncHandler(async (req, res, next) => {
  const { items, shippingAddress, billingAddress, paymentMethod, couponCode } = req.body;

  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ success: false, message: 'No items provided for the order.' });
  }

  let totalAmount = 0;
  const populatedItems = [];

  // Validate and calculate total amount
  for (const item of items) {
    const product = await Product.findById(item.product);

    if (!product || !product.isActive) {
      logger.warn(`Invalid product ID ${item.product} for order creation.`);
      return res.status(400).json({ success: false, message: `Product with ID ${item.product} is invalid.` });
    }

    // Check if 'variants' field exists and is an array
    if (!product.variants || !Array.isArray(product.variants) || product.variants.length === 0) {
      logger.warn(`Product ${product._id} (${product.title}) has undefined or invalid 'variants' field.`);
      return res.status(400).json({ success: false, message: `Product ${product.title} has invalid variants.` });
    }

    // Validate variant
    const selectedVariant = product.variants.find(
      (v) => v.size.toLowerCase() === item.variant.toLowerCase()
    );
    if (!selectedVariant) {
      logger.warn(`Variant ${item.variant} not found for product ${product.title}.`);
      return res.status(400).json({
        success: false,
        message: `Variant ${item.variant} not found for product ${product.title}.`,
      });
    }

    // Validate packaging
    if (!product.packaging.includes(item.packaging)) {
      logger.warn(`Packaging ${item.packaging} not valid for product ${product.title}.`);
      return res.status(400).json({
        success: false,
        message: `Packaging ${item.packaging} is not available for product ${product.title}.`,
      });
    }

    // Check stock
    if (selectedVariant.stock < item.quantity) {
      logger.warn(`Insufficient stock for product ${product.title}, variant ${item.variant}. Requested: ${item.quantity}, Available: ${selectedVariant.stock}`);
      return res.status(400).json({
        success: false,
        message: `Insufficient stock for product ${product.title}, variant ${item.variant}.`,
      });
    }

    // Calculate item total
    const itemTotal = selectedVariant.price * item.quantity;
    totalAmount += itemTotal;

    // Add to populated items
    populatedItems.push({
      product: product._id,
      quantity: item.quantity,
      price: selectedVariant.price,
      variant: selectedVariant.size,
      packaging: item.packaging,
    });
  }

  // Apply coupon if provided
  let discount = 0;
  if (couponCode) {
    const coupon = await Coupon.findOne({ code: couponCode, isActive: true });

    if (!coupon) {
      logger.warn(`Invalid or inactive coupon code: ${couponCode}`);
      return res.status(400).json({ success: false, message: 'Invalid or inactive coupon code.' });
    }

    // Validate coupon usage
    const couponValidation = Coupon.canApplyCoupon(coupon);
    if (!couponValidation.success) {
      logger.warn(`Coupon validation failed: ${couponValidation.message}`);
      return res.status(400).json({ success: false, message: couponValidation.message });
    }

    // Apply coupon
    discount = coupon.discountType === 'percentage' ? (totalAmount * (coupon.discount / 100)) : coupon.discount;
    totalAmount -= discount;

    // Ensure totalAmount doesn't go below zero
    totalAmount = Math.max(totalAmount, 0);

    // Increment used count
    coupon.usedCount += 1;
    if (coupon.maxUses !== null && coupon.usedCount >= coupon.maxUses) {
      coupon.isActive = false;
    }
    await coupon.save();
  }

  // Create order number
  const orderNumber = `ORD-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

  // Set initial status to 'pending'
  const order = await Order.create({
    orderNumber,
    customer: req.user._id,
    items: populatedItems,
    totalAmount,
    paymentMethod,
    shippingAddress,
    billingAddress,
    status: 'pending', // Set to 'pending' initially
    paymentStatus: ['cod', 'cash_on_delivery'].includes(paymentMethod.toLowerCase()) ? 'pending' : 'paid', // Updated assignment
    discount,
    couponCode: couponCode || null,
  });

  // Send Order Confirmation Email
  try {
    const populatedOrder = await order.populate('items.product', 'title thumbnail');

    const emailHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Order Confirmation</title>
      <!-- Import Poppins Font from Google Fonts -->
      <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&display=swap" rel="stylesheet">
      <style>
        /* Reset some default styles */
        body, html {
          margin: 0;
          padding: 0;
          width: 100%;
          height: 100%;
        }

        .logo{
            margin-bottom: 20px;
            background: #061aab; 
            text-align: center;
            padding: 30px 20px;
        }

        /* Base styles */
        body {
          font-family: 'Poppins', sans-serif;
          background-color: #f4f6f8;
          padding: 20px;
          color: #333333;
        }

        .container {
          background-color: #ffffff;
          padding: 40px;
          border-radius: 12px;
          max-width: 600px;
          margin: auto;
          box-shadow: 0 4px 20px rgba(0,0,0,0.1);
          text-align: start;
        }

        .logo img {
          width: 150px;
          height: auto;
        }

        h2 {
          color: #000000; /* Brand Color */
          margin-bottom: 20px;
          font-weight: 700;
          font-size: 24px;
        }

        p {
          color: #000000;
          font-weight: 300;
          line-height: 1.6;
          margin-bottom: 20px;
          font-size: 16px;
        }

        a{
            color: #061aab;
            text-decoration: none;
        }

        .button {
          display: inline-block;
          padding: 14px 28px;
          background: #061aab; /* Solid Brand Color */
          color: #ffffff;
          text-decoration: none;
          border-radius: 4px;
          font-family: 'Poppins', sans-serif;
          font-weight: 600;
          transition: background 0.3s ease, transform 0.3s ease;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .button:hover {
          background: #0041c4;
          transform: translateY(-2px);
          box-shadow: 0 6px 8px rgba(0, 0, 0, 0.15);
        }

        .order-summary {
          width: 100%;
          border-collapse: collapse;
          margin-bottom: 20px;
        }

        .order-summary th, .order-summary td {
          border: 1px solid #e0e0e0;
          padding: 10px;
          text-align: left;
        }

        .order-summary th {
          background-color: #f9f9f9;
        }

        .footer {
          margin-top: 30px;
          font-size: 14px;
          color: #000000;
          border-top: 1px solid #e0e0e0;
          padding-top: 20px;
        }

        .footer p {
          margin: 0;
        }

        /* Responsive Design */
        @media (max-width: 600px) {
          .container {
            padding: 20px;
          }

          .button {
            width: 100%;
            padding: 12px 0;
          }

          h2 {
            font-size: 20px;
          }

          p {
            font-size: 14px;
          }

          .order-summary th, .order-summary td {
            padding: 8px;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <!-- Logo Section -->
        <div class="logo">
          <img src="https://res.cloudinary.com/dvbbsgj1u/image/upload/v1731090126/tesnhlpvlo6w9bdjepag.png" alt="Your Company Logo">
        </div>
      
        <h2>Order Confirmation</h2>
        <p>Hi ${req.user.name},</p>
        <p>Thank you for your purchase! Your order has been received and is currently pending approval. Once approved by our team, you will receive an update.</p>

        <table class="order-summary">
          <thead>
            <tr>
              <th>Product</th>
              <th>Title</th>
              <th>Quantity</th>
              <th>Price</th>
              <th>Subtotal</th>
            </tr>
          </thead>
          <tbody>
            ${populatedOrder.items.map(item => `
              <tr>
                <td><img src="${item.product.thumbnail || 'https://via.placeholder.com/50'}" alt="${item.product.title}" width="50" height="50"></td>
                <td>${item.product.title}</td>
                <td>${item.quantity}</td>
                <td>$${item.price.toFixed(2)}</td>
                <td>$${(item.price * item.quantity).toFixed(2)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>

        <p><strong>Subtotal:</strong> $${(totalAmount + discount).toFixed(2)}</p>
        ${discount > 0 ? `<p><strong>Discount:</strong> -$${discount.toFixed(2)}</p>` : ''}
        <p><strong>Total Amount:</strong> $${totalAmount.toFixed(2)}</p>

        <p>Your order status is currently: <strong>${capitalize(order.status)}</strong>.</p>

        <p>If you have any questions or need further assistance, feel free to <a href="${process.env.SUPPORT_URL || 'http://localhost:5173/contact'}">contact our support team</a>.</p>

        <p>Thank you for choosing us!</p>
        
        <div class="footer">
          <p>Best regards, <br/>10X Formulas</p>
          <p><a href="${process.env.SUPPORT_URL || 'http://localhost:5173/contact'}">Contact Support</a></p>
        </div>
      </div>
    </body>
    </html>
    `;

    await sendEmail({
      email: req.user.email,
      subject: 'Your Order Confirmation - 10X Formulas',
      message: `Hi ${req.user.name}, your order has been received and is pending approval.`,
      html: emailHtml,
    });

    logger.info(`Order confirmation email sent to ${req.user.email}`);
  } catch (emailError) {
    logger.error(`Failed to send order confirmation email to ${req.user.email}: ${emailError.message}`);
    // Optionally, you can choose to proceed without failing the order creation
  }

  // For 'cod' payments, no immediate stock deduction or processing is done
  // Payment status remains 'pending' until the admin accepts the order

  // For online payments, payment is still 'paid' if not 'cod' or 'cash_on_delivery'
  // You might want to integrate payment verification based on your payment gateway

  // Invalidate cache if necessary
  await deleteCache(`orders_${req.user._id}`);
  await deleteCache('all_orders');

  res.status(201).json({
    success: true,
    data: order,
    message: MESSAGES.ORDER.CREATE_SUCCESS || 'Order created successfully.',
  });
});

/**
 * @desc    Admin Accept Order - Transition from Pending to Processing
 * @route   PUT /api/orders/:id/accept
 * @access  Private/Admin
 */
exports.acceptOrder = asyncHandler(async (req, res, next) => {
  const { id } = req.params;

  // Validate the order ID
  if (!isValidObjectId(id)) {
    logger.warn(`Invalid order ID received: ${id}`);
    return res.status(400).json({
      success: false,
      message: 'Invalid order ID.',
    });
  }

  const order = await Order.findById(id)
    .populate('customer', 'name email')
    .populate('items.product', 'title thumbnail variants');

  if (!order) {
    logger.warn(`Order with ID ${id} not found.`);
    return res.status(404).json({
      success: false,
      message: MESSAGES.ORDER.ORDER_NOT_FOUND || 'Order not found.',
    });
  }

  if (order.status !== 'pending') {
    logger.warn(`Attempted to accept order ${order._id} with status ${order.status}.`);
    return res.status(400).json({
      success: false,
      message: `Only orders with 'pending' status can be accepted.`,
    });
  }

  // Update status to 'processing'
  order.status = 'processing';
  order.updatedAt = Date.now();

  // Deduct stock
  try {
    await Promise.all(
      order.items.map(async (item) => {
        const product = await Product.findById(item.product._id);
        if (!product) {
          throw new Error(`Product with ID ${item.product._id} not found.`);
        }

        if (!product.variants || !Array.isArray(product.variants)) {
          throw new Error(`Product ${product.title} has invalid variants.`);
        }

        const variant = product.variants.find(v => v.size.toLowerCase() === item.variant.toLowerCase());
        if (!variant) {
          throw new Error(`Variant ${item.variant} not found for product ${product.title}.`);
        }

        if (variant.stock < item.quantity) {
          throw new Error(`Insufficient stock for product ${product.title}, variant ${item.variant}.`);
        }

        variant.stock -= item.quantity;
        await product.save();
      })
    );
  } catch (stockError) {
    logger.error(`Stock Deduction Error for Order ID ${order._id}: ${stockError.message}`);
    return res.status(400).json({
      success: false,
      message: stockError.message || 'Error deducting stock.',
    });
  }

  await order.save();

  // Invalidate cache
  await deleteCache(`orders_${order.customer._id}`);
  await deleteCache('all_orders');

  // Send Order Accepted Email
  try {
    const emailHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Order Accepted</title>
      <!-- Import Poppins Font from Google Fonts -->
      <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&display=swap" rel="stylesheet">
      <style>
        /* Styles as defined in previous email templates */
        body, html {
          margin: 0;
          padding: 0;
          width: 100%;
          height: 100%;
        }

        .logo{
            margin-bottom: 20px;
            background: #061aab; 
            text-align: center;
            padding: 30px 20px;
        }

        /* Base styles */
        body {
          font-family: 'Poppins', sans-serif;
          background-color: #f4f6f8;
          padding: 20px;
          color: #333333;
        }

        .container {
          background-color: #ffffff;
          padding: 40px;
          border-radius: 12px;
          max-width: 600px;
          margin: auto;
          box-shadow: 0 4px 20px rgba(0,0,0,0.1);
          text-align: start;
        }

        .logo img {
          width: 150px;
          height: auto;
        }

        h2 {
          color: #000000; /* Brand Color */
          margin-bottom: 20px;
          font-weight: 700;
          font-size: 24px;
        }

        p {
          color: #000000;
          font-weight: 300;
          line-height: 1.6;
          margin-bottom: 20px;
          font-size: 16px;
        }

        a{
            color: #061aab;
            text-decoration: none;
        }

        .button {
          display: inline-block;
          padding: 14px 28px;
          background: #061aab; /* Solid Brand Color */
          color: #ffffff;
          text-decoration: none;
          border-radius: 4px;
          font-family: 'Poppins', sans-serif;
          font-weight: 600;
          transition: background 0.3s ease, transform 0.3s ease;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .button:hover {
          background: #0041c4;
          transform: translateY(-2px);
          box-shadow: 0 6px 8px rgba(0, 0, 0, 0.15);
        }

        .order-summary {
          width: 100%;
          border-collapse: collapse;
          margin-bottom: 20px;
        }

        .order-summary th, .order-summary td {
          border: 1px solid #e0e0e0;
          padding: 10px;
          text-align: left;
        }

        .order-summary th {
          background-color: #f9f9f9;
        }

        .footer {
          margin-top: 30px;
          font-size: 14px;
          color: #000000;
          border-top: 1px solid #e0e0e0;
          padding-top: 20px;
        }

        .footer p {
          margin: 0;
        }

        /* Responsive Design */
        @media (max-width: 600px) {
          .container {
            padding: 20px;
          }

          .button {
            width: 100%;
            padding: 12px 0;
          }

          h2 {
            font-size: 20px;
          }

          p {
            font-size: 14px;
          }

          .order-summary th, .order-summary td {
            padding: 8px;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <!-- Logo Section -->
        <div class="logo">
          <img src="https://res.cloudinary.com/dvbbsgj1u/image/upload/v1731090126/tesnhlpvlo6w9bdjepag.png" alt="Your Company Logo">
        </div>
      
        <h2>Your Order is Now Processing</h2>
        <p>Hi ${order.customer.name},</p>
        <p>Great news! Your order <strong>${order.orderNumber}</strong> has been accepted and is now being processed. We will notify you once your order has been shipped.</p>

        <table class="order-summary">
          <thead>
            <tr>
              <th>Product</th>
              <th>Title</th>
              <th>Quantity</th>
              <th>Price</th>
              <th>Subtotal</th>
            </tr>
          </thead>
          <tbody>
            ${order.items.map(item => `
              <tr>
                <td><img src="${item.product.thumbnail || 'https://via.placeholder.com/50'}" alt="${item.product.title}" width="50" height="50"></td>
                <td>${item.product.title}</td>
                <td>${item.quantity}</td>
                <td>$${item.price.toFixed(2)}</td>
                <td>$${(item.price * item.quantity).toFixed(2)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>

        <p><strong>Subtotal:</strong> $${(order.totalAmount + order.discount).toFixed(2)}</p>
        ${order.discount > 0 ? `<p><strong>Discount:</strong> -$${order.discount.toFixed(2)}</p>` : ''}
        <p><strong>Total Amount:</strong> $${order.totalAmount.toFixed(2)}</p>

        <p>Your order status is currently: <strong>${capitalize(order.status)}</strong>.</p>

        <p>If you have any questions or need further assistance, feel free to <a href="${process.env.SUPPORT_URL || 'http://localhost:5173/contact'}">contact our support team</a>.</p>

        <p>Thank you for choosing us!</p>
        
        <div class="footer">
          <p>Best regards, <br/>10X Formulas</p>
          <p><a href="${process.env.SUPPORT_URL || 'http://localhost:5173/contact'}">Contact Support</a></p>
        </div>
      </div>
    </body>
    </html>
    `;

    await sendEmail({
      email: order.customer.email,
      subject: 'Your Order is Now Processing - 10X Formulas',
      message: `Hi ${order.customer.name}, your order is now processing.`,
      html: emailHtml,
    });

    logger.info(`Order accepted email sent to ${order.customer.email}`);
  } catch (emailError) {
    logger.error(`Failed to send order accepted email to ${order.customer.email}: ${emailError.message}`);
    // Optionally, handle email sending failure
  }

  res.status(200).json({
    success: true,
    data: order,
    message: 'Order has been accepted and is now processing.',
  });
});

/**
 * @desc    Update order status
 * @route   PUT /api/orders/:id/status
 * @access  Private/Admin/Order Manager
 */
exports.updateOrderStatus = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const { status } = req.body;

  // Validate the order ID
  if (!isValidObjectId(id)) {
    logger.warn(`Invalid order ID received: ${id}`);
    return res.status(400).json({
      success: false,
      message: 'Invalid order ID.',
    });
  }

  // Fetch the order and populate necessary fields
  const order = await Order.findById(id)
    .populate('customer', 'name email')
    .populate('items.product', 'title thumbnail');

  if (!order) {
    logger.warn(`Order with ID ${id} not found.`);
    return res.status(404).json({
      success: false,
      message: MESSAGES.ORDER.ORDER_NOT_FOUND || 'Order not found.',
    });
  }

  // Define allowed status transitions (Extended to include additional transitions)
  const allowedTransitions = {
    pending: ['processing', 'shipped', 'delivered', 'cancelled'],
    processing: ['shipped', 'delivered', 'cancelled'],
    shipped: ['delivered', 'refunded'],
    delivered: ['refunded'],
    cancelled: [],
    refunded: [],
  };

  if (!allowedTransitions[order.status].includes(status)) {
    logger.warn(`Invalid status transition from ${order.status} to ${status} for Order ID ${id}.`);
    return res.status(400).json({ success: false, message: 'Invalid status transition.' });
  }

  // Update the order status
  order.status = status;

  // Handle specific status changes
  if (status === 'shipped') {
    // Set shipping date
    order.shippingDate = Date.now();
    logger.info(`Order ID ${order._id} marked as shipped.`);
  } else if (status === 'delivered') {
    // Set delivery date
    order.deliveryDate = Date.now();
    logger.info(`Order ID ${order._id} marked as delivered.`);

    // Send Order Delivered Email
    try {
      const emailHtml = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Order Delivered</title>
        <!-- Import Poppins Font from Google Fonts -->
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&display=swap" rel="stylesheet">
        <style>
          /* Reset some default styles */
          body, html {
            margin: 0;
            padding: 0;
            width: 100%;
            height: 100%;
          }

          .logo{
              margin-bottom: 20px;
              background: #061aab; 
              text-align: center;
              padding: 30px 20px;
          }

          /* Base styles */
          body {
            font-family: 'Poppins', sans-serif;
            background-color: #f4f6f8;
            padding: 20px;
            color: #333333;
          }

          .container {
            background-color: #ffffff;
            padding: 40px;
            border-radius: 12px;
            max-width: 600px;
            margin: auto;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            text-align: start;
          }

          .logo img {
            width: 150px;
            height: auto;
          }

          h2 {
            color: #000000; /* Brand Color */
            margin-bottom: 20px;
            font-weight: 700;
            font-size: 24px;
          }

          p {
            color: #000000;
            font-weight: 300;
            line-height: 1.6;
            margin-bottom: 20px;
            font-size: 16px;
          }

          a{
              color: #061aab;
              text-decoration: none;
          }

          .button {
            display: inline-block;
            padding: 14px 28px;
            background: #061aab; /* Solid Brand Color */
            color: #ffffff;
            text-decoration: none;
            border-radius: 4px;
            font-family: 'Poppins', sans-serif;
            font-weight: 600;
            transition: background 0.3s ease, transform 0.3s ease;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          }

          .button:hover {
            background: #0041c4;
            transform: translateY(-2px);
            box-shadow: 0 6px 8px rgba(0, 0, 0, 0.15);
          }

          .order-summary {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
          }

          .order-summary th, .order-summary td {
            border: 1px solid #e0e0e0;
            padding: 10px;
            text-align: left;
          }

          .order-summary th {
            background-color: #f9f9f9;
          }

          .footer {
            margin-top: 30px;
            font-size: 14px;
            color: #000000;
            border-top: 1px solid #e0e0e0;
            padding-top: 20px;
          }

          .footer p {
            margin: 0;
          }

          /* Responsive Design */
          @media (max-width: 600px) {
            .container {
              padding: 20px;
            }

            .button {
              width: 100%;
              padding: 12px 0;
            }

            h2 {
              font-size: 20px;
            }

            p {
              font-size: 14px;
            }

            .order-summary th, .order-summary td {
              padding: 8px;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <!-- Logo Section -->
          <div class="logo">
            <img src="https://res.cloudinary.com/dvbbsgj1u/image/upload/v1731090126/tesnhlpvlo6w9bdjepag.png" alt="Your Company Logo">
          </div>
        
          <h2>Your Order Has Been Delivered!</h2>
          <p>Hi ${order.customer.name},</p>
          <p>We're thrilled to let you know that your order has been successfully delivered. We hope you enjoy your purchase! Here are the details of your order:</p>

          <table class="order-summary">
            <thead>
              <tr>
                <th>Product</th>
                <th>Title</th>
                <th>Quantity</th>
                <th>Price</th>
                <th>Subtotal</th>
              </tr>
            </thead>
            <tbody>
              ${order.items.map(item => `
                <tr>
                  <td><img src="${item.product.thumbnail || 'https://via.placeholder.com/50'}" alt="${item.product.title}" width="50" height="50"></td>
                  <td>${item.product.title}</td>
                  <td>${item.quantity}</td>
                  <td>$${item.price.toFixed(2)}</td>
                  <td>$${(item.price * item.quantity).toFixed(2)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>

          <p><strong>Subtotal:</strong> $${(order.totalAmount + order.discount).toFixed(2)}</p>
          ${order.discount > 0 ? `<p><strong>Discount:</strong> -$${order.discount.toFixed(2)}</p>` : ''}
          <p><strong>Total Amount:</strong> $${order.totalAmount.toFixed(2)}</p>

          <p>Your order status is currently: <strong>${capitalize(order.status)}</strong>.</p>

          <p>If you have any questions or need further assistance, feel free to <a href="${process.env.SUPPORT_URL || 'http://localhost:5173/contact'}">contact our support team</a>.</p>

          <p>Thank you for shopping with us!</p>
          
          <div class="footer">
            <p>Best regards, <br/>10X Formulas</p>
            <p><a href="${process.env.SUPPORT_URL || 'http://localhost:5173/contact'}">Contact Support</a></p>
          </div>
        </div>
      </body>
      </html>
      `;

      await sendEmail({
        email: order.customer.email,
        subject: 'Your Order Has Been Delivered - 10X Formulas',
        message: `Hi ${order.customer.name}, your order has been delivered.`,
        html: emailHtml,
      });

      logger.info(`Order delivered email sent to ${order.customer.email}`);
    } catch (emailError) {
      logger.error(`Failed to send order delivered email to ${order.customer.email}: ${emailError.message}`);
      // Optionally, handle email sending failure
    }
  }

  await order.save();

  // Invalidate cache
  await deleteCache(`orders_${order.customer._id}`);
  await deleteCache('all_orders');

  res.status(200).json({
    success: true,
    data: order,
    message: 'Order status updated successfully.',
  });
});

/**
 * @desc    Cancel an order
 * @route   POST /api/orders/:id/cancel
 * @access  Private/Admin/Order Manager
 */
exports.cancelOrder = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const { reason } = req.body;

  // Validate the order ID
  if (!isValidObjectId(id)) {
    logger.warn(`Invalid order ID received: ${id}`);
    return res.status(400).json({
      success: false,
      message: 'Invalid order ID.',
    });
  }

  const order = await Order.findById(id)
    .populate('customer', 'name email')
    .populate('items.product', 'title thumbnail');

  if (!order) {
    logger.warn(`Order with ID ${id} not found.`);
    return res.status(404).json({
      success: false,
      message: MESSAGES.ORDER.ORDER_NOT_FOUND || 'Order not found.',
    });
  }

  if (order.status === 'cancelled' || order.status === 'refunded') {
    return res.status(400).json({
      success: false,
      message: 'Order is already cancelled or refunded.',
    });
  }

  // If the order is in 'processing' or beyond, restore stock
  if (['processing', 'shipped', 'delivered'].includes(order.status)) {
    try {
      await Promise.all(
        order.items.map(async (item) => {
          const product = await Product.findById(item.product._id);
          if (!product) {
            throw new Error(`Product with ID ${item.product._id} not found.`);
          }

          if (!product.variants || !Array.isArray(product.variants)) {
            throw new Error(`Product ${product.title} has invalid variants.`);
          }

          const variant = product.variants.find(v => v.size.toLowerCase() === item.variant.toLowerCase());
          if (!variant) {
            throw new Error(`Variant ${item.variant} not found for product ${product.title}.`);
          }

          variant.stock += item.quantity;
          await product.save();
        })
      );
    } catch (stockError) {
      logger.error(`Stock Restoration Error for Order ID ${order._id}: ${stockError.message}`);
      return res.status(400).json({
        success: false,
        message: stockError.message || 'Error restoring stock.',
      });
    }
  }

  order.status = 'cancelled';
  order.paymentStatus = 'refunded'; // Assuming full refund
  order.cancellationReason = reason || 'No reason provided.';
  order.updatedAt = Date.now();

  await order.save();

  // Invalidate cache
  await deleteCache(`orders_${order.customer._id}`);
  await deleteCache('all_orders');

  // Send Order Cancellation Email
  try {
    const emailHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Order Cancellation</title>
      <!-- Import Poppins Font from Google Fonts -->
      <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&display=swap" rel="stylesheet">
      <style>
        /* Reset some default styles */
        body, html {
          margin: 0;
          padding: 0;
          width: 100%;
          height: 100%;
        }

        .logo{
            margin-bottom: 20px;
            background: #061aab; 
            text-align: center;
            padding: 30px 20px;
        }

        /* Base styles */
        body {
          font-family: 'Poppins', sans-serif;
          background-color: #f4f6f8;
          padding: 20px;
          color: #333333;
        }

        .container {
          background-color: #ffffff;
          padding: 40px;
          border-radius: 12px;
          max-width: 600px;
          margin: auto;
          box-shadow: 0 4px 20px rgba(0,0,0,0.1);
          text-align: start;
        }

        .logo img {
          width: 150px;
          height: auto;
        }

        h2 {
          color: #000000; /* Brand Color */
          margin-bottom: 20px;
          font-weight: 700;
          font-size: 24px;
        }

        p {
          color: #000000;
          font-weight: 300;
          line-height: 1.6;
          margin-bottom: 20px;
          font-size: 16px;
        }

        a{
            color: #061aab;
            text-decoration: none;
        }

        .button {
          display: inline-block;
          padding: 14px 28px;
          background: #061aab; /* Solid Brand Color */
          color: #ffffff;
          text-decoration: none;
          border-radius: 4px;
          font-family: 'Poppins', sans-serif;
          font-weight: 600;
          transition: background 0.3s ease, transform 0.3s ease;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .button:hover {
          background: #0041c4;
          transform: translateY(-2px);
          box-shadow: 0 6px 8px rgba(0, 0, 0, 0.15);
        }

        .order-summary {
          width: 100%;
          border-collapse: collapse;
          margin-bottom: 20px;
        }

        .order-summary th, .order-summary td {
          border: 1px solid #e0e0e0;
          padding: 10px;
          text-align: left;
        }

        .order-summary th {
          background-color: #f9f9f9;
        }

        .footer {
          margin-top: 30px;
          font-size: 14px;
          color: #000000;
          border-top: 1px solid #e0e0e0;
          padding-top: 20px;
        }

        .footer p {
          margin: 0;
        }

        /* Responsive Design */
        @media (max-width: 600px) {
          .container {
            padding: 20px;
          }

          .button {
            width: 100%;
            padding: 12px 0;
          }

          h2 {
            font-size: 20px;
          }

          p {
            font-size: 14px;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <!-- Logo Section -->
        <div class="logo">
          <img src="https://res.cloudinary.com/dvbbsgj1u/image/upload/v1731090126/tesnhlpvlo6w9bdjepag.png" alt="Your Company Logo">
        </div>
      
        <h2>Your Order Has Been Cancelled</h2>
        <p>Hi ${order.customer.name},</p>
        <p>We're sorry to inform you that your order with order number <strong>${order.orderNumber}</strong> has been cancelled.</p>
        ${reason ? `<p>Reason: ${reason}</p>` : ''}
        <p>If you have any questions or need further assistance, feel free to <a href="${process.env.SUPPORT_URL || 'http://localhost:5173/contact'}">contact our support team</a>.</p>

        <p>Thank you for your understanding.</p>
        
        <div class="footer">
          <p>Best regards, <br/>10X Formulas</p>
          <p><a href="${process.env.SUPPORT_URL || 'http://localhost:5173/contact'}">Contact Support</a></p>
        </div>
      </div>
    </body>
    </html>
    `;

    await sendEmail({
      email: order.customer.email,
      subject: 'Your Order Has Been Cancelled - 10X Formulas',
      message: `Hi ${order.customer.name}, your order has been cancelled.`,
      html: emailHtml,
    });

    logger.info(`Order cancellation email sent to ${order.customer.email}`);
  } catch (emailError) {
    logger.error(`Failed to send order cancellation email to ${order.customer.email}: ${emailError.message}`);
    // Optionally, handle email sending failure
  }

  res.status(200).json({
    success: true,
    message: MESSAGES.ORDER.CANCEL_SUCCESS || 'Order cancelled successfully.',
  });
});

/**
 * @desc    Get all orders with optional filters
 * @route   GET /api/orders
 * @access  Private/Admin/Order Manager/Analytics Viewer
 */
exports.getAllOrders = asyncHandler(async (req, res, next) => {
  const { status, dateFrom, dateTo, customer, page = 1, limit = 10 } = req.query;
  let filter = {};

  if (status) {
    filter.status = status;
  }

  if (customer) {
    if (isValidObjectId(customer)) {
      filter.customer = customer;
    } else {
      return res.status(400).json({ success: false, message: 'Invalid customer ID.' });
    }
  }

  if (dateFrom || dateTo) {
    filter.createdAt = {};
    if (dateFrom) filter.createdAt.$gte = new Date(dateFrom);
    if (dateTo) filter.createdAt.$lte = new Date(dateTo);
  }

  const skip = (page - 1) * limit;

  try {
    const orders = await Order.find(filter)
      .populate('customer', 'name email')
      .populate('items.product', 'title thumbnail') // Changed 'images' to 'thumbnail'
      .sort({ createdAt: -1 })
      .skip(parseInt(skip))
      .limit(parseInt(limit));

    const total = await Order.countDocuments(filter);

    res.status(200).json({
      success: true,
      count: orders.length,
      total,
      data: orders,
      message: MESSAGES.ORDER.FETCH_SUCCESS || 'Orders fetched successfully.',
    });
  } catch (error) {
    logger.error(`Error fetching all orders: ${error.message}`, { timestamp: new Date().toISOString() });
    res.status(500).json({
      success: false,
      message: error.message || "An unexpected error occurred.",
      errorDetails: error.stack || null,
    });
  }
});

/**
 * @desc    Get authenticated user's orders
 * @route   GET /api/orders/my-orders
 * @access  Private/Customer
 */
exports.getMyOrders = asyncHandler(async (req, res, next) => {
  const { page = 1, limit = 10, status, dateFrom, dateTo } = req.query;

  let filter = { customer: req.user._id };

  if (status) {
    filter.status = status;
  }

  if (dateFrom || dateTo) {
    filter.createdAt = {};
    if (dateFrom) filter.createdAt.$gte = new Date(dateFrom);
    if (dateTo) filter.createdAt.$lte = new Date(dateTo);
  }

  const skip = (page - 1) * limit;

  try {
    const orders = await Order.find(filter)
      .populate('items.product', 'title thumbnail') // Changed 'images' to 'thumbnail'
      .sort({ createdAt: -1 })
      .skip(parseInt(skip))
      .limit(parseInt(limit));

    const total = await Order.countDocuments(filter);

    res.status(200).json({
      success: true,
      count: orders.length,
      total,
      data: orders,
      message: 'Orders fetched successfully.',
    });
  } catch (error) {
    logger.error(`Error fetching user's orders: ${error.message}`, { timestamp: new Date().toISOString() });
    res.status(500).json({
      success: false,
      message: error.message || "An unexpected error occurred.",
      errorDetails: error.stack || null,
    });
  }
});

/**
 * @desc    Get a single order by ID
 * @route   GET /api/orders/:id
 * @access  Private/Admin/Order Manager/Customer
 */
exports.getOrderById = asyncHandler(async (req, res, next) => {
  const { id } = req.params;

  // Validate the order ID
  if (!isValidObjectId(id)) {
    logger.warn(`Invalid order ID received: ${id}`);
    return res.status(400).json({
      success: false,
      message: 'Invalid order ID.',
    });
  }

  const order = await Order.findById(id)
    .populate('customer', 'name email')
    .populate('items.product', 'title thumbnail'); // Changed 'images' to 'thumbnail'

  if (!order) {
    logger.warn(`Order with ID ${id} not found.`);
    return res.status(404).json({
      success: false,
      message: MESSAGES.ORDER.ORDER_NOT_FOUND || 'Order not found.',
    });
  }

  // If the user is a customer, ensure they own the order
  if (req.user.role === 'user' && String(order.customer._id) !== String(req.user._id)) {
    logger.warn(`User ${req.user._id} attempted to access order ${order._id} not owned by them.`);
    return res.status(403).json({
      success: false,
      message: MESSAGES.GENERAL.FORBIDDEN || 'Access forbidden.',
    });
  }

  res.status(200).json({
    success: true,
    data: order,
    message: MESSAGES.ORDER.FETCH_SUCCESS || 'Order fetched successfully.',
  });
});

// src/controllers/orderController.js

/**
 * @desc    Get Order Metrics
 * @route   GET /api/orders/metrics
 * @access  Private/Admin/Order Manager/Analytics Viewer
 */
exports.getOrderMetrics = asyncHandler(async (req, res, next) => {
  const { dateFrom, dateTo } = req.query;

  let match = {};

  // Filter by date range if provided
  if (dateFrom || dateTo) {
    match.createdAt = {};
    if (dateFrom) match.createdAt.$gte = new Date(dateFrom);
    if (dateTo) match.createdAt.$lte = new Date(dateTo);
  }

  // Main aggregation pipeline
  const pipeline = [
    { $match: match },
    {
      $facet: {
        // 1) Total Orders
        totalOrders: [{ $count: 'count' }],

        // 2) Repeat Orders
        repeatOrders: [
          {
            $group: {
              _id: '$customer',
              orderCount: { $sum: 1 },
            },
          },
          { $match: { orderCount: { $gt: 1 } } },
          { $count: 'count' },
        ],

        // 3) New Orders
        newOrders: [
          {
            $group: {
              _id: '$customer',
              orderCount: { $sum: 1 },
            },
          },
          { $match: { orderCount: { $eq: 1 } } }, // First-time customers
          { $count: 'count' },
        ],

        // 4) Abandoned Orders
        abandonedOrders: [
          { $match: { status: 'abandoned' } },
          { $count: 'count' },
        ],

        // 5) Gross Merchandise Value (GMV)
        grossRevenue: [
          {
            $group: {
              _id: null,
              totalGMV: { $sum: '$totalAmount' },
            },
          },
        ],

        // 6) Net Revenue
        netRevenue: [
          {
            $group: {
              _id: null,
              totalNetRevenue: { $sum: '$totalAmount' },
              totalDiscount: { $sum: '$discount' },
              totalRefunds: {
                $sum: {
                  $cond: [{ $eq: ['$paymentStatus', 'refunded'] }, '$totalAmount', 0],
                },
              },
            },
          },
          {
            $project: {
              totalNetRevenue: {
                $subtract: ['$totalNetRevenue', { $add: ['$totalDiscount', '$totalRefunds'] }],
              },
            },
          },
        ],

        // 7) Average Order Value (AOV)
        averageOrderValue: [
          {
            $group: {
              _id: null,
              avgOrderValue: { $avg: '$totalAmount' },
            },
          },
        ],

        // 8) On-Time Delivery Rate
        onTimeDelivery: [
          {
            $match: {
              status: 'delivered',
              $expr: { $lte: ['$updatedAt', '$promisedDeliveryDate'] },
            },
          },
          { $count: 'count' },
        ],

        // 9) Order Processing Time
        orderProcessingTime: [
          {
            $project: {
              processingTime: {
                $divide: [
                  {
                    $subtract: [
                      { $arrayElemAt: ['$orderHistory.updatedAt', 1] }, // Assuming second entry is 'processing'
                      '$createdAt',
                    ],
                  },
                  1000 * 60 * 60, // Convert milliseconds to hours
                ],
              },
            },
          },
          {
            $group: {
              _id: null,
              avgProcessingTime: { $avg: '$processingTime' },
            },
          },
        ],

        // 10) Order Accuracy Rate
        orderAccuracy: [
          {
            $match: { isAccurate: true },
          },
          { $count: 'count' },
          {
            $lookup: {
              from: 'orders',
              pipeline: [{ $match: match }, { $count: 'total' }],
              as: 'totalOrders',
            },
          },
          {
            $addFields: {
              accuracyRate: {
                $multiply: [
                  { $divide: ['$count', { $arrayElemAt: ['$totalOrders.count', 0] || 1 }] },
                  100,
                ],
              },
            },
          },
          {
            $project: {
              _id: 0,
              accuracyRate: 1,
            },
          },
        ],

        // 11) Order Frequency Rate (OFR)
        orderFrequencyRate: [
          {
            $group: {
              _id: '$customer',
              orderCount: { $sum: 1 },
            },
          },
          {
            $group: {
              _id: null,
              averageOrderFrequency: { $avg: '$orderCount' },
            },
          },
        ],

        // 12) Repeat Purchase Rate (RPR)
        repeatPurchaseRate: [
          {
            $group: {
              _id: '$customer',
              orderCount: { $sum: 1 },
            },
          },
          {
            $group: {
              _id: null,
              totalCustomers: { $sum: 1 },
              repeatCustomers: {
                $sum: {
                  $cond: [{ $gt: ['$orderCount', 1] }, 1, 0],
                },
              },
            },
          },
          {
            $project: {
              _id: 0,
              rpr: {
                $multiply: [
                  { $divide: ['$repeatCustomers', '$totalCustomers'] },
                  100,
                ],
              },
            },
          },
        ],

        // 13) Order Abandonment Rate
        orderAbandonmentRate: [
          {
            $group: {
              _id: null,
              totalAbandoned: {
                $sum: { $cond: [{ $eq: ['$status', 'abandoned'] }, 1, 0] },
              },
              totalCarts: { $sum: 1 }, // Assuming each order attempt is a cart
            },
          },
          {
            $project: {
              _id: 0,
              abandonmentRate: {
                $multiply: [
                  { $divide: ['$totalAbandoned', '$totalCarts'] },
                  100,
                ],
              },
            },
          },
        ],

        // 14) Shipping Cost per Order
        shippingCostPerOrder: [
          {
            $group: {
              _id: null,
              avgShippingCost: { $avg: '$shippingCost' },
            },
          },
        ],

        // 15) Orders with Free Shipping
        ordersWithFreeShipping: [
          {
            $match: { shippingCost: 0 },
          },
          { $count: 'count' },
        ],

        // 16) Top Selling Products
        topSellingProducts: [
          { $unwind: '$items' },
          {
            $group: {
              _id: '$items.product',
              totalSold: { $sum: '$items.quantity' },
            },
          },
          { $sort: { totalSold: -1 } },
          { $limit: 5 },
          {
            $lookup: {
              from: 'products',
              localField: '_id',
              foreignField: '_id',
              as: 'product',
            },
          },
          { $unwind: '$product' },
          {
            $project: {
              _id: 0,
              productId: '$product._id',
              title: '$product.title',
              totalSold: 1,
            },
          },
        ],

        // 17) Feedback Metrics (CSAT & NPS)
        feedbackMetrics: [
          {
            $lookup: {
              from: 'feedbacks',
              localField: '_id',
              foreignField: 'order',
              as: 'feedback',
            },
          },
          { $unwind: { path: '$feedback', preserveNullAndEmptyArrays: true } },
          {
            $group: {
              _id: null,
              totalFeedbacks: {
                $sum: { $cond: [{ $ifNull: ['$feedback', false] }, 1, 0] },
              },
              averageCSAT: { $avg: '$feedback.rating' },
              averageNPS: { $avg: '$feedback.nps' },
            },
          },
        ],

        // 18) Marketing Metrics (CPO)
        marketingMetrics: [
          {
            $lookup: {
              from: 'marketingspends',
              localField: '_id',
              foreignField: '_id', // Assuming marketing spend is tracked globally or per campaign
              as: 'marketing',
            },
          },
          {
            $group: {
              _id: null,
              totalMarketingSpend: { $sum: '$marketing.amount' },
            },
          },
        ],

        // 19) Revenue Over Time (Daily Gross Revenue)
        revenueOverTime: [
          {
            $group: {
              _id: {
                year: { $year: '$createdAt' },
                month: { $month: '$createdAt' },
                day: { $dayOfMonth: '$createdAt' },
              },
              grossRevenue: { $sum: '$totalAmount' },
            },
          },
          {
            $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 },
          },
          {
            $project: {
              _id: 0,
              date: {
                $dateToString: {
                  format: '%Y-%m-%d',
                  date: {
                    $dateFromParts: {
                      year: '$_id.year',
                      month: '$_id.month',
                      day: '$_id.day',
                    },
                  },
                },
              },
              grossRevenue: 1,
            },
          },
        ],
      },
    },
  ];

  try {
    const metrics = await Order.aggregate(pipeline);

    // Extract Marketing Spend
    const totalMarketingSpend = metrics[0].marketingMetrics[0]
      ? metrics[0].marketingMetrics[0].totalMarketingSpend
      : 0;

    // Extract Total Orders
    const totalOrders = metrics[0].totalOrders[0] ? metrics[0].totalOrders[0].count : 0;

    // Calculate Cost Per Order (CPO)
    const costPerOrder = totalOrders ? totalMarketingSpend / totalOrders : 0;

    // Extract Feedback Metrics
    const totalFeedbacks = metrics[0].feedbackMetrics[0]
      ? metrics[0].feedbackMetrics[0].totalFeedbacks
      : 0;
    const averageCSAT = metrics[0].feedbackMetrics[0]
      ? metrics[0].feedbackMetrics[0].averageCSAT
      : 0;
    const averageNPS = metrics[0].feedbackMetrics[0]
      ? metrics[0].feedbackMetrics[0].averageNPS
      : 0;

    const response = {
      // Order Volume Metrics
      totalOrders,
      repeatOrders: metrics[0].repeatOrders[0] ? metrics[0].repeatOrders[0].count : 0,
      newOrders: metrics[0].newOrders[0] ? metrics[0].newOrders[0].count : 0,
      abandonedOrders: metrics[0].abandonedOrders[0] ? metrics[0].abandonedOrders[0].count : 0,

      // Revenue Metrics
      grossRevenue: metrics[0].grossRevenue[0] ? metrics[0].grossRevenue[0].totalGMV : 0,
      netRevenue: metrics[0].netRevenue[0] ? metrics[0].netRevenue[0].totalNetRevenue : 0,
      averageOrderValue: metrics[0].averageOrderValue[0]
        ? metrics[0].averageOrderValue[0].avgOrderValue
        : 0,

      // Fulfillment Metrics
      onTimeDeliveryRate: metrics[0].onTimeDelivery[0]
        ? (metrics[0].onTimeDelivery[0].count / (totalOrders || 1)) * 100
        : 0,
      averageProcessingTime: metrics[0].orderProcessingTime[0]
        ? metrics[0].orderProcessingTime[0].avgProcessingTime
        : 0, // in hours
      orderAccuracyRate: metrics[0].orderAccuracy[0]
        ? metrics[0].orderAccuracy[0].accuracyRate
        : 100, // Default to 100% if no data

      // Customer Behavior Metrics
      orderFrequencyRate: metrics[0].orderFrequencyRate[0]
        ? metrics[0].orderFrequencyRate[0].averageOrderFrequency
        : 0,
      repeatPurchaseRate: metrics[0].repeatPurchaseRate[0]
        ? metrics[0].repeatPurchaseRate[0].rpr
        : 0,
      orderAbandonmentRate: metrics[0].orderAbandonmentRate[0]
        ? metrics[0].orderAbandonmentRate[0].abandonmentRate
        : 0,

      // Shipping Metrics
      averageShippingCostPerOrder: metrics[0].shippingCostPerOrder[0]
        ? metrics[0].shippingCostPerOrder[0].avgShippingCost
        : 0,
      ordersWithFreeShipping: metrics[0].ordersWithFreeShipping[0]
        ? metrics[0].ordersWithFreeShipping[0].count
        : 0,

      // Additional Metrics
      topSellingProducts: metrics[0].topSellingProducts,

      // Feedback Metrics
      totalFeedbacks,
      averageCSAT,
      averageNPS,

      // Marketing Metrics
      totalMarketingSpend,
      costPerOrder,

      // Revenue Over Time
      revenueOverTime: metrics[0].revenueOverTime,

      message: 'Order metrics fetched successfully.',
    };

    res.status(200).json({
      success: true,
      data: response,
    });
  } catch (error) {
    logger.error(`Error fetching order metrics: ${error.message}`);
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to fetch order metrics.',
    });
  }
});


/**
 * @desc    Update tracking details for shipped orders
 * @route   PUT /api/orders/:id/tracking
 * @access  Private/Admin/Order Manager
 */
exports.updateTracking = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const { trackingId, carrier } = req.body;

  // Validate input using Joi
  const schema = Joi.object({
    trackingId: Joi.string().required(),
    carrier: Joi.string().required(),
  });

  const { error } = schema.validate({ trackingId, carrier });
  if (error) {
    return res.status(400).json({ success: false, message: error.details[0].message });
  }

  // Validate the order ID
  if (!isValidObjectId(id)) {
    logger.warn(`Invalid order ID received for tracking update: ${id}`);
    return res.status(400).json({ success: false, message: 'Invalid order ID.' });
  }

  const order = await Order.findById(id)
    .populate('customer', 'name email');

  if (!order) {
    logger.warn(`Order with ID ${id} not found for tracking update.`);
    return res.status(404).json({ success: false, message: 'Order not found.' });
  }

  // Ensure the order has been shipped
  if (order.status !== 'shipped') {
    return res.status(400).json({ success: false, message: 'Only shipped orders can have tracking details updated.' });
  }

  // Update tracking details
  order.trackingDetails = {
    trackingId,
    carrier,
    updatedAt: new Date(),
  };
  await order.save();

  // Notify the customer about tracking update
  try {
    const emailHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Order Tracking Updated</title>
      <style>
        /* Add your email styles here */
      </style>
    </head>
    <body>
      <p>Hi ${order.customer.name},</p>
      <p>Your order <strong>${order.orderNumber}</strong> has updated tracking information.</p>
      <p><strong>Carrier:</strong> ${carrier}</p>
      <p><strong>Tracking ID:</strong> ${trackingId}</p>
      <p>You can track your shipment <a href="https://www.${carrier.toLowerCase()}.com/track/${trackingId}">here</a>.</p>
      <p>Thank you for shopping with us.</p>
    </body>
    </html>
    `;

    await sendEmail({
      email: order.customer.email,
      subject: 'Your Order Tracking Information Updated - 10X Formulas',
      message: `Hi ${order.customer.name}, your order tracking information has been updated.`,
      html: emailHtml,
    });

    logger.info(`Tracking update email sent to ${order.customer.email} for Order ID ${order._id}`);
  } catch (emailError) {
    logger.error(`Failed to send tracking update email to ${order.customer.email}: ${emailError.message}`);
    // Proceed without failing the tracking update
  }

  res.status(200).json({
    success: true,
    data: order.trackingDetails,
    message: 'Tracking details updated successfully.',
  });
});


/**
 * @desc    Allow customers to request a return
 * @route   POST /api/orders/:id/return
 * @access  Private/Customer
 */
exports.returnOrder = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const { items, reason } = req.body;

  // Validate input using Joi
  const schema = Joi.object({
    items: Joi.array().items(
      Joi.object({
        productId: Joi.string().required(),
        quantity: Joi.number().positive().required(),
      })
    ).min(1).required(),
    reason: Joi.string().max(500).optional(),
  });

  const { error } = schema.validate({ items, reason });
  if (error) {
    return res.status(400).json({ success: false, message: error.details[0].message });
  }

  // Validate the order ID
  if (!isValidObjectId(id)) {
    logger.warn(`Invalid order ID received for return: ${id}`);
    return res.status(400).json({ success: false, message: 'Invalid order ID.' });
  }

  const order = await Order.findById(id)
    .populate('customer', 'name email')
    .populate('items.product', 'title price');

  if (!order) {
    logger.warn(`Order with ID ${id} not found for return.`);
    return res.status(404).json({ success: false, message: 'Order not found.' });
  }

  // Check if the order is eligible for return
  if (!['delivered'].includes(order.status)) {
    return res.status(400).json({ success: false, message: 'Only delivered orders can be returned.' });
  }

  // Check if the return request is within the return window (e.g., 30 days)
  const returnWindowDays = 30;
  const orderDate = new Date(order.createdAt);
  const currentDate = new Date();
  const diffTime = Math.abs(currentDate - orderDate);
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  if (diffDays > returnWindowDays) {
    return res.status(400).json({ success: false, message: `Return window of ${returnWindowDays} days has expired.` });
  }

  // Validate that the items being returned are part of the order
  for (const returnItem of items) {
    const orderedItem = order.items.find(
      (item) => String(item.product._id) === String(returnItem.productId)
    );
    if (!orderedItem) {
      return res.status(400).json({ success: false, message: `Product with ID ${returnItem.productId} is not part of this order.` });
    }
    if (returnItem.quantity > orderedItem.quantity - (orderedItem.returned || 0)) {
      return res.status(400).json({ success: false, message: `Return quantity for product ${orderedItem.product.title} exceeds the purchased quantity.` });
    }
  }

  // Create a return request (Assuming you have a Return model)
  const returnRequest = await Return.create({
    order: order._id,
    customer: order.customer._id,
    items,
    reason: reason || 'No reason provided.',
    status: 'pending',
    requestedAt: new Date(),
  });

  // Notify Admins about the return request (Assuming you have a way to get admin emails)
  try {
    const adminEmails = await getAdminEmails(); // Implement this function based on your admin setup

    const emailHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Return Request</title>
      <style>
        /* Add your email styles here */
      </style>
    </head>
    <body>
      <p>Hi Admin,</p>
      <p>A customer has requested a return for order <strong>${order.orderNumber}</strong>.</p>
      <p><strong>Customer:</strong> ${order.customer.name} (${order.customer.email})</p>
      <p><strong>Items to Return:</strong></p>
      <ul>
        ${items.map(item => `<li>Product ID: ${item.productId}, Quantity: ${item.quantity}</li>`).join('')}
      </ul>
      <p><strong>Reason:</strong> ${reason || 'No reason provided.'}</p>
      <p>Please review the return request.</p>
    </body>
    </html>
    `;

    await sendEmail({
      email: adminEmails,
      subject: 'New Return Request - 10X Formulas',
      message: `A new return request has been submitted for order ${order.orderNumber}.`,
      html: emailHtml,
    });

    logger.info(`Return request email sent to admins for Order ID ${order._id}`);
  } catch (emailError) {
    logger.error(`Failed to send return request email for Order ID ${order._id}: ${emailError.message}`);
    // Proceed without failing the return request creation
  }

  res.status(201).json({
    success: true,
    data: returnRequest,
    message: 'Return request submitted successfully.',
  });
});

/**
 * @desc    Process a partial/full refund for a delivered order
 * @route   POST /api/orders/:id/refund
 * @access  Private/Admin/Order Manager
 */
exports.refundOrder = asyncHandler(async (req, res, next) => {
  const { id } = req.params;
  const { amount, reason } = req.body;

  // Validate input using Joi
  const schema = Joi.object({
    amount: Joi.number().positive().required(),
    reason: Joi.string().max(500).optional(),
  });

  const { error } = schema.validate({ amount, reason });
  if (error) {
    return res.status(400).json({ success: false, message: error.details[0].message });
  }

  // Validate the order ID
  if (!isValidObjectId(id)) {
    logger.warn(`Invalid order ID received for refund: ${id}`);
    return res.status(400).json({ success: false, message: 'Invalid order ID.' });
  }

  const order = await Order.findById(id)
    .populate('customer', 'name email')
    .populate('items.product', 'title price');

  if (!order) {
    logger.warn(`Order with ID ${id} not found for refund.`);
    return res.status(404).json({ success: false, message: 'Order not found.' });
  }

  // Check if the order is eligible for refund
  if (!['delivered', 'returned'].includes(order.status)) {
    return res.status(400).json({ success: false, message: 'Only delivered or returned orders can be refunded.' });
  }

  // Calculate the refundable amount
  const refundableAmount = order.totalAmount - order.totalRefunded;
  if (amount > refundableAmount) {
    return res.status(400).json({ success: false, message: `Refund amount exceeds refundable limit of $${refundableAmount.toFixed(2)}.` });
  }

  // Process the refund via payment gateway
  const refundResponse = await processPaymentRefund(order.paymentTransactionId, amount);

  if (!refundResponse.success) {
    logger.error(`Refund processing failed for Order ID ${id}: ${refundResponse.message}`);
    return res.status(500).json({ success: false, message: 'Refund processing failed.' });
  }

  // Update the order's refunded amount
  order.totalRefunded += amount;
  if (order.totalRefunded >= order.totalAmount) {
    order.paymentStatus = 'refunded';
    order.status = 'refunded';
  }
  await order.save();

  // Create a refund record
  const refund = await Refund.create({
    order: order._id,
    amount,
    reason: reason || 'No reason provided.',
    refundedAt: new Date(),
    transactionId: refundResponse.data.id, // Assuming the refund ID from the gateway
  });

  // Send Refund Confirmation Email
  try {
    const emailHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Refund Processed</title>
      <style>
        /* Add your email styles here */
      </style>
    </head>
    <body>
      <p>Hi ${order.customer.name},</p>
      <p>Your refund for order <strong>${order.orderNumber}</strong> has been processed.</p>
      <p><strong>Amount Refunded:</strong> $${amount.toFixed(2)}</p>
      <p><strong>Reason:</strong> ${reason || 'No reason provided.'}</p>
      <p>Thank you for shopping with us.</p>
    </body>
    </html>
    `;

    await sendEmail({
      email: order.customer.email,
      subject: 'Your Refund Has Been Processed - 10X Formulas',
      message: `Hi ${order.customer.name}, your refund has been processed.`,
      html: emailHtml,
    });

    logger.info(`Refund confirmation email sent to ${order.customer.email}`);
  } catch (emailError) {
    logger.error(`Failed to send refund confirmation email to ${order.customer.email}: ${emailError.message}`);
    // Proceed without failing the refund process
  }

  res.status(200).json({
    success: true,
    data: refund,
    message: 'Refund processed successfully.',
  });
});

// Helper function to process refunds via payment gateway (Stripe example)
async function processPaymentRefund(transactionId, amount) {
  try {
    // Replace with your payment gateway's refund logic
    const refund = await stripe.refunds.create({
      charge: transactionId,
      amount: Math.round(amount * 100), // amount in cents
    });
    return { success: true, data: refund };
  } catch (error) {
    return { success: false, message: error.message };
  }
}


/**
 * @desc    Allow bulk status updates for orders
 * @route   PUT /api/orders/bulk-update
 * @access  Private/Admin/Order Manager
 */
exports.bulkUpdateOrders = asyncHandler(async (req, res, next) => {
  const { orderIds, status } = req.body;

  // Validate input using Joi
  const schema = Joi.object({
    orderIds: Joi.array().items(Joi.string().required()).min(1).required(),
    status: Joi.string().valid('pending', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded').required(),
  });

  const { error } = schema.validate({ orderIds, status });
  if (error) {
    return res.status(400).json({ success: false, message: error.details[0].message });
  }

  // Validate each order ID
  const invalidIds = orderIds.filter(id => !isValidObjectId(id));
  if (invalidIds.length > 0) {
    return res.status(400).json({ success: false, message: `Invalid order IDs: ${invalidIds.join(', ')}` });
  }

  // Define allowed status transitions
  const allowedTransitions = {
    pending: ['processing', 'shipped', 'delivered', 'cancelled'],
    processing: ['shipped', 'delivered', 'cancelled'],
    shipped: ['delivered', 'refunded'],
    delivered: ['refunded'],
    cancelled: [],
    refunded: [],
  };

  // Fetch all orders to be updated
  const orders = await Order.find({ _id: { $in: orderIds } })
    .populate('customer', 'name email')
    .populate('items.product', 'title price');

  // Check allowed transitions
  const invalidTransitions = orders.filter(order => !allowedTransitions[order.status].includes(status));
  if (invalidTransitions.length > 0) {
    const invalidOrderNumbers = invalidTransitions.map(order => order.orderNumber).join(', ');
    return res.status(400).json({ success: false, message: `Invalid status transition for orders: ${invalidOrderNumbers}` });
  }

  // Update each order
  const updatedOrders = [];
  for (const order of orders) {
    order.status = status;

    // Handle specific status updates if needed
    if (status === 'shipped') {
      order.shippingDate = new Date();
      // Optionally, set tracking details if provided
    } else if (status === 'delivered') {
      order.deliveryDate = new Date();
    }

    await order.save();
    updatedOrders.push(order);

    // Send notification emails as necessary
    try {
      const emailHtml = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Order Status Updated</title>
        <style>
          /* Add your email styles here */
        </style>
      </head>
      <body>
        <p>Hi ${order.customer.name},</p>
        <p>Your order <strong>${order.orderNumber}</strong> has been updated to status <strong>${capitalize(status)}</strong>.</p>
        <p>Thank you for shopping with us.</p>
      </body>
      </html>
      `;

      await sendEmail({
        email: order.customer.email,
        subject: `Your Order Status Updated to ${capitalize(status)} - 10X Formulas`,
        message: `Hi ${order.customer.name}, your order status has been updated to ${status}.`,
        html: emailHtml,
      });

      logger.info(`Bulk update email sent to ${order.customer.email} for Order ID ${order._id}`);
    } catch (emailError) {
      logger.error(`Failed to send bulk update email to ${order.customer.email}: ${emailError.message}`);
      // Proceed without failing the entire bulk update
    }
  }

  res.status(200).json({
    success: true,
    data: updatedOrders,
    message: 'Bulk order status updated successfully.',
  });
});

/**
 * @desc    Fetch cached order metrics or trigger recomputation
 * @route   GET /api/orders/metrics-cache
 * @access  Private/Admin/Order Manager/Analytics Viewer
 */
exports.getMetricsCache = asyncHandler(async (req, res, next) => {
  const { dateFrom, dateTo } = req.query;
  const cacheKey = `order_metrics_${dateFrom || 'all'}_${dateTo || 'all'}`;

  // Try fetching from cache
  const cachedMetrics = await getCache(cacheKey);
  if (cachedMetrics) {
    return res.status(200).json({
      success: true,
      data: JSON.parse(cachedMetrics),
      message: 'Order metrics fetched from cache.',
    });
  }

  // If not cached, compute metrics
  try {
    // Reuse the existing getOrderMetrics function logic
    const metrics = await exports.getOrderMetrics(req, res, next);

    // Cache the metrics with an expiration time (e.g., 1 hour)
    await setCache(cacheKey, JSON.stringify(metrics.data), 3600); // 3600 seconds = 1 hour

    res.status(200).json({
      success: true,
      data: metrics.data,
      message: 'Order metrics fetched and cached successfully.',
    });
  } catch (error) {
    logger.error(`Error fetching order metrics for cache: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch order metrics.',
    });
  }
});
