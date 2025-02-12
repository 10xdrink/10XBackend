// controllers/reportController.js
const Order = require('../models/Order');
const Product = require('../models/Product');
const User = require('../models/User');
const logger = require('../utils/logger');
const ERROR_CODES = require('../constants/errorCodes');
const { Parser } = require('json2csv');

// @desc    Get sales summary
// @route   GET /api/reports/sales-summary
// @access  Private/Admin/Analytics Viewer
exports.getSalesSummary = async (req, res, next) => {
  try {
    const totalSales = await Order.countDocuments({ status: { $in: ['delivered', 'shipped'] } });
    const totalRevenue = await Order.aggregate([
      { $match: { status: { $in: ['delivered', 'shipped'] } } },
      { $unwind: '$items' },
      {
        $group: {
          _id: null,
          total: { $sum: '$items.price' },
        },
      },
    ]);
    const revenue = totalRevenue[0] ? totalRevenue[0].total : 0;

    res.status(200).json({
      success: true,
      data: {
        totalSales,
        totalRevenue,
      },
    });
  } catch (error) {
    logger.error('Get Sales Summary Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

// @desc    Get top-selling products
// @route   GET /api/reports/top-products
// @access  Private/Admin/Analytics Viewer
exports.getTopProducts = async (req, res, next) => {
  try {
    const { limit = 10 } = req.query;

    const topProducts = await Order.aggregate([
      { $match: { status: { $in: ['delivered', 'shipped'] } } },
      { $unwind: '$items' },
      {
        $group: {
          _id: '$items.product',
          totalSold: { $sum: '$items.quantity' },
        },
      },
      { $sort: { totalSold: -1 } },
      { $limit: Number(limit) },
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
          name: '$product.name',
          totalSold: 1,
        },
      },
    ]);

    res.status(200).json({
      success: true,
      data: topProducts,
    });
  } catch (error) {
    logger.error('Get Top Products Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

// @desc    Get customer analytics
// @route   GET /api/reports/customer-analytics
// @access  Private/Admin/Analytics Viewer
exports.getCustomerAnalytics = async (req, res, next) => {
  try {
    const activeCustomers = await User.countDocuments({ isActive: true });
    const totalOrders = await Order.countDocuments({ status: { $in: ['delivered', 'shipped'] } });
    const repeatCustomers = await Order.aggregate([
      { $match: { status: { $in: ['delivered', 'shipped'] } } },
      { $group: { _id: '$customer', orderCount: { $sum: 1 } } },
      { $match: { orderCount: { $gt: 1 } } },
      { $count: 'repeatCustomers' },
    ]);
    const repeatCustomerCount = repeatCustomers[0] ? repeatCustomers[0].repeatCustomers : 0;

    res.status(200).json({
      success: true,
      data: {
        activeCustomers,
        totalOrders,
        repeatCustomerCount,
      },
    });
  } catch (error) {
    logger.error('Get Customer Analytics Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

// @desc    Export sales reports
// @route   GET /api/reports/export
// @access  Private/Admin/Analytics Viewer
exports.exportSalesReport = async (req, res, next) => {
  try {
    const { type } = req.query; // e.g., 'csv', 'excel'

    const salesData = await Order.find({ status: { $in: ['delivered', 'shipped'] } })
      .populate('items.product', 'name price')
      .populate('customer', 'name email')
      .select('orderNumber customer items totalAmount createdAt');

    if (type === 'csv') {
      const fields = ['orderNumber', 'customer.name', 'customer.email', 'items', 'totalAmount', 'createdAt'];
      const opts = { fields };
      const parser = new Parser(opts);
      const csv = parser.parse(salesData.map(order => ({
        orderNumber: order.orderNumber,
        'customer.name': order.customer.name,
        'customer.email': order.customer.email,
        items: order.items.map(item => `${item.product.name} x${item.quantity}`).join('; '),
        totalAmount: order.totalAmount,
        createdAt: order.createdAt,
      })));

      res.header('Content-Type', 'text/csv');
      res.attachment('sales_report.csv');
      return res.send(csv);
    }

    res.status(400).json({ success: false, message: 'Invalid export type' });
  } catch (error) {
    logger.error('Export Sales Report Error:', error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};
