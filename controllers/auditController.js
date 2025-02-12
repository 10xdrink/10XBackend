// controllers/auditController.js

const AuditLog = require('../models/AuditLog');
const { validationResult } = require('express-validator');

// Get all audit logs with optional filters and pagination
exports.getAllAuditLogs = async (req, res) => {
  const { action, userId, dateFrom, dateTo, page = 1, limit = 10 } = req.query;

  try {
    const filters = {};

    if (action) filters.action = action;
    if (userId) filters.changedBy = userId;
    if (dateFrom || dateTo) {
      filters.createdAt = {};
      if (dateFrom) filters.createdAt.$gte = new Date(dateFrom);
      if (dateTo) filters.createdAt.$lte = new Date(dateTo);
    }

    const logs = await AuditLog.find(filters)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    const total = await AuditLog.countDocuments(filters);

    res.status(200).json({
      success: true,
      data: logs,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve audit logs',
      error: error.message,
    });
  }
};

// Get audit log by ID
exports.getAuditLogById = async (req, res) => {
  const { id } = req.params;

  try {
    const log = await AuditLog.findById(id);
    if (!log) {
      return res.status(404).json({ success: false, message: 'Audit log not found' });
    }
    res.status(200).json({ success: true, data: log });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve audit log',
      error: error.message,
    });
  }
};

// Delete audit logs older than a specified date (cleanup)
exports.deleteOldAuditLogs = async (req, res) => {
  const { olderThanDate } = req.body;

  try {
    const date = new Date(olderThanDate);
    const result = await AuditLog.deleteMany({ createdAt: { $lt: date } });

    res.status(200).json({
      success: true,
      message: `${result.deletedCount} audit logs older than ${olderThanDate} were deleted`,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to delete old audit logs',
      error: error.message,
    });
  }
};
