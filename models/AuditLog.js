// models/AuditLog.js

const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema(
  {
    entity: {
      type: String,
      required: false, // Changed from true to false
      enum: [
        'Settings',
        'NotificationTemplate',
        'User',
        'Product',
        'Order',
        'Coupon',
        'Review',
        'BlogPost',
        'BulkOperation', // Optionally add 'BulkOperation' if desired
      ], // Add other entities as needed
    },
    action: {
      type: String,
      required: true,
      enum: ['CREATE', 'UPDATE', 'DELETE', 'RESTORE', 'BULK_UPDATE'],
    },
    entityId: {
      type: mongoose.Schema.Types.ObjectId,
      required: false, // Changed from true to false
    },
    changes: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
      default: {},
      validate: {
        validator: function (v) {
          // Optional validation for changes object structure
          return typeof v === 'object';
        },
        message: 'Changes should be an object',
      },
    },
    performedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    details: {
      type: String,
    },
  },
  {
    timestamps: true, // Automatically includes createdAt and updatedAt fields
  }
);

// Static method to log an action with default handling
AuditLogSchema.statics.logAction = async function (
  entity,
  action,
  entityId = null,
  changes = {},
  performedBy,
  details = ''
) {
  try {
    return await this.create({
      entity,
      action,
      entityId,
      changes,
      performedBy,
      details,
    });
  } catch (error) {
    console.error('Error logging audit action:', error);
    throw error;
  }
};

// Static method to retrieve logs for a specific entity
AuditLogSchema.statics.getLogsForEntity = function (entity, entityId) {
  return this.find({ entity, entityId })
    .sort({ createdAt: -1 }) // Sorted by timestamp (newest first)
    .lean();
};

// Indexes for optimized retrieval
AuditLogSchema.index({ entity: 1, entityId: 1 });
AuditLogSchema.index({ performedBy: 1, createdAt: -1 });

module.exports = mongoose.model('AuditLog', AuditLogSchema);
