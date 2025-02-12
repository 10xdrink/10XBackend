// models/ActivityLog.js

const mongoose = require('mongoose');

const ActivityLogSchema = new mongoose.Schema(
  {
    action: {
      type: String,
      required: true,
      enum: [
        'create',
        'update_status',
        'assign',
        'delete',
        'restore',
        'respond',
        'export',
      ],
    },
    messageId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ContactMessage',
      required: true,
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
  { timestamps: true }
);

module.exports = mongoose.model('ActivityLog', ActivityLogSchema);
