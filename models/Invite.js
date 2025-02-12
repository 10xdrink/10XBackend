// models/Invite.js

const mongoose = require('mongoose');

const InviteSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, 'Email is required for invitation'],
      unique: true,
      trim: true,
      lowercase: true,
      match: [
        /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
        'Please add a valid email address',
      ],
    },
    role: {
      type: String,
      enum: Object.values(require('../constants/userRoles')),
      required: [true, 'Role is required for invitation'],
    },
    token: {
      type: String,
      required: [true, 'Invitation token is required'],
    },
    expiresAt: {
      type: Date,
      required: [true, 'Expiration date is required'],
    },
    isUsed: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('Invite', InviteSchema);
