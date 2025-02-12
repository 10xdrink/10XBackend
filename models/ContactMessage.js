// models/ContactMessage.js

const mongoose = require('mongoose');

const ContactMessageSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please provide your name'],
      trim: true,
      minlength: [2, 'Name must be at least 2 characters long'],
      maxlength: [50, 'Name cannot exceed 50 characters'],
    },
    email: {
      type: String,
      required: [true, 'Please provide an email address'],
      trim: true,
      lowercase: true,
      match: [
        /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
        'Please enter a valid email address',
      ],
    },
    message: {
      type: String,
      required: [true, 'Please enter a message'],
      trim: true,
      minlength: [10, 'Message must be at least 10 characters long'],
      maxlength: [1000, 'Message cannot exceed 1000 characters'],
    },
    termsAgreed: {
      type: Boolean,
      required: [true, 'You must agree to the terms to submit'],
    },
    status: {
      type: String,
      enum: ['new', 'in-progress', 'resolved'],
      default: 'new',
    },
    responses: [
      {
        responder: {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'User',
          required: true,
        },
        message: {
          type: String,
          required: true,
          trim: true,
          minlength: [10, 'Response must be at least 10 characters long'],
          maxlength: [1000, 'Response cannot exceed 1000 characters'],
        },
        createdAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
    deleted: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true, // Automatically adds createdAt and updatedAt fields
    toJSON: {
      virtuals: true,
      transform: (_, ret) => {
        delete ret.__v; // Remove __v from JSON output
      },
    },
    toObject: { virtuals: true },
  }
);

// Indexes for efficient retrieval by status, creation date, and deletion status
ContactMessageSchema.index({ status: 1 });
ContactMessageSchema.index({ createdAt: -1 });
ContactMessageSchema.index({ deleted: 1 });

module.exports = mongoose.model('ContactMessage', ContactMessageSchema);
