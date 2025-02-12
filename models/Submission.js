// models/Submission.js

const mongoose = require('mongoose');

const SubmissionSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Name is required.'],
      trim: true,
    },
    mobile: {
      type: String,
      required: [true, 'Mobile number is required.'],
      trim: true,
      match: [/^\+91\d{10}$/, 'Please enter a valid +91 mobile number.'],
    },
    email: {
      type: String,
      required: [true, 'Email is required.'],
      trim: true,
      lowercase: true,
      match: [
        /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
        'Please enter a valid email address.',
      ],
    },
    message: {
      type: String,
      required: [true, 'Message is required.'],
      trim: true,
    },
    consent: {
      type: Boolean,
      required: [true, 'Consent is required.'],
    },
    submittedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true, // Automatically includes createdAt and updatedAt
  }
);

module.exports = mongoose.model('Submission', SubmissionSchema);
