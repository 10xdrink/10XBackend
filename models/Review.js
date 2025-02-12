// models/Review.js

const mongoose = require('mongoose');

const ReviewSchema = new mongoose.Schema(
  {
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product',
      required: [true, 'Please add a product to review'],
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Please add a user'],
    },
    rating: {
      type: Number,
      required: [true, 'Please add a rating'],
      min: [1, 'Rating must be at least 1'],
      max: [5, 'Rating cannot exceed 5'],
    },
    comment: {
      type: String,
      trim: true,
      maxlength: [1000, 'Comment cannot exceed 1000 characters'],
    },
    photos: [
      {
        url: {
          type: String,
          required: true,
        },
        public_id: {
          type: String,
          required: true,
        },
      },
    ],
    isApproved: {
      type: Boolean,
      default: false,
    },
  },
  { 
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

// Virtual for truncated comment preview (useful for summaries)
ReviewSchema.virtual('commentPreview').get(function () {
  return this.comment && this.comment.length > 100 
    ? `${this.comment.substring(0, 100)}...` 
    : this.comment;
});

// Pre-save hook to auto-approve reviews with a high rating (e.g., 5 stars)
ReviewSchema.pre('save', function (next) {
  if (this.rating === 5) {
    this.isApproved = true;
  }
  next();
});

// Prevent duplicate reviews by the same user for the same product
ReviewSchema.index({ product: 1, user: 1 }, { unique: true });

// Indexes for optimized query performance
ReviewSchema.index({ product: 1, isApproved: 1 });
ReviewSchema.index({ rating: 1 });

module.exports = mongoose.model('Review', ReviewSchema);
