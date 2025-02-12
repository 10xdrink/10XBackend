// models/FAQ.js

const mongoose = require('mongoose');

const FAQSchema = new mongoose.Schema(
  {
    question: {
      type: String,
      required: [true, 'Please add a question'],
      trim: true,
      minlength: [5, 'Question must be at least 5 characters long'],
      unique: true, // Ensures no duplicate questions
    },
    answer: {
      type: String,
      required: [true, 'Please add an answer'],
      trim: true,
      minlength: [10, 'Answer must be at least 10 characters long'],
    },
    isActive: {
      type: Boolean,
      default: true, // Allows toggling FAQ visibility
    },
    tags: {
      type: [String],
      default: [], // Array of tags for categorization
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Virtual field to check if the FAQ is long
FAQSchema.virtual('isLongFAQ').get(function () {
  return this.answer.length > 100; // Arbitrary length to determine "long" FAQs
});

// Indexes for search optimization and faster query
FAQSchema.index({ question: 'text', answer: 'text' });
FAQSchema.index({ isActive: 1 });
FAQSchema.index({ tags: 1 });

// Pre-save hook to ensure unique question formatting
FAQSchema.pre('save', function (next) {
  if (this.isModified('question')) {
    this.question = this.question.charAt(0).toUpperCase() + this.question.slice(1);
  }
  next();
});

// Static method to get all active FAQs
FAQSchema.statics.getActiveFAQs = function () {
  return this.find({ isActive: true });
};

// Exporting the model
module.exports = mongoose.model('FAQ', FAQSchema);
