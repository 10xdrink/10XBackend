// models/Tag.js

const mongoose = require('mongoose');

const tagSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please add a tag name'],
      unique: true,
      trim: true,
      lowercase: true,
      minlength: [2, 'Tag name must be at least 2 characters long'],
      maxlength: [50, 'Tag name cannot exceed 50 characters'],
      match: [/^[a-zA-Z0-9-_ ]+$/, 'Tag name can only contain alphanumeric characters, dashes, underscores, and spaces'],
    },
    description: {
      type: String,
      maxlength: [200, 'Description cannot exceed 200 characters'],
      default: '',
    },
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);

// Optional: Add static methods if needed
tagSchema.statics.getActiveTags = function () {
  return this.find({ isActive: true });
};

const Tag = mongoose.model('Tag', tagSchema);

module.exports = Tag;
