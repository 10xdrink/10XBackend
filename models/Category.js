// src/models/Category.js

const mongoose = require('mongoose');
const slugify = require('slugify');

const CategorySchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please add a category name'],
      trim: true,
      unique: true,
      minlength: [2, 'Category name must be at least 2 characters'],
      maxlength: [100, 'Category name cannot exceed 100 characters'],
    },
    slug: {
      type: String,
      unique: true,
      lowercase: true,
      trim: true,
    },
    type: {
      type: String,
      enum: ['product', 'blog'],
      required: [true, 'Please specify the category type'],
    },
    description: {
      type: String,
      trim: true,
      maxlength: [500, 'Description cannot exceed 500 characters'],
    },
    parent: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Category',
      default: null,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  { 
    timestamps: true,
    toJSON: { virtuals: true, transform: (_, ret) => { delete ret.__v; } },
    toObject: { virtuals: true },
  }
);

// Virtual field for subcategories (useful for nested category structures)
CategorySchema.virtual('subcategories', {
  ref: 'Category',
  localField: '_id',
  foreignField: 'parent',
  justOne: false,
});

// Pre-save hook to generate slug if the name changes
CategorySchema.pre('save', function (next) {
  if (this.isModified('name') && !this.slug) {
    this.slug = slugify(this.name, { lower: true, strict: true });
  }
  next();
});

// Indexes for optimized queries
CategorySchema.index({ name: 1, type: 1 });
CategorySchema.index({ slug: 1, type: 1 });
CategorySchema.index({ parent: 1, isActive: 1 });

module.exports = mongoose.model('Category', CategorySchema);
