// models/BlogPost.js

const mongoose = require('mongoose');
const slugify = require('slugify');

const BlogPostSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, 'Please add a title'],
      trim: true,
    },
    slug: {
      type: String,
      unique: true,
      lowercase: true,
      trim: true,
    },
    content: {
      type: String,
      required: [true, 'Please add content'],
    },
    categories: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Category',
        required: [true, 'Please add at least one category'],
      },
    ],
    tags: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Tag',
      },
    ],
    images: [
      {
        type: String,
        match: [
          /^https?:\/\/.*\.(?:jpg|jpeg|png|webp|avif|gif|svg)$/i,
          'Please use a valid image URL.',
        ],
      },
    ],
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Please add an author'],
    },
    status: {
      type: String,
      enum: ['draft', 'published'],
      default: 'draft',
    },
    isFeatured: {
      type: Boolean,
      default: false,
    },
    views: {
      type: Number,
      default: 0,
    },
    meta: {
      title: {
        type: String,
        default: function () {
          return this.title;
        },
      },
      description: {
        type: String,
        default: function () {
          return `${this.title} - A blog post on ${this.categories.map(cat => cat.name).join(', ')}.`;
        },
      },
      keywords: {
        type: [String],
        default: function () {
          return [this.title, 'blog', ...this.categories.map(cat => cat.name)];
        },
      },
    },
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform: (_, ret) => {
        delete ret.__v; // Hide internal fields if any
      },
    },
    toObject: { virtuals: true },
  }
);

// Pre-save hook to generate slug and update meta fields
BlogPostSchema.pre('save', async function (next) {
  if (this.isModified('title')) {
    const baseSlug = slugify(this.title, { lower: true, strict: true });
    const existingPost = await this.constructor.findOne({ slug: baseSlug });
    if (existingPost && existingPost._id.toString() !== this._id.toString()) {
      // Append unique identifier if slug exists
      this.slug = `${baseSlug}-${Date.now()}`;
    } else {
      this.slug = baseSlug;
    }
  }

  // Populate categories to get their names for meta fields
  await this.populate('categories', 'name');

  // Update meta fields with category names
  this.meta.description = `${this.title} - A blog post on ${this.categories.map(cat => cat.name).join(', ')}.`;
  this.meta.keywords = [this.title, 'blog', ...this.categories.map(cat => cat.name)];

  next();
});

// Indexes for optimized search
BlogPostSchema.index({ title: 'text', content: 'text' });
BlogPostSchema.index({ slug: 1 });

module.exports = mongoose.model('BlogPost', BlogPostSchema);
