const mongoose = require('mongoose');

const SEOSettingsSchema = new mongoose.Schema(
  {
    page: {
      type: String,
      required: true,
      unique: true,
      enum: [
        'homepage',
        'productPage',
        'blogPage',
        'contactPage',
        // Extend this list as needed
      ],
    },
    metaTitle: {
      type: String,
      default: '',
      trim: true,
      maxlength: [60, 'Meta title cannot exceed 60 characters'],
    },
    metaDescription: {
      type: String,
      default: '',
      trim: true,
      maxlength: [160, 'Meta description cannot exceed 160 characters'],
    },
    metaKeywords: {
      type: [String],
      default: [],
      validate: {
        validator: (v) => Array.isArray(v) && v.length <= 10,
        message: 'You can specify a maximum of 10 keywords',
      },
    },
    openGraph: {
      ogTitle: { type: String, default: '', trim: true, maxlength: [60, 'OG title cannot exceed 60 characters'] },
      ogDescription: { type: String, default: '', trim: true, maxlength: [160, 'OG description cannot exceed 160 characters'] },
      ogImage: {
        type: String,
        match: [/^https?:\/\/.+\.(jpg|jpeg|png|webp)$/i, 'Please enter a valid image URL'],
      },
      ogType: { type: String, default: 'website', trim: true },
    },
    customMeta: {
      type: Map,
      of: String,
      default: {},
    },
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Static method to retrieve active SEO settings for a specific page
SEOSettingsSchema.statics.getSEOSettingsForPage = async function (page) {
  return this.findOne({ page, isActive: true });
};

// Static method to update or create SEO settings for a page
SEOSettingsSchema.statics.updateSEOSettingsForPage = async function (page, updates) {
  return this.findOneAndUpdate({ page }, updates, { new: true, upsert: true });
};

// Indexes for optimized search and retrieval
SEOSettingsSchema.index({ page: 1, isActive: 1 });

module.exports = mongoose.model('SEOSettings', SEOSettingsSchema);
