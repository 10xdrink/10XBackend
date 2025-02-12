const mongoose = require('mongoose');

const LocalizationSettingsSchema = new mongoose.Schema(
  {
    region: {
      type: String,
      required: true,
      unique: true,
      uppercase: true, // Store region codes in uppercase (e.g., 'US', 'IN', 'FR')
    },
    currency: {
      type: String,
      required: true,
      default: 'USD',
      maxlength: 3, // ISO currency code format (e.g., USD, EUR)
      uppercase: true,
    },
    language: {
      type: String,
      required: true,
      default: 'en',
      maxlength: 5, // ISO language code format (e.g., en, fr, es)
      lowercase: true,
    },
    dateFormat: {
      type: String,
      required: true,
      default: 'MM/DD/YYYY',
    },
    timeZone: {
      type: String,
      default: 'UTC',
    },
    taxRate: {
      type: Number,
      min: 0,
      max: 100,
      default: 0, // Default tax rate as a percentage
    },
    customSettings: {
      type: Map,
      of: String, // Flexible key-value pairs for additional custom settings
      default: {},
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Virtual field to check if tax is applicable
LocalizationSettingsSchema.virtual('isTaxApplicable').get(function () {
  return this.taxRate > 0;
});

// Static method to retrieve settings by region
LocalizationSettingsSchema.statics.getSettingsByRegion = async function (region) {
  return this.findOne({ region: region.toUpperCase() });
};

// Static method to update settings by region
LocalizationSettingsSchema.statics.updateSettingsByRegion = async function (region, updates) {
  return this.findOneAndUpdate(
    { region: region.toUpperCase() },
    updates,
    { new: true, upsert: true }
  );
};

// Middleware to ensure the region, currency, and language codes are in proper format
LocalizationSettingsSchema.pre('save', function (next) {
  if (this.isModified('region')) {
    this.region = this.region.toUpperCase();
  }
  if (this.isModified('currency')) {
    this.currency = this.currency.toUpperCase();
  }
  if (this.isModified('language')) {
    this.language = this.language.toLowerCase();
  }
  next();
});

// Indexes for efficient querying
LocalizationSettingsSchema.index({ region: 1 });
LocalizationSettingsSchema.index({ currency: 1 });

module.exports = mongoose.model('LocalizationSettings', LocalizationSettingsSchema);
