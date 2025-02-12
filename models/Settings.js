const mongoose = require('mongoose');

// Schema for individual setting entries
const SettingSchema = new mongoose.Schema(
  {
    key: {
      type: String,
      required: [true, 'Please provide a setting key'],
      unique: true,
      trim: true,
      maxlength: [100, 'Key cannot exceed 100 characters'],
    },
    value: {
      type: mongoose.Schema.Types.Mixed, // Allows any data type (string, number, object, etc.)
      required: [true, 'Please provide a setting value'],
    },
    category: {
      type: String,
      required: [true, 'Please specify a category'],
      enum: [
        'Site Settings',
        'Payment Settings',
        'Notification Settings',
        'Feature Toggles',
        'SEO Settings',
        'Tax and Shipping',
      ],
    },
    description: {
      type: String,
      trim: true,
      maxlength: [500, 'Description cannot exceed 500 characters'],
    },
    isActive: {
      type: Boolean,
      default: true, // For soft deletion or deactivation of settings
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Versioning Schema for maintaining a history log of setting changes
const SettingVersionSchema = new mongoose.Schema(
  {
    settingId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Setting',
      required: true,
    },
    previousValue: {
      type: mongoose.Schema.Types.Mixed,
      required: true,
    },
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

// Static method to create or update a setting with version control
SettingSchema.statics.upsertSetting = async function (key, newValue, category, updatedBy, description = '') {
  let setting = await this.findOne({ key });
  if (setting) {
    // Log the old version before updating
    await SettingVersion.create({
      settingId: setting._id,
      previousValue: setting.value,
      updatedBy,
    });

    // Update the setting
    setting.value = newValue;
    setting.category = category;
    setting.updatedBy = updatedBy;
    setting.description = description;
    return setting.save();
  } else {
    // Create a new setting if it doesn't exist
    setting = new this({
      key,
      value: newValue,
      category,
      createdBy: updatedBy,
      description,
    });
    return setting.save();
  }
};

// Static method to get setting history
SettingSchema.statics.getSettingHistory = async function (settingId) {
  return SettingVersion.find({ settingId }).sort({ updatedAt: -1 });
};

// Static method to restore a previous version of a setting
SettingSchema.statics.restoreSettingVersion = async function (settingId, versionId, updatedBy) {
  const version = await SettingVersion.findById(versionId);
  if (!version) throw new Error('Version not found');

  const setting = await this.findById(settingId);
  if (!setting) throw new Error('Setting not found');

  // Log current version before restoring
  await SettingVersion.create({
    settingId: setting._id,
    previousValue: setting.value,
    updatedBy,
  });

  setting.value = version.previousValue;
  setting.updatedBy = updatedBy;
  return setting.save();
};

// Indexes for fast search and retrieval
SettingSchema.index({ key: 1, isActive: 1 });
SettingSchema.index({ category: 1 });
SettingSchema.index({ updatedAt: -1 }); // For sorting by latest updates

// Setting Version Model for maintaining history
const SettingVersion = mongoose.model('SettingVersion', SettingVersionSchema);

module.exports = mongoose.model('Setting', SettingSchema);
