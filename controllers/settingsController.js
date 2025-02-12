const Settings = require('../models/Settings');
const SEOSettings = require('../models/SEOSettings');
const NotificationTemplate = require('../models/NotificationTemplate');
const AuditLog = require('../models/AuditLog');
const { validationResult } = require('express-validator');

// Retrieve all settings with optional categorization and localization
exports.getSettings = async (req, res) => {
  try {
    const settings = await Settings.find({ isActive: true }).lean();
    const seoSettings = await SEOSettings.find({ isActive: true }).lean();
    const notificationTemplates = await NotificationTemplate.find({ isActive: true }).lean();

    res.status(200).json({
      success: true,
      data: {
        settings,
        seoSettings,
        notificationTemplates,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to retrieve settings', error: error.message });
  }
};

// Update a specific setting with version control and optional categorization
exports.updateSettings = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, errors: errors.array() });
  }

  const { key, value, category } = req.body;

  try {
    const existingSetting = await Settings.findOne({ key });
    if (existingSetting) {
      await AuditLog.create({
        action: 'update_setting',
        key,
        previousValue: existingSetting.value,
        newValue: value,
        category: existingSetting.category,
        changedBy: req.user.id,
      });

      existingSetting.value = value;
      if (category) existingSetting.category = category;
      await existingSetting.save();
    } else {
      await Settings.create({ key, value, category });
    }

    res.status(200).json({ success: true, message: 'Setting updated successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update setting', error: error.message });
  }
};

// Retrieve version history for a setting
exports.getSettingHistory = async (req, res) => {
  const { key } = req.params;

  try {
    const history = await AuditLog.find({ action: 'update_setting', key }).sort({ createdAt: -1 });
    res.status(200).json({ success: true, data: history });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to retrieve setting history', error: error.message });
  }
};

// Retrieve SEO settings for a specific page
exports.getSEOSettings = async (req, res) => {
  const { page } = req.params;

  try {
    const seoSettings = await SEOSettings.findOne({ page });
    if (!seoSettings) {
      return res.status(404).json({ success: false, message: 'SEO settings not found for this page' });
    }

    res.status(200).json({ success: true, data: seoSettings });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to retrieve SEO settings', error: error.message });
  }
};

// Update SEO settings for a page
exports.updateSEOSettings = async (req, res) => {
  const { page } = req.params;
  const updates = req.body;

  try {
    const updatedSEOSettings = await SEOSettings.findOneAndUpdate({ page }, updates, { new: true, upsert: true });
    res.status(200).json({ success: true, data: updatedSEOSettings, message: 'SEO settings updated successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update SEO settings', error: error.message });
  }
};

// Toggle a feature's enable/disable status
exports.toggleFeature = async (req, res) => {
  const { featureKey, enable } = req.body;

  try {
    const featureSetting = await Settings.findOneAndUpdate(
      { key: featureKey },
      { value: enable },
      { new: true, upsert: true }
    );

    res.status(200).json({ success: true, data: featureSetting, message: 'Feature toggle updated successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update feature toggle', error: error.message });
  }
};

// Retrieve all notification templates
exports.getNotificationTemplates = async (req, res) => {
  try {
    const templates = await NotificationTemplate.find({ isActive: true }).lean();
    res.status(200).json({ success: true, data: templates });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to retrieve notification templates', error: error.message });
  }
};

// Update a specific notification template
exports.updateNotificationTemplate = async (req, res) => {
  const { id } = req.params;
  const { subject, body } = req.body;

  try {
    const template = await NotificationTemplate.findByIdAndUpdate(id, { subject, body }, { new: true });
    if (!template) {
      return res.status(404).json({ success: false, message: 'Notification template not found' });
    }

    res.status(200).json({ success: true, data: template, message: 'Notification template updated successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update notification template', error: error.message });
  }
};
