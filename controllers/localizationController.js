// controllers/localizationController.js

const LocalizationSettings = require('../models/LocalizationSettings');
const { validationResult } = require('express-validator');

// Get localization settings for a specific region
exports.getLocalizationSettings = async (req, res) => {
  const { region } = req.params;
  try {
    const settings = await LocalizationSettings.findOne({ region: region.toUpperCase() });
    if (!settings) {
      return res.status(404).json({ success: false, message: 'Settings not found for this region' });
    }
    res.status(200).json({ success: true, data: settings });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to retrieve settings', error: error.message });
  }
};

// Update localization settings for a specific region
exports.updateLocalizationSettings = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, errors: errors.array() });
  }

  const { region } = req.params;
  const updates = req.body;
  try {
    const updatedSettings = await LocalizationSettings.findOneAndUpdate(
      { region: region.toUpperCase() },
      updates,
      { new: true, upsert: true }
    );
    res.status(200).json({ success: true, data: updatedSettings, message: 'Settings updated successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update settings', error: error.message });
  }
};

// Create new localization settings
exports.createLocalizationSettings = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, errors: errors.array() });
  }

  try {
    const settings = new LocalizationSettings(req.body);
    await settings.save();
    res.status(201).json({ success: true, data: settings, message: 'Settings created successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to create settings', error: error.message });
  }
};

// List all localization settings (for admin use)
exports.listAllLocalizationSettings = async (req, res) => {
  try {
    const settings = await LocalizationSettings.find({});
    res.status(200).json({ success: true, data: settings });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to list settings', error: error.message });
  }
};
