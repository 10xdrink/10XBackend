// controllers/seoController.js

const SEOSettings = require('../models/SEOSettings');
const { validationResult } = require('express-validator');

// Get all SEO settings
exports.getAllSEOSettings = async (req, res) => {
  try {
    const settings = await SEOSettings.find();
    res.status(200).json({
      success: true,
      data: settings,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve SEO settings',
      error: error.message,
    });
  }
};

// Get SEO setting by key
exports.getSEOSettingByKey = async (req, res) => {
  const { key } = req.params;
  try {
    const setting = await SEOSettings.findOne({ key });
    if (!setting) {
      return res.status(404).json({ success: false, message: 'SEO setting not found' });
    }
    res.status(200).json({ success: true, data: setting });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve SEO setting',
      error: error.message,
    });
  }
};

// Update SEO setting
exports.updateSEOSetting = async (req, res) => {
  const { key } = req.params;
  const { title, description, keywords, openGraphTags } = req.body;

  try {
    let setting = await SEOSettings.findOne({ key });

    if (!setting) {
      setting = new SEOSettings({ key, title, description, keywords, openGraphTags });
    } else {
      setting.title = title || setting.title;
      setting.description = description || setting.description;
      setting.keywords = keywords || setting.keywords;
      setting.openGraphTags = openGraphTags || setting.openGraphTags;
    }

    await setting.save();

    res.status(200).json({
      success: true,
      message: 'SEO setting updated successfully',
      data: setting,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to update SEO setting',
      error: error.message,
    });
  }
};

// Delete SEO setting by key
exports.deleteSEOSetting = async (req, res) => {
  const { key } = req.params;

  try {
    const result = await SEOSettings.findOneAndDelete({ key });

    if (!result) {
      return res.status(404).json({ success: false, message: 'SEO setting not found' });
    }

    res.status(200).json({
      success: true,
      message: 'SEO setting deleted successfully',
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to delete SEO setting',
      error: error.message,
    });
  }
};
