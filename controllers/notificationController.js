// controllers/notificationController.js

const NotificationTemplate = require('../models/NotificationTemplate');
const AuditLog = require('../models/AuditLog');
const { validationResult } = require('express-validator');

// Retrieve all notification templates
exports.getAllTemplates = async (req, res) => {
  try {
    const templates = await NotificationTemplate.find({ isActive: true });
    res.status(200).json({ success: true, data: templates });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to retrieve notification templates', error: error.message });
  }
};

// Retrieve a specific notification template by ID
exports.getTemplateById = async (req, res) => {
  const { id } = req.params;
  try {
    const template = await NotificationTemplate.findById(id);
    if (!template) {
      return res.status(404).json({ success: false, message: 'Notification template not found' });
    }
    res.status(200).json({ success: true, data: template });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to retrieve notification template', error: error.message });
  }
};

// Create a new notification template
exports.createTemplate = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ success: false, errors: errors.array() });
  }

  const { title, subject, body } = req.body;

  try {
    const newTemplate = await NotificationTemplate.create({ title, subject, body });

    await AuditLog.create({
      action: 'create_template',
      key: newTemplate._id,
      changedBy: req.user.id,
      details: `Created new template: ${title}`,
    });

    res.status(201).json({ success: true, data: newTemplate, message: 'Notification template created successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to create notification template', error: error.message });
  }
};

// Update a notification template by ID
exports.updateTemplate = async (req, res) => {
  const { id } = req.params;
  const { title, subject, body } = req.body;

  try {
    const template = await NotificationTemplate.findById(id);
    if (!template) {
      return res.status(404).json({ success: false, message: 'Notification template not found' });
    }

    // Log the changes
    await AuditLog.create({
      action: 'update_template',
      key: template._id,
      changedBy: req.user.id,
      details: `Updated template: ${template.title} to ${title || template.title}`,
    });

    template.title = title || template.title;
    template.subject = subject || template.subject;
    template.body = body || template.body;

    await template.save();

    res.status(200).json({ success: true, data: template, message: 'Notification template updated successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update notification template', error: error.message });
  }
};

// Delete a notification template by ID
exports.deleteTemplate = async (req, res) => {
  const { id } = req.params;

  try {
    const template = await NotificationTemplate.findByIdAndUpdate(id, { isActive: false });
    if (!template) {
      return res.status(404).json({ success: false, message: 'Notification template not found' });
    }

    // Log the deletion
    await AuditLog.create({
      action: 'delete_template',
      key: template._id,
      changedBy: req.user.id,
      details: `Deleted template: ${template.title}`,
    });

    res.status(200).json({ success: true, message: 'Notification template deleted successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to delete notification template', error: error.message });
  }
};

// Send a test notification using a specific template
exports.sendTestNotification = async (req, res) => {
  const { id } = req.params;
  const { email, variables } = req.body;

  try {
    const template = await NotificationTemplate.findById(id);
    if (!template) {
      return res.status(404).json({ success: false, message: 'Notification template not found' });
    }

    // Replace variables in the template body
    let message = template.body;
    for (const [key, value] of Object.entries(variables)) {
      message = message.replace(new RegExp(`{{${key}}}`, 'g'), value);
    }

    // Assuming `sendEmail` utility is available
    await sendEmail({
      email,
      subject: template.subject,
      message,
    });

    res.status(200).json({ success: true, message: `Test notification sent to ${email}` });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to send test notification', error: error.message });
  }
};
