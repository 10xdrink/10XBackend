const mongoose = require('mongoose');

// Schema for notification templates
const NotificationTemplateSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please provide a template name'],
      unique: true,
      trim: true,
      maxlength: [100, 'Template name cannot exceed 100 characters'],
    },
    subject: {
      type: String,
      required: [true, 'Please provide a subject for the template'],
      trim: true,
    },
    body: {
      type: String,
      required: [true, 'Please provide the body content for the template'],
    },
    category: {
      type: String,
      enum: ['Email', 'SMS', 'Push Notification'],
      required: [true, 'Please specify the template category'],
    },
    isActive: {
      type: Boolean,
      default: true, // To enable or disable a template
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Creator is required'],
    },
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Updater is required'],
    },
  },
  { 
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Schema for version control of templates
const TemplateVersionSchema = new mongoose.Schema(
  {
    templateId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'NotificationTemplate',
      required: true,
    },
    previousSubject: {
      type: String,
      required: true,
    },
    previousBody: {
      type: String,
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
  { 
    timestamps: true,
  }
);

// Static method to create or update a notification template with version control
NotificationTemplateSchema.statics.upsertTemplate = async function (name, subject, body, category, updatedBy) {
  let template = await this.findOne({ name });
  if (template) {
    // Log the current version before updating
    await TemplateVersion.create({
      templateId: template._id,
      previousSubject: template.subject,
      previousBody: template.body,
      updatedBy,
    });

    // Update the template
    template.subject = subject;
    template.body = body;
    template.category = category;
    template.updatedBy = updatedBy;
  } else {
    // Create a new template if it doesn't exist
    template = new this({
      name,
      subject,
      body,
      category,
      createdBy: updatedBy,
      updatedBy,
    });
  }
  return template.save();
};

// Static method to retrieve template history
NotificationTemplateSchema.statics.getTemplateHistory = function (templateId) {
  return TemplateVersion.find({ templateId }).sort({ updatedAt: -1 });
};

// Static method to restore a previous version of a template
NotificationTemplateSchema.statics.restoreTemplateVersion = async function (templateId, versionId, updatedBy) {
  const version = await TemplateVersion.findById(versionId);
  if (!version) throw new Error('Version not found');

  const template = await this.findById(templateId);
  if (!template) throw new Error('Template not found');

  // Log current version before restoring
  await TemplateVersion.create({
    templateId: template._id,
    previousSubject: template.subject,
    previousBody: template.body,
    updatedBy,
  });

  template.subject = version.previousSubject;
  template.body = version.previousBody;
  template.updatedBy = updatedBy;
  return template.save();
};

// Indexes for faster retrieval
NotificationTemplateSchema.index({ name: 1 });
NotificationTemplateSchema.index({ category: 1 });
TemplateVersionSchema.index({ templateId: 1, updatedAt: -1 });

// Models for notification templates and version history
const TemplateVersion = mongoose.model('TemplateVersion', TemplateVersionSchema);
module.exports = mongoose.model('NotificationTemplate', NotificationTemplateSchema);
