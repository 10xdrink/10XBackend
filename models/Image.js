// models/Image.js

const mongoose = require('mongoose');

const ImageSchema = new mongoose.Schema({
  public_id: {
    type: String,
    required: true,
    unique: true,
  },
  secure_url: {
    type: String,
    required: true,
  },
  folder: {
    type: String,
    required: true,
  },
  uploaded_at: {
    type: Date,
    default: Date.now,
  },
  // Add any other fields you need
});

module.exports = mongoose.model('Image', ImageSchema);
