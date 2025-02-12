const cloudinary = require('cloudinary').v2; // Ensure you're using cloudinary.v2
const logger = require('../utils/logger');

// Properly configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadImage = async (filePath, options = {}) => {
  try {
    const result = await cloudinary.uploader.upload(filePath, options);
    logger.info(`Image uploaded to Cloudinary successfully: ${result.secure_url}`);
    return result;
  } catch (error) {
    logger.error(`Cloudinary image upload failed: ${error.message}`);
    throw new Error('Failed to upload image');
  }
};

const deleteImage = async (publicId) => {
  try {
    const result = await cloudinary.uploader.destroy(publicId);
    if (result.result === 'ok') {
      logger.info(`Image deleted from Cloudinary: ${publicId}`);
    } else {
      logger.warn(`Image deletion failed for public ID: ${publicId}`);
    }
    return result;
  } catch (error) {
    logger.error(`Cloudinary image deletion failed: ${error.message}`);
    throw new Error('Failed to delete image');
  }
};

module.exports = {
  uploadImage,
  deleteImage,
};
