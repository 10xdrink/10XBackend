// services/uploadService.js

const cloudinary = require('../config/cloudinary');
const logger = require('../utils/logger');
const streamifier = require('streamifier');

/**
 * Uploads an image buffer to Cloudinary.
 * @param {Buffer} buffer - The image buffer.
 * @param {String} folder - The Cloudinary folder where the image will be stored.
 * @returns {Promise<String>} - The URL of the uploaded image.
 */
const uploadToCloudinary = (buffer, folder) => {
  return new Promise((resolve, reject) => {
    const cld_upload_stream = cloudinary.uploader.upload_stream(
      {
        folder,
        width: 800,
        height: 800,
        crop: 'fill',
      },
      (error, result) => {
        if (result) {
          resolve(result.secure_url);
        } else {
          reject(error);
        }
      }
    );

    streamifier.createReadStream(buffer).pipe(cld_upload_stream);
  });
};

module.exports = {
  uploadToCloudinary,
};
