// config/cloudinary.js

const cloudinary = require('cloudinary').v2;
const dotenv = require('dotenv');

dotenv.config();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, // Add to your .env
  api_key: process.env.CLOUDINARY_API_KEY,       // Add to your .env
  api_secret: process.env.CLOUDINARY_API_SECRET, // Add to your .env
});

module.exports = cloudinary;
