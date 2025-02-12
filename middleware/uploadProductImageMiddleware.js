// middleware/uploadProductImageMiddleware.js

const multer = require('multer');
const path = require('path');
const ERROR_CODES = require('../constants/errorCodes');

// Set up in-memory storage
const storage = multer.memoryStorage();

// Configure file filter to allow only images
const fileFilter = (req, file, cb) => {
  const filetypes = /jpeg|jpg|png|gif/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = filetypes.test(file.mimetype);

  if (mimetype && extname) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'));
  }
};

// Initialize multer with storage, file filter, and size limit
const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB limit
});

// Middleware to handle single file upload with field name 'image'
const uploadProductImageMiddleware = upload.single('image');

// Middleware to handle upload errors
const handleUploadErrors = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    // Multer-specific errors
    return res.status(400).json({ success: false, message: `Upload error: ${err.message}` });
  } else if (err) {
    // Other errors, such as file type issues
    return res.status(400).json({ success: false, message: err.message || ERROR_CODES.INVALID_INPUT });
  }
  next();
};

// Export middleware as an array
module.exports = [uploadProductImageMiddleware, handleUploadErrors];
