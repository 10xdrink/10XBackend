// routes/authRoutes.js

const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const passport = require('passport');
const { generateAccessToken } = require('../utils/generateToken');

const validateMiddleware = require('../middleware/validateMiddleware');
const authMiddleware = require('../middleware/authMiddleware');
const uploadMiddleware = require('../middleware/uploadMiddleware'); // Import as an array

// Validation rules for registration
const registerValidation = [
  body('name')
    .isString()
    .isLength({ min: 3 })
    .withMessage('Name must be at least 3 characters long'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password')
    .isStrongPassword()
    .withMessage(
      'Password must be at least 8 characters long and include one uppercase letter, one number, and one special character'
    ),
];

// Validation rules for login
const loginValidation = [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').exists().withMessage('Password is required'),
];

// Validation rules for verify OTP
const verifyOTPValidation = [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('otp')
    .isLength({ min: 6, max: 6 })
    .withMessage('OTP must be 6 digits'),
];

// Validation rules for forgot password
const forgotPasswordValidation = [
  body('email').isEmail().withMessage('Please provide a valid email'),
];

// Validation rules for reset password
const resetPasswordValidation = [
  body('password')
    .isStrongPassword()
    .withMessage(
      'Password must be at least 8 characters long and include one uppercase letter, one number, and one special character'
    ),
];

// Validation rules for updating profile
const updateProfileValidation = [
  body('name')
    .optional()
    .isString()
    .isLength({ min: 3 })
    .withMessage('Name must be at least 3 characters long'),
  body('email')
    .optional()
    .isEmail()
    .withMessage('Please provide a valid email'),
];

// Validation rules for account deletion
const requestDeleteAccountValidation = [
  // No body parameters needed; user is authenticated
];

// Validation rules for resend OTP
const resendOTPValidation = [
  body('email').isEmail().withMessage('Please provide a valid email'),
];

// Routes
router.post(
  '/register',
  registerValidation,
  validateMiddleware,
  authController.register
);

router.post(
  '/login',
  loginValidation,
  validateMiddleware,
  authController.login
);

router.post(
  '/verify-otp',
  verifyOTPValidation,
  validateMiddleware,
  authController.verifyOTP
);

router.post(
  '/resend-otp',
  resendOTPValidation,
  validateMiddleware,
  authController.resendOTP
);

router.post(
  '/logout',
  authMiddleware,
  authController.logout
);

router.get(
  '/me',
  authMiddleware,
  authController.getMe
);

router.post(
  '/forgot-password',
  forgotPasswordValidation,
  validateMiddleware,
  authController.forgotPassword
);

router.post(
  '/reset-password/:resetToken',
  resetPasswordValidation,
  validateMiddleware,
  authController.resetPassword
);

// Account Deletion Routes
router.post(
  '/request-delete-account',
  authMiddleware,
  requestDeleteAccountValidation,
  validateMiddleware,
  authController.requestAccountDeletion
);

router.get(
  '/confirm-delete/:token',
  authController.confirmAccountDeletion
);

// Google OAuth login route
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google OAuth callback route
router.get(
  '/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Ensure req.user is populated after successful authentication
    if (req.user) {
      const token = generateAccessToken(req.user);
      // Use the environment variable for the frontend URL
      const frontendURL = process.env.FRONTEND_URL || 'http://localhost:5173';
      // Redirect to the frontend with the token
      res.redirect(`${frontendURL}/user-dashboard?token=${token}`);
    } else {
      res.redirect('/login');
    }
  }
);

// Update profile with image upload
router.put(
  '/update-profile',
  authMiddleware,        // Ensure the user is authenticated
  ...uploadMiddleware,  // Spread the array to apply both upload and error handling middleware
  updateProfileValidation,
  validateMiddleware,
  authController.updateProfile
);

module.exports = router;
