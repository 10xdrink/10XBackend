// controllers/authController.js

const fs = require("fs");
const path = require("path");
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const handlebars = require("handlebars");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");
const logger = require("../utils/logger");
const ERROR_CODES = require("../constants/errorCodes");
const cloudinary = require("../config/cloudinary");

// Import related models for cascading deletes
const Order = require("../models/Order");
// Removed Post import as it's not required
// const Post = require("../models/Post"); // Removed

/**
 * @desc    Register a new user
 * @route   POST /api/auth/register
 * @access  Public
 */
exports.register = async (req, res, next) => {
  try {
    const { name, email, password, role, adminSecretKey } = req.body;

    // Check if user exists
    let user = await User.findOne({ email });
    if (user) {
      logger.warn(`Registration attempt with existing email: ${email}`);
      return res
        .status(400)
        .json({ success: false, message: "User already exists" });
    }

    // Check if the role is an elevated one and validate the admin secret key
    if (role && role !== "user") {
      const adminKeys = {
        "super-admin": process.env.SUPER_ADMIN,
        "product-manager": process.env.PRODUCT_MANAGER,
        "order-manager": process.env.ORDER_MANAGER,
        "content-manager": process.env.CONTENT_MANAGER,
        "customer-support-manager": process.env.CUSTOMER_SUPPORT_MANAGER,
        "marketing-manager": process.env.MARKETING_MANAGER,
        "finance-manager": process.env.FINANCE_MANAGER,
        "sales-manager": process.env.SALES_MANAGER,
      };

      // Validate the provided admin secret key
      if (!adminSecretKey || adminSecretKey !== adminKeys[role]) {
        logger.warn(
          `Invalid or missing admin secret key for role '${role}' during registration`
        );
        return res
          .status(403)
          .json({ success: false, message: "Invalid admin secret key" });
      }
    }

    // Create user
    user = new User({
      name,
      email,
      password,
      role: role || "user", // Default role set to 'user'
    });

    // Hash password
    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(password, salt);

    // Handle profile picture upload if provided
    if (req.file) {
      try {
        const uploadResult = await new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: "user_profiles" },
            (error, result) => {
              if (error) {
                logger.error("Cloudinary Upload Error:", error);
                return reject(error);
              }
              resolve(result);
            }
          );
          stream.end(req.file.buffer);
        });

        // Set profile picture URL
        user.profilePicture = uploadResult.secure_url;
        logger.info(
          `Profile picture uploaded for user ${email}: ${uploadResult.secure_url}`
        );
      } catch (uploadError) {
        logger.error("Profile Picture Upload Error:", uploadError);
        return res.status(500).json({
          success: false,
          message: "Failed to upload profile picture",
        });
      }
    }

    await user.save();
    logger.info(`New user registered: ${email}`);

    // Generate JWT
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    res.status(201).json({
      success: true,
      token,
      data: user, // toJSON method in User model excludes sensitive fields
    });
  } catch (error) {
    logger.error("Register Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Update user profile
 * @route   PUT /api/auth/update-profile
 * @access  Private
 */
exports.updateProfile = async (req, res, next) => {
  try {
    const { name, email } = req.body;

    // Fetch the user by ID from the token
    const user = await User.findById(req.user.id);

    if (!user) {
      logger.warn(`Update Profile: User not found with ID ${req.user.id}`);
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // If email is being updated, check if it's already in use
    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        logger.warn(`Update Profile: Email already in use - ${email}`);
        return res
          .status(400)
          .json({ success: false, message: "Email already in use" });
      }
      user.email = email;
    }

    // Update name if provided
    if (name) {
      user.name = name;
    }

    // Handle profile picture upload if a file is provided
    if (req.file) {
      try {
        const uploadResult = await new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: "user_profiles" },
            (error, result) => {
              if (error) {
                logger.error("Cloudinary Upload Error:", error);
                return reject(error);
              }
              resolve(result);
            }
          );
          stream.end(req.file.buffer);
        });

        // Update user's profile picture URL
        user.profilePicture = uploadResult.secure_url;
        logger.info(
          `Profile picture updated for user ${user.email}: ${uploadResult.secure_url}`
        );
      } catch (uploadError) {
        logger.error("Profile Picture Upload Error:", uploadError);
        return res.status(500).json({
          success: false,
          message: "Failed to upload profile picture",
        });
      }
    }

    await user.save();
    logger.info(`Profile updated for user ${user.email}`);

    res.status(200).json({
      success: true,
      data: user,
    });
  } catch (error) {
    logger.error("Update Profile Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Login user/admin with OTP for admin roles
 * @route   POST /api/auth/login
 * @access  Public
 */
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Validate email & password
    if (!email || !password) {
      logger.warn("Login attempt with missing email or password");
      return res.status(400).json({
        success: false,
        message: "Please provide email and password",
      });
    }

    // Check for user
    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      logger.warn(`Login failed: No user found with email ${email}`);
      return res
        .status(401)
        .json({ success: false, message: ERROR_CODES.AUTHENTICATION_FAILED });
    }

    // Check if user is active
    if (!user.isActive) {
      logger.warn(`Login attempt for inactive user ${email}`);
      return res.status(403).json({
        success: false,
        message: "Account is deactivated. Please contact support.",
      });
    }

    // Check if password matches
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logger.warn(`Login failed: Incorrect password for email ${email}`);
      return res
        .status(401)
        .json({ success: false, message: ERROR_CODES.AUTHENTICATION_FAILED });
    }

    // Check if user is an admin
    const isAdmin = user.role !== "user";

    if (isAdmin) {
      // Generate OTP
      const otp = crypto.randomInt(100000, 999999).toString(); // 6-digit OTP
      user.otp = otp;
      user.otpExpire = Date.now() + 10 * 60 * 1000; // 10 minutes
      await user.save();

      // Send OTP via email
      const templatePath = path.join(__dirname, "../templates/otpEmail.html");
      const templateSource = fs.readFileSync(templatePath, "utf8");
      const template = handlebars.compile(templateSource);

      const htmlContent = template({
        name: user.name,
        otp,
      });

      // Define plain text message as a fallback
      const plainTextMessage = `Hello ${user.name},

Your OTP for admin login is: ${otp}

This OTP is valid for 10 minutes.

If you did not attempt to login, please contact support immediately.

Thank you,
Your Company Team`;

      await sendEmail({
        email: user.email,
        subject: "Admin Login OTP Verification",
        message: plainTextMessage,
        html: htmlContent, // Send the HTML content
      });

      logger.info(`OTP sent to admin user: ${user.email}`);

      return res.status(200).json({
        success: true,
        message: "OTP sent to your email. Please verify to complete login.",
        requiresOTP: true,
      });
    }

    // For non-admin users, proceed to issue JWT
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    logger.info(`User logged in: ${user.email}`);

    res.status(200).json({
      success: true,
      token,
      data: user,
    });
  } catch (error) {
    logger.error("Login Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Verify OTP for admin login
 * @route   POST /api/auth/verify-otp
 * @access  Public
 */
exports.verifyOTP = async (req, res, next) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Please provide email and OTP",
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      logger.warn(`OTP Verification failed: No user found with email ${email}`);
      return res
        .status(401)
        .json({ success: false, message: ERROR_CODES.AUTHENTICATION_FAILED });
    }

    if (user.otp !== otp || user.otpExpire < Date.now()) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP",
      });
    }

    // Clear OTP fields
    user.otp = undefined;
    user.otpExpire = undefined;
    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    logger.info(`Admin user logged in after OTP verification: ${user.email}`);

    res.status(200).json({
      success: true,
      token,
      data: user,
    });
  } catch (error) {
    logger.error("Verify OTP Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Resend OTP for admin login
 * @route   POST /api/auth/resend-otp
 * @access  Public
 */
exports.resendOTP = async (req, res, next) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Please provide email",
      });
    }

    const user = await User.findOne({ email });

    if (!user || user.role === "user") {
      return res.status(400).json({
        success: false,
        message: "Invalid request",
      });
    }

    // Generate new OTP
    const otp = crypto.randomInt(100000, 999999).toString(); // 6-digit OTP
    user.otp = otp;
    user.otpExpire = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    // Send OTP via email
    const templatePath = path.join(__dirname, "../templates/otpEmail.html");
    const templateSource = fs.readFileSync(templatePath, "utf8");
    const template = handlebars.compile(templateSource);

    const htmlContent = template({
      name: user.name,
      otp,
    });

    // Define plain text message as a fallback
    const plainTextMessage = `Hello ${user.name},

Your OTP for admin login is: ${otp}

This OTP is valid for 10 minutes.

If you did not attempt to login, please contact support immediately.

Thank you,
Your Company Team`;

    await sendEmail({
      email: user.email,
      subject: "Admin Login OTP Verification",
      message: plainTextMessage,
      html: htmlContent, // Send the HTML content
    });

    logger.info(`OTP resent to admin user: ${user.email}`);

    res.status(200).json({
      success: true,
      message: "OTP resent to your email. Please verify to complete login.",
    });
  } catch (error) {
    logger.error("Resend OTP Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Get current logged-in user
 * @route   GET /api/auth/me
 * @access  Private
 */
exports.getMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      logger.warn(`Get Me: User not found with ID ${req.user.id}`);
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    res.status(200).json({
      success: true,
      data: user,
    });
  } catch (error) {
    logger.error("Get Me Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Forgot Password
 * @route   POST /api/auth/forgot-password
 * @access  Public
 */
exports.forgotPassword = async (req, res, next) => {
  try {
    logger.info("Initiating forgotPassword process");
    logger.info(`Request body: ${JSON.stringify(req.body)}`);

    // Find the user by email
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      logger.warn(
        `Forgot Password: No user found with email ${req.body.email}`
      );
      return res
        .status(404)
        .json({ success: false, message: "There is no user with that email" });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString("hex");
    logger.info(`Generated reset token: ${resetToken}`);

    // Hash token and set to resetPasswordToken field
    const hashedResetToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");
    user.resetPasswordToken = hashedResetToken;
    logger.info(`Hashed reset token: ${hashedResetToken}`);

    // Set token expiration time (10 minutes)
    user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes
    logger.info(
      `Reset password token expiration set to: ${new Date(
        user.resetPasswordExpire
      ).toISOString()}`
    );

    await user.save({ validateBeforeSave: false });
    logger.info(`Saved reset token and expiration for user: ${user.email}`);

    // Create reset URL pointing to the frontend
    const frontendURL = process.env.FRONTEND_URL || "http://localhost:5173";
    const resetUrl = `${frontendURL}/reset-password/${resetToken}`;
    logger.info(`Reset URL: ${resetUrl}`);

    // Load and compile the HTML template
    const templatePath = path.join(
      __dirname,
      "../templates/passwordReset.html"
    );
    logger.info(`Template path: ${templatePath}`);
    const templateSource = fs.readFileSync(templatePath, "utf8");
    const template = handlebars.compile(templateSource);

    const htmlContent = template({
      name: user.name,
      resetUrl,
    });

    // Define plain text message as a fallback
    const plainTextMessage = `You are receiving this email because you (or someone else) have requested the reset of a password.\n\nPlease use the following link to reset your password:\n\n${resetUrl}\n\nIf you did not request this, please ignore this email and your password will remain unchanged.`;

    try {
      await sendEmail({
        email: user.email,
        subject: "Password Reset Request",
        message: plainTextMessage,
        html: htmlContent, // Send the HTML content
      });

      logger.info(`Password reset email sent to: ${user.email}`);
      res.status(200).json({ success: true, data: "Email sent" });
    } catch (err) {
      // Reset the reset token and expiration
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;

      await user.save({ validateBeforeSave: false });
      logger.error("Forgot Password Email Error:", err);
      return res
        .status(500)
        .json({ success: false, message: "Email could not be sent" });
    }
  } catch (error) {
    logger.error("Forgot Password Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Reset Password
 * @route   POST /api/auth/reset-password/:resetToken
 * @access  Public
 */
exports.resetPassword = async (req, res, next) => {
  try {
    const { resetToken } = req.params;
    const { password } = req.body;

    logger.info(`Received reset password request with token: ${resetToken}`);

    // Validate input
    if (!password) {
      logger.warn("Reset Password: No password provided in request");
      return res.status(400).json({
        success: false,
        message: "Please provide a new password",
      });
    }

    // Hash the received reset token
    const hashedResetToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");
    logger.info(`Hashed received reset token: ${hashedResetToken}`);

    // Find the user by the hashed reset token and ensure token is not expired
    const user = await User.findOne({
      resetPasswordToken: hashedResetToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      logger.warn(
        `Reset Password: Invalid or expired token attempted by user with token ${resetToken}`
      );
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired token" });
    }

    logger.info(`User found for password reset: ${user.email}`);

    // Hash the new password before saving
    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(password, salt);
    logger.info(`Password updated for user: ${user.email}`);

    // Clear reset token fields
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();
    logger.info(`Reset token cleared for user: ${user.email}`);

    // Generate JWT for the user
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    logger.info(`JWT generated for user ${user.email} after password reset`);

    res.status(200).json({
      success: true,
      token,
      data: user,
    });
  } catch (error) {
    logger.error("Reset Password Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Logout User
 * @route   POST /api/auth/logout
 * @access  Private
 */
exports.logout = async (req, res, next) => {
  try {
    // If using token blacklist, add token to blacklist here
    // Example: await blacklistToken(req.token);
    logger.info(`User logged out: ${req.user.email}`);

    res.status(200).json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    logger.error("Logout Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Initiates the account deletion process by sending a confirmation email.
 * @route   POST /api/auth/request-delete-account
 * @access  Private
 */
exports.requestAccountDeletion = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      logger.warn(
        `Request Account Deletion: User not found with ID ${req.user.id}`
      );
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Generate a unique deletion token
    const deletionToken = crypto.randomBytes(20).toString("hex");

    // Hash the token and set it to the user
    const hashedDeletionToken = crypto
      .createHash("sha256")
      .update(deletionToken)
      .digest("hex");
    user.deletionToken = hashedDeletionToken;
    user.deletionTokenExpire = Date.now() + 24 * 60 * 60 * 1000; // Token valid for 24 hours

    await user.save({ validateBeforeSave: false });
    logger.info(`Deletion token generated for user: ${user.email}`);

    // Create deletion URL pointing to the frontend
    const frontendURL = process.env.FRONTEND_URL || "http://localhost:5173";
    const deleteUrl = `${frontendURL}/confirm-delete/${deletionToken}`;

    // Load and compile the HTML template
    const templatePath = path.join(
      __dirname,
      "../templates/accountDeletion.html"
    );
    const templateSource = fs.readFileSync(templatePath, "utf8");
    const template = handlebars.compile(templateSource);

    const htmlContent = template({
      name: user.name,
      deleteUrl,
      supportUrl: `${frontendURL}/contact`, // Ensure this matches your actual support/contact page
    });

    // Define plain text message as a fallback
    const plainTextMessage = `Hello ${user.name},

You have requested to delete your account. Please confirm this action by visiting the following link:

${deleteUrl}

If you did not request this, please ignore this email or contact support immediately.

Thank you,
Your Company Team`;

    // Send the confirmation email
    await sendEmail({
      email: user.email,
      subject: "Confirm Account Deletion",
      message: plainTextMessage,
      html: htmlContent,
    });

    logger.info(`Account deletion confirmation email sent to: ${user.email}`);

    res.status(200).json({
      success: true,
      message:
        "Account deletion confirmation email sent. Please check your inbox.",
    });
  } catch (error) {
    logger.error("Request Account Deletion Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Confirms the account deletion when the user clicks the link in the email.
 * @route   GET /api/auth/confirm-delete/:token
 * @access  Public
 */
exports.confirmAccountDeletion = async (req, res, next) => {
  try {
    const { token } = req.params;

    if (!token) {
      logger.warn("Confirm Account Deletion: No token provided");
      return res
        .status(400)
        .json({ success: false, message: "Invalid or missing token" });
    }

    // Hash the received token
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    // Find the user with the matching deletion token and ensure it's not expired
    const user = await User.findOne({
      deletionToken: hashedToken,
      deletionTokenExpire: { $gt: Date.now() },
    });

    if (!user) {
      logger.warn(`Confirm Account Deletion: Invalid or expired token`);
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired token" });
    }

    // Delete related data
    await Order.deleteMany({ user: user._id });
    // Removed Post.deleteMany as Post model is not required
    // await Post.deleteMany({ user: user._id }); // Removed

    // Perform a hard delete: permanently remove the user from the database
    await User.findByIdAndDelete(user._id);

    logger.info(`User account permanently deleted: ${user.email}`);

    res.status(200).json({
      success: true,
      message: "Your account has been successfully deleted.",
    });
  } catch (error) {
    logger.error("Confirm Account Deletion Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};
