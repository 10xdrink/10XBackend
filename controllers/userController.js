// controllers/userController.js

const User = require("../models/User");
const AuditLog = require("../models/AuditLog"); // Ensure AuditLog model is imported
const Invite = require("../models/Invite"); // Import Invite model for invitation functionality
const cloudinary = require("../config/cloudinary"); // Import Cloudinary configuration
const bcrypt = require("bcryptjs");
const logger = require("../utils/logger");
const ERROR_CODES = require("../constants/errorCodes");
const { createObjectCsvStringifier } = require("csv-writer");
const jwt = require("jsonwebtoken");
const { generateToken } = require("../utils/generateToken"); // Token generator utility
const { sendInvitationEmail } = require("../services/emailService"); // Email service utility
const ProductPurchase = require('../models/ProductPurchase');
// Define allowed actions for AuditLog
const ALLOWED_AUDIT_ACTIONS = ["CREATE", "UPDATE", "DELETE", "RESTORE"];

/**
 * @desc    Get all users with optional filters
 * @route   GET /api/users/admin/users
 * @access  Private/Admin
 */
exports.getAllUsers = async (req, res) => {
  try {
    const { role, isActive, page = 1, limit = 20 } = req.query;
    let query = {};

    if (role) {
      query.role = role;
    }

    if (isActive !== undefined) {
      query.isActive = isActive === "true";
    }

    const users = await User.find(query)
      .select("-password") // Exclude password field
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    const totalUsers = await User.countDocuments(query);
    const totalPages = Math.ceil(totalUsers / limit);

    res.status(200).json({
      success: true,
      count: users.length,
      totalPages,
      currentPage: parseInt(page),
      data: users,
    });
  } catch (error) {
    logger.error("Get All Users Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Invite a new user by email and role
 * @route   POST /api/users/admin/users/invite
 * @access  Private/Admin
 */
exports.inviteUser = async (req, res) => {
  try {
    const { email, role } = req.body;

    // Check if a user already exists with this email
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({
          success: false,
          message: "A user with this email already exists.",
        });
    }

    // Check if an invite already exists for this email and is not used
    let existingInvite = await Invite.findOne({ email, isUsed: false });
    if (existingInvite) {
      return res
        .status(400)
        .json({
          success: false,
          message: "An active invitation already exists for this email.",
        });
    }

    // Generate a unique token
    const token = generateToken({ email, role }, "24h"); // Token valid for 24 hours

    // Create an invite
    const invite = await Invite.create({
      email,
      role,
      token,
      expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
    });

    // Send invitation email
    const subject = "You are invited to join Our App";
    const message = `Hello,

You have been invited to join Our App with the role of ${role.replace(
      /_/g,
      " "
    )}.

Please click the link below to set up your account:

${process.env.FRONTEND_URL}/signup?token=${token}

This link will expire in 24 hours.

If you did not expect this invitation, you can ignore this email.

Best regards,
The Team`;

    const html = `
      <p>Hello,</p>
      <p>You have been invited to join <strong>Our App</strong> with the role of <strong>${role.replace(
        /_/g,
        " "
      )}</strong>.</p>
      <p>Please click the link below to set up your account:</p>
      <a href="${
        process.env.FRONTEND_URL
      }/signup?token=${token}">Set Up Your Account</a>
      <p>This link will expire in 24 hours.</p>
      <p>If you did not expect this invitation, you can ignore this email.</p>
      <p>Best regards,<br/>The Team</p>
    `;

    await sendInvitationEmail(email, token, role, subject, message, html);

    // Log the invitation action in AuditLog
    await AuditLog.create({
      performedBy: req.user._id, // ID of the admin performing the action
      entityId: invite._id, // ID of the invite
      entity: "Invite", // Type of entity
      action: "CREATE", // Action performed
      details: `Invited user with email: ${email} and role: ${role}.`,
    });

    res
      .status(200)
      .json({ success: true, message: "Invitation sent successfully." });
  } catch (error) {
    logger.error("Invite User Error:", error);
    res
      .status(500)
      .json({
        success: false,
        message: "Error sending invitation",
        error: error.message,
      });
  }
};

/**
 * @desc    Signup a user via invitation token
 * @route   POST /api/users/signup
 * @access  Public
 */
exports.signupViaInvite = async (req, res) => {
  try {
    const { token, name, password, confirmPassword } = req.body;

    // Verify the token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired token." });
    }

    const { email, role } = decoded;

    // Check if the invite exists and is not used
    const invite = await Invite.findOne({ email, token, isUsed: false });
    if (!invite) {
      return res
        .status(400)
        .json({
          success: false,
          message: "Invalid or already used invitation token.",
        });
    }

    // Check if user already exists
    let existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({
          success: false,
          message: "A user with this email already exists.",
        });
    }

    // Validate password and confirmPassword
    if (password !== confirmPassword) {
      return res
        .status(400)
        .json({ success: false, message: "Passwords do not match." });
    }

    // Create the user
    const user = await User.create({
      name,
      email,
      password,
      role,
    });

    // Mark the invite as used
    invite.isUsed = true;
    await invite.save();

    // Optionally, generate a JWT token for the user to log in immediately
    const userToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.status(201).json({
      success: true,
      message: "Account created successfully.",
      token: userToken,
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    logger.error("Signup Via Invite Error:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
};

/**
 * @desc    Get a single user by ID
 * @route   GET /api/users/admin/users/:id
 * @access  Private/Admin
 */
exports.getUserById = async (req, res) => {
  try {
    const userId = req.params.id;

    const user = await User.findById(userId).select("-password");

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    res.status(200).json({
      success: true,
      data: user,
    });
  } catch (error) {
    logger.error("Get User By ID Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Create a new user
 * @route   POST /api/users/admin/users
 * @access  Private/Admin/Super Admin/Marketing Manager
 */
exports.createUser = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res
        .status(400)
        .json({ success: false, message: "User already exists" });
    }

    // Create new user instance
    user = new User({ name, email, password, role });

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
              if (error) return reject(error);
              resolve(result);
            }
          );
          stream.end(req.file.buffer);
        });

        // Update user's profile picture URL
        user.profilePicture = uploadResult.secure_url;
      } catch (uploadError) {
        logger.error("Profile Picture Upload Error:", uploadError);
        return res
          .status(500)
          .json({
            success: false,
            message: "Failed to upload profile picture",
          });
      }
    }

    await user.save();

    // Log the creation in AuditLog
    await AuditLog.create({
      performedBy: req.user._id, // ID of the admin performing the action
      entityId: user._id, // ID of the user being created
      entity: "User", // Type of entity
      action: "CREATE", // Action performed
      details: `Created user with email: ${user.email} and role: ${user.role}.`,
    });

    res.status(201).json({
      success: true,
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        profilePicture: user.profilePicture,
        isActive: user.isActive,
      }, // Exclude password
    });
  } catch (error) {
    logger.error("Create User Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Update a user by ID
 * @route   PUT /api/users/admin/users/:id
 * @access  Private/Admin/Super Admin/Marketing Manager
 */
exports.updateUser = async (req, res) => {
  try {
    const { name, email, role, isActive } = req.body;
    const userId = req.params.id;

    // Fetch the user by ID
    const user = await User.findById(userId);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Update fields if provided
    if (name) user.name = name;
    if (email) user.email = email;
    if (role) user.role = role;
    if (typeof isActive !== "undefined") user.isActive = isActive;

    // Handle profile picture upload if provided
    if (req.file) {
      try {
        const uploadResult = await new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: "user_profiles" },
            (error, result) => {
              if (error) return reject(error);
              resolve(result);
            }
          );
          stream.end(req.file.buffer);
        });

        // Update user's profile picture URL
        user.profilePicture = uploadResult.secure_url;
      } catch (uploadError) {
        logger.error("Profile Picture Upload Error:", uploadError);
        return res
          .status(500)
          .json({
            success: false,
            message: "Failed to upload profile picture",
          });
      }
    }

    await user.save();

    // Log the update in AuditLog
    await AuditLog.create({
      performedBy: req.user._id, // ID of the admin performing the action
      entityId: user._id, // ID of the user being updated
      entity: "User", // Type of entity
      action: "UPDATE", // Action performed
      details: `Updated user with email: ${user.email}.`,
    });

    res.status(200).json({
      success: true,
      data: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        profilePicture: user.profilePicture,
        isActive: user.isActive,
      }, // Exclude password
    });
  } catch (error) {
    logger.error("Update User Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Delete a user by ID
 * @route   DELETE /api/users/admin/users/:id
 * @access  Private/Admin (Super Admin only)
 */
exports.deleteUser = async (req, res) => {
  try {
    const userId = req.params.id;

    // Attempt to delete the user from the database
    const user = await User.findByIdAndDelete(userId);

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Log the deletion in AuditLog
    await AuditLog.create({
      performedBy: req.user._id, // ID of the admin performing the action
      entityId: user._id, // ID of the user being deleted
      entity: "User", // Type of entity
      action: "DELETE", // Action performed
      details: `Deleted user with email: ${user.email}.`,
    });

    res.status(200).json({
      success: true,
      message: "User deleted successfully",
    });
  } catch (error) {
    logger.error("Delete User Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Admin-initiated password reset for a user
 * @route   POST /api/users/admin/users/:id/reset-password
 * @access  Private/Admin (Super Admin only)
 */
exports.resetUserPassword = async (req, res) => {
  try {
    const { password } = req.body;
    const userId = req.params.id;

    let user = await User.findById(userId).select("+password");

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(password, salt);

    await user.save();

    // Log the password reset in AuditLog
    await AuditLog.create({
      performedBy: req.user._id, // ID of the admin performing the action
      entityId: user._id, // ID of the user whose password is reset
      entity: "User", // Type of entity
      action: "UPDATE", // Action performed
      details: `Reset password for user with email: ${user.email}.`,
    });

    res.status(200).json({
      success: true,
      message: "User password reset successfully",
    });
  } catch (error) {
    logger.error("Reset User Password Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Search or filter users based on query parameters
 * @route   GET /api/users/admin/users/search
 * @access  Private/Admin
 */
exports.searchUsers = async (req, res) => {
  try {
    const {
      name,
      email,
      role,
      createdFrom,
      createdTo,
      page = 1,
      limit = 20,
    } = req.query;
    const filter = {};

    if (name) {
      filter.name = { $regex: name, $options: "i" }; // Case-insensitive search
    }

    if (email) {
      filter.email = { $regex: email, $options: "i" };
    }

    if (role) {
      filter.role = role;
    }

    if (createdFrom || createdTo) {
      filter.createdAt = {};
      if (createdFrom) {
        filter.createdAt.$gte = new Date(createdFrom);
      }
      if (createdTo) {
        filter.createdAt.$lte = new Date(createdTo);
      }
    }

    const users = await User.find(filter)
      .select("-password") // Exclude password
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    const totalUsers = await User.countDocuments(filter);
    const totalPages = Math.ceil(totalUsers / limit);

    res.status(200).json({
      success: true,
      count: users.length,
      totalPages,
      currentPage: parseInt(page),
      data: users,
    });
  } catch (error) {
    logger.error("Search Users Error:", error);
    res
      .status(500)
      .json({ success: false, message: "Server Error", error: error.message });
  }
};

/**
 * @desc    Export users in specified format (CSV/Excel)
 * @route   GET /api/users/admin/users/export
 * @access  Private/Admin
 */
exports.exportUsers = async (req, res) => {
  try {
    const format = req.query.format || "csv";
    const users = await User.find({})
      .select(
        "-password -resetPasswordToken -resetPasswordExpire -deletionToken -deletionTokenExpire"
      )
      .lean();

    if (format === "csv") {
      const csvStringifier = createObjectCsvStringifier({
        header: [
          { id: "_id", title: "ID" },
          { id: "name", title: "Name" },
          { id: "email", title: "Email" },
          { id: "role", title: "Role" },
          { id: "isActive", title: "Active" },
          { id: "createdAt", title: "Created At" },
          { id: "updatedAt", title: "Updated At" },
        ],
      });

      const header = csvStringifier.getHeaderString();
      const records = csvStringifier.stringifyRecords(users);

      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", "attachment; filename=users.csv");
      res.status(200).send(Buffer.from(header + records));
    } else if (format === "excel") {
      // Implement Excel export if needed using a library like exceljs
      return res
        .status(400)
        .json({ success: false, message: "Unsupported export format" });
    } else {
      return res
        .status(400)
        .json({ success: false, message: "Invalid export format" });
    }
  } catch (error) {
    logger.error("Export Users Error:", error);
    res
      .status(500)
      .json({
        success: false,
        message: "Error exporting users",
        error: error.message,
      });
  }
};

/**
 * @desc    Change a user's active status
 * @route   PATCH /api/users/admin/users/:id/status
 * @access  Private/Admin
 */
exports.changeUserStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { isActive } = req.body;

    const user = await User.findByIdAndUpdate(
      id,
      { isActive },
      { new: true, runValidators: true }
    ).select("-password");

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Log the action in AuditLog
    await AuditLog.create({
      performedBy: req.user._id, // ID of the admin performing the action
      entityId: user._id, // ID of the user whose status is changed
      entity: "User", // Type of entity
      action: isActive ? "RESTORE" : "DELETE", // 'RESTORE' for activation, 'DELETE' for deactivation
      details: `User ${user.email} has been ${
        isActive ? "activated" : "deactivated"
      }.`,
    });

    res.status(200).json({ success: true, user });
  } catch (error) {
    logger.error("Change User Status Error:", error);
    res
      .status(500)
      .json({
        success: false,
        message: "Error updating user status",
        error: error.message,
      });
  }
};

/**
 * @desc    Perform bulk updates on multiple users
 * @route   POST /api/users/admin/users/bulk-update
 * @access  Private/Admin
 */
exports.bulkUpdateUsers = async (req, res) => {
  try {
    const { userIds, actions } = req.body;

    // Debugging: Log the received payload
    console.log("Received bulkUpdateUsers payload:", req.body);

    if (!Array.isArray(userIds) || userIds.length === 0) {
      return res
        .status(400)
        .json({ success: false, message: "No user IDs provided." });
    }

    if (!Array.isArray(actions) || actions.length === 0) {
      return res
        .status(400)
        .json({ success: false, message: "No actions provided." });
    }

    // Iterate over each action and perform accordingly
    for (const actionObj of actions) {
      const { action, data } = actionObj;

      switch (action) {
        case "changeRole":
          await User.updateMany({ _id: { $in: userIds } }, { role: data.role });
          break;
        case "changeStatus":
          await User.updateMany(
            { _id: { $in: userIds } },
            { isActive: data.isActive }
          );
          break;
        case "deleteUsers":
          await User.deleteMany({ _id: { $in: userIds } });
          break;
        default:
          return res
            .status(400)
            .json({ success: false, message: `Unknown action: ${action}` });
      }
    }

    // Log the bulk action in AuditLog
    await AuditLog.create({
      performedBy: req.user._id, // ID of the admin performing the action
      entityId: null, // Since multiple entities are affected, set to null
      entity: null, // Optional: Can set to 'User' or leave as null
      action: "BULK_UPDATE", // Action performed
      details: `Bulk updated users with IDs: ${userIds.join(", ")}.`,
    });

    res.status(200).json({ success: true, message: "Bulk update successful." });
  } catch (error) {
    logger.error("Bulk Update Users Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Fetch recent login activity for a specific user
 * @route   GET /api/users/admin/users/:id/activity
 * @access  Private/Admin
 */
exports.getUserActivity = async (req, res) => {
  try {
    const { id } = req.params;

    // Fetch recent activities related to the user
    const activities = await AuditLog.find({ entityId: id, entity: "User" })
      .sort({ createdAt: -1 })
      .limit(10); // Fetch last 10 activities

    res.status(200).json({ success: true, activities });
  } catch (error) {
    logger.error("Get User Activity Error:", error);
    res
      .status(500)
      .json({
        success: false,
        message: "Error fetching user activity",
        error: error.message,
      });
  }
};

/**
 * @desc    Get a count of users grouped by role
 * @route   GET /api/users/admin/users/count-by-role
 * @access  Private/Admin
 */
exports.countUsersByRole = async (req, res) => {
  try {
    const counts = await User.aggregate([
      {
        $group: {
          _id: "$role",
          count: { $sum: 1 },
        },
      },
      {
        $project: {
          role: "$_id",
          count: 1,
          _id: 0,
        },
      },
    ]);

    res.status(200).json({ success: true, counts });
  } catch (error) {
    logger.error("Count Users By Role Error:", error);
    res
      .status(500)
      .json({
        success: false,
        message: "Error counting users by role",
        error: error.message,
      });
  }
};

/**
 * @desc    Get total number of users
 * @route   GET /api/users/admin/users/count
 * @access  Private/Admin
 */
exports.getUserCount = async (req, res) => {
  try {
    const count = await User.countDocuments({});
    res.status(200).json({
      success: true,
      totalUsers: count,
    });
  } catch (error) {
    logger.error("Get User Count Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};

/**
 * @desc    Fetch a user's audit logs
 * @route   GET /api/users/admin/users/:id/audit
 * @access  Private/Admin
 */
exports.getUserAuditLogs = async (req, res) => {
  try {
    const { id } = req.params;

    const auditLogs = await AuditLog.find({ entityId: id, entity: "User" })
      .sort({ createdAt: -1 })
      .limit(50); // Limit to last 50 actions

    res.status(200).json({ success: true, auditLogs });
  } catch (error) {
    logger.error("Get User Audit Logs Error:", error);
    res
      .status(500)
      .json({
        success: false,
        message: "Error fetching audit logs",
        error: error.message,
      });
  }
};

/**
 * @desc    Count new users
 * @route   GET /api/users/admin/users/count-new
 * @access  Private/Admin
 */
exports.countNewUsers = async (req, res) => {
  try {
    // Define the period for new users, e.g., last 30 days
    const days = req.query.days ? parseInt(req.query.days) : 30;
    if (isNaN(days) || days <= 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid 'days' parameter. It must be a positive integer.",
      });
    }

    const sinceDate = new Date();
    sinceDate.setDate(sinceDate.getDate() - days);

    const count = await User.countDocuments({ createdAt: { $gte: sinceDate } });

    res.status(200).json({ success: true, newUsers: count });
  } catch (error) {
    logger.error("Count New Users Error:", error);
    res.status(500).json({
      success: false,
      message: "Invalid input. Please ensure all fields are filled out correctly and try again.",
    });
  }
};

/**
 * @desc    Count returning users
 * @route   GET /api/users/admin/users/count-returning
 * @access  Private/Admin
 */
exports.countReturningUsers = async (req, res) => {
  try {
    // Define what constitutes a returning user
    // For example, users who have logged in at least 2 times
    const aggregation = [
      { $match: { entity: "User", action: "LOGIN" } },
      { $group: { _id: "$entityId", loginCount: { $sum: 1 } } },
      { $match: { loginCount: { $gte: 2 } } },
      { $count: "returningUsers" },
    ];

    const result = await AuditLog.aggregate(aggregation);
    const returningUsers = result.length > 0 ? result[0].returningUsers : 0;

    res.status(200).json({ success: true, returningUsers });
  } catch (error) {
    logger.error("Count Returning Users Error:", error);
    res.status(500).json({
      success: false,
      message: "Invalid input. Please ensure all fields are filled out correctly and try again.",
    });
  }
};
/**
 * @desc    Get metrics for a specific user
 * @route   GET /api/users/admin/users/:id/metrics
 * @access  Private/Admin
 */
exports.getUserMetrics = async (req, res) => {
  try {
    const userId = req.params.id;

    // Validate if the user exists
    const user = await User.findById(userId);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Example Metrics:
    // 1. Number of products purchased
    // 2. Login frequency

    // Replace these with actual implementations based on your data models

    // Example: Count of products purchased by the user
    const productPurchasedCount = await ProductPurchase.countDocuments({ user: userId });

    // Example: Count of logins from AuditLog
    const loginFrequency = await AuditLog.countDocuments({ 
      entityId: userId, 
      entity: "User", 
      action: "LOGIN" 
    });

    // You can add more metrics as needed

    const metrics = {
      productPurchasedCount,
      loginFrequency,
      // Add other metrics here
    };

    res.status(200).json({ success: true, metrics });
  } catch (error) {
    logger.error("Get User Metrics Error:", error);
    res.status(500).json({ success: false, message: ERROR_CODES.SERVER_ERROR });
  }
};
