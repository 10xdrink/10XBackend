// routes/userRoutes.js

const express = require("express");
const router = express.Router();
const { body, param, query } = require("express-validator");
const userController = require("../controllers/userController");
const authMiddleware = require("../middleware/authMiddleware");
const adminMiddleware = require("../middleware/adminMiddleware");
const validateMiddleware = require("../middleware/validateMiddleware");
const USER_ROLES = require("../constants/userRoles");
const uploadMiddlewares = require("../middleware/uploadMiddleware");
const {
  getAddresses,
  addAddress,
  updateAddress,
  deleteAddress,
} = require("../controllers/addressController");

// ============================
// Validation Rules
// ============================

// Validation rules for creating a new user
const createUserValidation = [
  body("name")
    .isString()
    .isLength({ min: 3 })
    .withMessage("Name must be at least 3 characters long"),
  body("email").isEmail().withMessage("Please provide a valid email"),
  body("password")
    .isStrongPassword()
    .withMessage(
      "Password must contain at least 8 characters, including one uppercase letter, one number, and one special character"
    ),
  body("role")
    .optional()
    .isIn(Object.values(USER_ROLES))
    .withMessage("Invalid user role"),
];

// Validation rules for updating an existing user
const updateUserValidation = [
  body("name")
    .optional()
    .isString()
    .isLength({ min: 3 })
    .withMessage("Name must be at least 3 characters long"),
  body("email")
    .optional()
    .isEmail()
    .withMessage("Please provide a valid email"),
  body("role")
    .optional()
    .isIn(Object.values(USER_ROLES))
    .withMessage("Invalid user role"),
  body("isActive")
    .optional()
    .isBoolean()
    .withMessage("isActive must be a boolean"),
];

// Validation rules for resetting user password
const resetPasswordValidation = [
  body("password")
    .isStrongPassword()
    .withMessage(
      "Password must contain at least 8 characters, including one uppercase letter, one number, and one special character"
    ),
];

// ============================
// Invitation Routes
// ============================

/**
 * @route   POST /api/users/admin/users/invite
 * @desc    Send an invitation to a new user
 * @access  Private/Admin
 */
router.post(
  "/admin/users/invite",
  authMiddleware,
  adminMiddleware([
    USER_ROLES.SUPER_ADMIN,
    USER_ROLES.MARKETING_MANAGER,
    USER_ROLES.PRODUCT_MANAGER,
  ]),
  [
    body("email").isEmail().withMessage("Please provide a valid email"),
    body("role")
      .isIn(Object.values(USER_ROLES))
      .withMessage("Invalid user role"),
  ],
  validateMiddleware,
  userController.inviteUser
);

/**
 * @route   POST /api/users/signup
 * @desc    Signup via invitation token
 * @access  Public
 */
router.post(
  "/signup",
  [
    body("token").notEmpty().withMessage("Token is required"),
    body("name")
      .isString()
      .isLength({ min: 2 })
      .withMessage("Name must be at least 2 characters"),
    body("password")
      .isStrongPassword()
      .withMessage(
        "Password must be at least 8 characters and include uppercase letters, numbers, and special characters"
      ),
    body("confirmPassword")
      .custom((value, { req }) => value === req.body.password)
      .withMessage("Passwords must match"),
  ],
  validateMiddleware,
  userController.signupViaInvite
);

// ============================
// Count Routes
// ============================

/**
 * @route   GET /api/users/admin/users/count
 * @desc    Get total number of users
 * @access  Private/Admin
 */
router.get(
  "/admin/users/count",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  userController.getUserCount
);

/**
 * @route   GET /api/users/admin/users/count-by-role
 * @desc    Get a count of users grouped by role
 * @access  Private/Admin
 */
router.get(
  "/admin/users/count-by-role",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  userController.countUsersByRole
);

/**
 * @route   GET /api/users/admin/users/count-new
 * @desc    Get count of new users
 * @access  Private/Admin
 */
router.get(
  "/admin/users/count-new",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  [
    query("days")
      .optional()
      .isInt({ min: 1 })
      .withMessage("Days must be a positive integer"),
  ],
  validateMiddleware,
  userController.countNewUsers
);

/**
 * @route   GET /api/users/admin/users/count-returning
 * @desc    Get count of returning users
 * @access  Private/Admin
 */
router.get(
  "/admin/users/count-returning",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  // No additional validation required as per current controller logic
  validateMiddleware,
  userController.countReturningUsers
);

// ============================
// Export Route
// ============================

/**
 * @route   GET /api/users/admin/users/export
 * @desc    Export user data in CSV format
 * @access  Private/Admin
 */
router.get(
  "/admin/users/export",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  userController.exportUsers
);

// ============================
// Search Route
// ============================

/**
 * @route   GET /api/users/admin/users/search
 * @desc    Search or filter users by name, email, role, or other criteria.
 * @access  Private/Admin
 */
router.get(
  "/admin/users/search",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  [
    // Optional query parameters
    query("name").optional().isString().withMessage("Name must be a string"),
    query("email").optional().isEmail().withMessage("Invalid email format"),
    query("role")
      .optional()
      .isIn(Object.values(USER_ROLES))
      .withMessage("Invalid role"),
    query("createdFrom")
      .optional()
      .isISO8601()
      .toDate()
      .withMessage("Invalid date format for createdFrom"),
    query("createdTo")
      .optional()
      .isISO8601()
      .toDate()
      .withMessage("Invalid date format for createdTo"),
    query("page")
      .optional()
      .isInt({ min: 1 })
      .withMessage("Page must be a positive integer"),
    query("limit")
      .optional()
      .isInt({ min: 1 })
      .withMessage("Limit must be a positive integer"),
  ],
  validateMiddleware,
  userController.searchUsers
);

// ============================
// Parameterized Routes
// ============================

/**
 * @route   POST /api/users/admin/users
 * @desc    Create a new user
 * @access  Private/Admin
 */
router.post(
  "/admin/users",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  ...uploadMiddlewares, // Spread the array to apply both upload and error handling middleware
  createUserValidation,
  validateMiddleware,
  userController.createUser
);

/**
 * @route   GET /api/users/admin/users
 * @desc    Get all users
 * @access  Private/Admin
 */
router.get(
  "/admin/users",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  validateMiddleware,
  userController.getAllUsers
);

/**
 * @route   GET /api/users/admin/users/:id
 * @desc    Get user by ID
 * @access  Private/Admin
 */
router.get(
  "/admin/users/:id",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  param("id").isMongoId().withMessage("Invalid user ID"),
  validateMiddleware,
  userController.getUserById
);

/**
 * @route   PUT /api/users/admin/users/:id
 * @desc    Update user by ID
 * @access  Private/Admin
 */
router.put(
  "/admin/users/:id",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  ...uploadMiddlewares, // Spread the array to apply both upload and error handling middleware
  [
    param("id").isMongoId().withMessage("Invalid user ID"),
    ...updateUserValidation,
  ],
  validateMiddleware,
  userController.updateUser
);

/**
 * @route   DELETE /api/users/admin/users/:id
 * @desc    Delete or deactivate user
 * @access  Private/Admin (Super Admin only)
 */
router.delete(
  "/admin/users/:id",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  param("id").isMongoId().withMessage("Invalid user ID"),
  validateMiddleware,
  userController.deleteUser
);

/**
 * @route   POST /api/users/admin/users/:id/reset-password
 * @desc    Admin-initiated password reset
 * @access  Private/Admin (Super Admin only)
 */
router.post(
  "/admin/users/:id/reset-password",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN]),
  [
    param("id").isMongoId().withMessage("Invalid user ID"),
    ...resetPasswordValidation,
  ],
  validateMiddleware,
  userController.resetUserPassword
);

/**
 * @route   PATCH /api/users/admin/users/:id/status
 * @desc    Change a user's active status
 * @access  Private/Admin
 */
router.patch(
  "/admin/users/:id/status",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  [
    param("id").isMongoId().withMessage("Invalid user ID"),
    body("isActive")
      .isBoolean()
      .withMessage("isActive must be a boolean value"),
  ],
  validateMiddleware,
  userController.changeUserStatus
);

/**
 * @route   POST /api/users/admin/users/bulk-update
 * @desc    Perform bulk updates on multiple users
 * @access  Private/Admin
 */
router.post(
  "/admin/users/bulk-update",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  [
    // Validate userIds
    body("userIds")
      .isArray({ min: 1 })
      .withMessage("userIds must be a non-empty array"),
    body("userIds.*")
      .isMongoId()
      .withMessage("Each user ID must be a valid MongoDB ID"),

    // Validate actions
    body("actions")
      .isArray({ min: 1 })
      .withMessage("actions must be a non-empty array"),
    body("actions.*.action")
      .isIn(['changeRole', 'changeStatus', 'deleteUsers'])
      .withMessage("Invalid action type"),
    body("actions.*.data").optional().isObject().withMessage("Data must be an object"),

    // Conditional validations based on action type
    body("actions.*.data.role")
      .if(body("actions.*.action").equals("changeRole"))
      .isIn(Object.values(USER_ROLES))
      .withMessage("Invalid role"),
    body("actions.*.data.isActive")
      .if(body("actions.*.action").equals("changeStatus"))
      .isBoolean()
      .withMessage("isActive must be a boolean"),
  ],
  validateMiddleware,
  userController.bulkUpdateUsers
);

// ============================
// Addresses Routes
// ============================

// Route: /api/users/addresses
router
  .route("/addresses")
  .get(authMiddleware, getAddresses)
  .post(authMiddleware, addAddress);

// Route: /api/users/addresses/:id
router
  .route("/addresses/:id")
  .put(authMiddleware, updateAddress)
  .delete(authMiddleware, deleteAddress);

/**
 * @route   GET /api/users/admin/users/:id/activity
 * @desc    Fetch recent login activity for a specific user
 * @access  Private/Admin
 */
router.get(
  "/admin/users/:id/activity",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  [param("id").isMongoId().withMessage("Invalid user ID")],
  validateMiddleware,
  userController.getUserActivity
);

/**
 * @route   GET /api/users/admin/users/:id/metrics
 * @desc    Get metrics for a specific user
 * @access  Private/Admin
 */
router.get(
  "/admin/users/:id/metrics",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  [
    param("id").isMongoId().withMessage("Invalid user ID"),
  ],
  validateMiddleware,
  userController.getUserMetrics
);


/**
 * @route   GET /api/users/admin/users/:id/audit
 * @desc    Fetch a user's audit logs
 * @access  Private/Admin
 */
router.get(
  "/admin/users/:id/audit",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.MARKETING_MANAGER]),
  [param("id").isMongoId().withMessage("Invalid user ID")],
  validateMiddleware,
  userController.getUserAuditLogs
);

// Export the router
module.exports = router;
