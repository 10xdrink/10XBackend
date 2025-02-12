// routes/productRoutes.js

const express = require("express");
const router = express.Router();
const { body, param, query } = require("express-validator");
const productController = require("../controllers/productController");
const authMiddleware = require("../middleware/authMiddleware");
const adminMiddleware = require("../middleware/adminMiddleware");
const validateMiddleware = require("../middleware/validateMiddleware");
const USER_ROLES = require("../constants/userRoles");

// Import the product image upload middleware
const uploadProductImageMiddleware = require('../middleware/uploadProductImageMiddleware');

// Validation rules for creating a product
const createProductValidation = [
  body("title")
    .isString()
    .isLength({ min: 3 })
    .withMessage("Title must be at least 3 characters long"),
  body("price")
    .isFloat({ gt: 0 })
    .withMessage("Price must be a positive number"),
  body("stock")
    .isInt({ min: 0 })
    .withMessage("Stock must be a non-negative integer"),
  body("description")
    .optional()
    .isString()
    .isLength({ max: 1000 })
    .withMessage("Description is too long"),
  body("category")
    .isString()
    .isLength({ min: 1 })
    .withMessage("Category is required and must be a string"),
  body("tags").optional().isArray().withMessage("Tags must be an array of IDs"),
  body("discountPercentage")
    .isFloat({ min: 0, max: 100 })
    .withMessage("Discount percentage must be between 0 and 100"),
  body("brand")
    .isString()
    .isLength({ min: 1 })
    .withMessage("Brand is required and must be a string"),
  body("accordion").isObject().withMessage("Accordion must be an object"),
  body("accordion.details").isString().withMessage("Details must be a string"),
  body("accordion.shipping")
    .isString()
    .withMessage("Shipping must be a string"),
  body("accordion.returns").isString().withMessage("Returns must be a string"),
];

// Validation rules for getting all products with filters
const getAllProductsValidation = [
  query("category")
    .optional()
    .isString()
    .isLength({ min: 1 })
    .withMessage("Category must be a string"),
  query("tags")
    .optional()
    .isString()
    .withMessage("Tags must be a comma-separated string of IDs"),
  query("variants")
    .optional()
    .isString()
    .withMessage("Variants must be a comma-separated string of sizes"),
  query("packaging")
    .optional()
    .isString()
    .withMessage("Packaging must be a string"),
  query("priceMin")
    .optional()
    .isFloat({ gt: 0 })
    .withMessage("priceMin must be a positive number"),
  query("priceMax")
    .optional()
    .isFloat({ gt: 0 })
    .withMessage("priceMax must be a positive number"),
  query("inStock")
    .optional()
    .isBoolean()
    .withMessage("inStock must be a boolean"),
  query("page")
    .optional()
    .isInt({ min: 1 })
    .withMessage("page must be at least 1"),
  query("limit")
    .optional()
    .isInt({ min: 1 })
    .withMessage("limit must be at least 1"),
  validateMiddleware,
];

// Validation rules for updating a product
const updateProductValidation = [
  body("title")
    .optional()
    .isString()
    .isLength({ min: 3 })
    .withMessage("Title must be at least 3 characters long"),
  body("price")
    .optional()
    .isFloat({ gt: 0 })
    .withMessage("Price must be a positive number"),
  body("stock")
    .optional()
    .isInt({ min: 0 })
    .withMessage("Stock must be a non-negative integer"),
  body("description")
    .optional()
    .isString()
    .isLength({ max: 1000 })
    .withMessage("Description is too long"),
  body("category")
    .optional()
    .isString()
    .isLength({ min: 1 })
    .withMessage("Category must be a string"),
  body("tags").optional().isArray().withMessage("Tags must be an array of IDs"),
  body("discountPercentage")
    .optional()
    .isFloat({ min: 0, max: 100 })
    .withMessage("Discount percentage must be between 0 and 100"),
  body("brand")
    .optional()
    .isString()
    .isLength({ min: 1 })
    .withMessage("Brand must be a string"),
  body("accordion")
    .optional()
    .isObject()
    .withMessage("Accordion must be an object"),
  body("accordion.details")
    .optional()
    .isString()
    .withMessage("Details must be a string"),
  body("accordion.shipping")
    .optional()
    .isString()
    .withMessage("Shipping must be a string"),
  body("accordion.returns")
    .optional()
    .isString()
    .withMessage("Returns must be a string"),
];

// Validation rules for bulk updating products
const bulkUpdateValidation = [
  body("updates").isArray().withMessage("Updates must be an array"),
  body("updates.*.id").isMongoId().withMessage("Invalid product ID"),
  body("updates.*.fields").isObject().withMessage("Fields must be an object"),
  // Optional: Add validations for fields being updated, including accordion
  body("updates.*.fields.title")
    .optional()
    .isString()
    .isLength({ min: 3 })
    .withMessage("Title must be at least 3 characters long"),
  body("updates.*.fields.price")
    .optional()
    .isFloat({ gt: 0 })
    .withMessage("Price must be a positive number"),
  body("updates.*.fields.stock")
    .optional()
    .isInt({ min: 0 })
    .withMessage("Stock must be a non-negative integer"),
  body("updates.*.fields.description")
    .optional()
    .isString()
    .isLength({ max: 1000 })
    .withMessage("Description is too long"),
  body("updates.*.fields.category")
    .optional()
    .isString()
    .isLength({ min: 1 })
    .withMessage("Category must be a string"),
  body("updates.*.fields.tags")
    .optional()
    .isArray()
    .withMessage("Tags must be an array of IDs"),
  body("updates.*.fields.discountPercentage")
    .optional()
    .isFloat({ min: 0, max: 100 })
    .withMessage("Discount percentage must be between 0 and 100"),
  body("updates.*.fields.brand")
    .optional()
    .isString()
    .isLength({ min: 1 })
    .withMessage("Brand must be a string"),
  body("updates.*.fields.accordion")
    .optional()
    .isObject()
    .withMessage("Accordion must be an object"),
  body("updates.*.fields.accordion.details")
    .optional()
    .isString()
    .withMessage("Details must be a string"),
  body("updates.*.fields.accordion.shipping")
    .optional()
    .isString()
    .withMessage("Shipping must be a string"),
  body("updates.*.fields.accordion.returns")
    .optional()
    .isString()
    .withMessage("Returns must be a string"),
];

// Validation rules for updating product stock
const stockUpdateValidation = [
  body("stock")
    .isInt({ min: 0 })
    .withMessage("Stock must be a non-negative integer"),
];

// Routes

// Create a new product
router.post(
  "/",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.PRODUCT_MANAGER]),
  createProductValidation,
  validateMiddleware,
  productController.createProduct
);

// Get all products with filtering and pagination
router.get("/", getAllProductsValidation, productController.getAllProducts);

// Search products
router.get('/search', productController.searchProducts);

// Get a single product by slug
router.get("/slug/:slug", productController.getProductBySlug);

// Get a single product by ID
router.get(
  "/:id",
  [
    param("id").isMongoId().withMessage("Invalid product ID"),
    validateMiddleware,
  ],
  productController.getProductById
);

// Update a product by ID
router.put(
  "/:id",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.PRODUCT_MANAGER]),
  [
    param("id").isMongoId().withMessage("Invalid product ID"),
    updateProductValidation,
    validateMiddleware,
  ],
  productController.updateProduct
);

// Delete (deactivate) a product by ID
router.delete(
  "/:id",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.PRODUCT_MANAGER]),
  [
    param("id").isMongoId().withMessage("Invalid product ID"),
    validateMiddleware,
  ],
  productController.deleteProduct
);

// Update product stock level
router.put(
  "/:id/stock",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.PRODUCT_MANAGER]),
  [
    param("id").isMongoId().withMessage("Invalid product ID"),
    stockUpdateValidation,
    validateMiddleware,
  ],
  productController.updateProductStock
);

// Bulk update products
router.post(
  "/bulk-update",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.PRODUCT_MANAGER]),
  bulkUpdateValidation,
  validateMiddleware,
  productController.bulkUpdateProducts
);

// Upload product image with product image upload middleware
router.post(
  "/upload-image",
  authMiddleware,
  adminMiddleware([USER_ROLES.SUPER_ADMIN, USER_ROLES.PRODUCT_MANAGER]),
  uploadProductImageMiddleware, // Apply the product image upload middleware
  productController.uploadProductImage
);

module.exports = router;
