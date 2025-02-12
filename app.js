// Load environment variables from .env
require("dotenv").config();

const express = require("express");
const path = require("path");
const helmet = require("helmet");
const morgan = require("morgan");
const cors = require("cors");
const session = require("express-session");
const RedisStore = require("connect-redis").default;
const passport = require("passport");
const redisClient = require("./config/redis");
const logger = require("./utils/logger");
const { uploadImage } = require("./services/cloudinaryService");
const multer = require("multer");
const rateLimit = require("express-rate-limit");
require("express-async-errors"); // Patches Express to handle async errors

// Middleware and route imports
const errorMiddleware = require("./middleware/errorMiddleware");
const authRoutes = require("./routes/authRoutes");
const userRoutes = require("./routes/userRoutes");
const productRoutes = require("./routes/productRoutes");
const orderRoutes = require("./routes/orderRoutes");
const blogRoutes = require("./routes/blogRoutes");
const faqRoutes = require("./routes/faqRoutes");
const webhookRoutes = require("./routes/webhookRoutes");
const categoryRoutes = require("./routes/categoryRoutes");
const reviewRoutes = require("./routes/reviewRoutes");
const couponRoutes = require("./routes/couponRoutes");
const settingsRoutes = require("./routes/settingsRoutes");
const reportRoutes = require("./routes/reportRoutes");
const contactRoutes = require("./routes/contactRoutes");
const cartRoutes = require("./routes/cartRoutes");
const emailListRoutes = require("./routes/emailListRoutes");
const chatbotRoutes = require("./routes/chatbotRoutes");
const tagRoutes = require("./routes/tagRoutes");
const validateConfig = require("./utils/validateConfig");
const setupGoogleStrategy = require("./services/googleOAuthService");

// Destructure body parser methods from express
const { json, urlencoded } = express;

// Validate Configuration (ensures required env vars are set)
validateConfig();

// Determine the port (used in allowedOrigins)
const port = process.env.PORT || 5000;

// Initialize Express App
const app = express();

// --- Security & Utility Middlewares ---

// Use Helmet with a custom Content Security Policy (CSP)
// Allow external styles from cdnjs and Google Fonts.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        // Allow inline styles, cdnjs, and Google Fonts for styles
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://cdnjs.cloudflare.com",
          "https://fonts.googleapis.com"
        ],
        imgSrc: ["'self'", "data:", "https://res.cloudinary.com"],
        connectSrc: ["'self'"],
      },
    },
  })
);

// CORS Middleware
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map((origin) => origin.trim())
  : [
      process.env.FRONTEND_URL,
      process.env.ADMIN_URL,
      `http://localhost:${port}`,
    ];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || origin === "null" || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

// Body Parsing Middleware
app.use(json());
app.use(urlencoded({ extended: true }));

// Rate Limiting Middleware for API routes
const apiLimiter = rateLimit({
  windowMs: process.env.RATE_LIMIT_WINDOW_MS
    ? parseInt(process.env.RATE_LIMIT_WINDOW_MS)
    : 15 * 60 * 1000,
  max: process.env.RATE_LIMIT_MAX
    ? parseInt(process.env.RATE_LIMIT_MAX)
    : 100,
  message: "Too many requests from this IP, please try again later.",
  headers: true,
});
app.use("/api/", apiLimiter);

// Logging Middleware using Morgan
app.use(morgan("combined", { stream: logger.stream }));

// Serve static files from the "public" directory
app.use(
  express.static(path.join(__dirname, "public"), {
    maxAge: "1d",
    etag: false,
  })
);

// --- Session, Passport & Redis Setup ---

const redisStore = new RedisStore({
  client: redisClient,
  prefix: "session:",
});

app.use(
  session({
    store: redisStore,
    secret: process.env.SESSION_SECRET || process.env.JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());
setupGoogleStrategy();

// --- File Upload and Cloudinary Configuration ---

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

logger.info(
  `Cloudinary configured with Cloud Name: ${process.env.CLOUDINARY_CLOUD_NAME}`
);

app.post("/api/upload", upload.single("image"), async (req, res, next) => {
  try {
    if (!req.file) {
      return res
        .status(400)
        .json({ success: false, message: "No file uploaded." });
    }
    const result = await uploadImage(req.file.path);
    res.status(200).json({ success: true, url: result.secure_url });
  } catch (error) {
    next(error);
  }
});

// --- API Routes ---
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/products", productRoutes);
app.use("/api/orders", orderRoutes);
app.use("/api/blogs", blogRoutes);
app.use("/api/faqs", faqRoutes);
app.use("/api/reviews", reviewRoutes);
app.use("/api/coupons", couponRoutes);
app.use("/api/settings", settingsRoutes);
app.use("/api/webhooks", webhookRoutes);
app.use("/api/categories", categoryRoutes);
app.use("/api/reports", reportRoutes);
app.use("/api/contact", contactRoutes);
app.use("/api/cart", cartRoutes);
app.use("/api/email-list", emailListRoutes);
app.use("/api/chatbot", chatbotRoutes);
app.use("/api/tags", tagRoutes);

// --- Static Files for Frontend and Admin ---
const frontendPath = path.join(__dirname, "../Frontend/react/dist");
const adminPath = path.join(__dirname, "../Admin/dist");

app.use(express.static(frontendPath, { extensions: ["html", "css", "js"] }));
app.use("/10x-login", express.static(adminPath, { extensions: ["html", "css", "js"] }));

// --- Other Routes ---
app.get("/server-running", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "ServerRunning.html"));
});

app.get("/api/health", (req, res) => {
  logger.info("Health check passed");
  res.status(200).json({ success: true, message: "API is healthy." });
});

// --- Catch-All Route for React Router Support ---
app.get("*", (req, res) => {
  if (req.originalUrl.startsWith("/admin")) {
    res.sendFile(path.join(adminPath, "index.html"));
  } else {
    res.sendFile(path.join(frontendPath, "index.html"));
  }
});

// --- 404 & Error Handlers ---
app.use((req, res, next) => {
  res.status(404).json({ success: false, message: "Resource not found" });
});

app.use(errorMiddleware);

// --- Redis Event Listeners ---
redisClient.on("connect", () => {
  logger.info("Connected to Redis successfully");
});
redisClient.on("error", (err) => {
  logger.error(`Redis connection error: ${err.message}`);
});

module.exports = app;
