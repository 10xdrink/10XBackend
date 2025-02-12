// Load environment variables from .env
require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const morgan = require('morgan');
const cors = require('cors');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const passport = require('passport');
const redisClient = require('./config/redis');
const logger = require('./utils/logger');
const { uploadImage } = require('./services/cloudinaryService');

// Middleware imports
const rateLimitMiddleware = require('./middleware/rateLimitMiddleware').rateLimitMiddleware;
const errorMiddleware = require('./middleware/errorMiddleware');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const productRoutes = require('./routes/productRoutes');
const orderRoutes = require('./routes/orderRoutes');
const blogRoutes = require('./routes/blogRoutes');
const faqRoutes = require('./routes/faqRoutes');
const webhookRoutes = require('./routes/webhookRoutes');
const categoryRoutes = require('./routes/categoryRoutes');
const reviewRoutes = require('./routes/reviewRoutes');
const couponRoutes = require('./routes/couponRoutes');
const settingsRoutes = require('./routes/settingsRoutes');
const reportRoutes = require('./routes/reportRoutes');
const contactRoutes = require('./routes/contactRoutes');
const cartRoutes = require('./routes/cartRoutes'); 
const validateConfig = require('./utils/validateConfig');
const setupGoogleStrategy = require('./services/googleOAuthService');
const emailListRoutes = require('./routes/emailListRoutes');
const chatbotRoutes = require('./routes/chatbotRoutes');
const tagRoutes = require('./routes/tagRoutes');




// Body parser setup
const { json, urlencoded } = express;

// Validate Configuration
validateConfig();

// Initialize Express App
const app = express();

// Security Middleware
app.use(helmet());

// CORS Middleware
const allowedOrigins = [
  process.env.FRONTEND_URL, // Main frontend app
  process.env.ADMIN_URL // Admin panel
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
  })
);
// Body Parsing Middleware
app.use(json());
app.use(urlencoded({ extended: true }));

// Rate Limiting Middleware
app.use(rateLimitMiddleware);

// Logging Middleware
app.use(morgan('combined', { stream: logger.stream }));

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Redis store
const redisStore = new RedisStore({
  client: redisClient,
});

redisClient.on('connect', () => {
  logger.info('Connected to Redis successfully');
});

redisClient.on('error', (err) => {
  logger.error(`Redis connection error: ${err.message}`);
});

// Initialize Passport for authentication strategies
app.use(
  session({
    store: redisStore,
    secret: process.env.JWT_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
setupGoogleStrategy();

// Cloudinary Configuration Logging
logger.info(`Cloudinary configured with Cloud Name: ${process.env.CLOUDINARY_CLOUD_NAME}`);

// Image Upload Route Example
app.post('/upload', async (req, res) => {
  try {
    const result = await uploadImage(req.file.path);
    res.status(200).json({ success: true, url: result.secure_url });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/products', productRoutes);
app.get('/api/products/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const product = await Product.findById(id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found.' });
    }
    res.status(200).json(product);
  } catch (error) {
    res.status(422).json({ message: 'Invalid product ID.' });
  }
});
app.use('/api/orders', orderRoutes);
app.use('/api/blogs', blogRoutes);
app.use('/api/faqs', faqRoutes);
app.use('/api/reviews', reviewRoutes);
app.use('/api/coupons', couponRoutes);
app.use('/api/settings', settingsRoutes);
app.use('/api/webhooks', webhookRoutes);
app.use('/api/categories', categoryRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/contact', contactRoutes);
app.use('/api/cart', cartRoutes);
app.use('/api/review', reviewRoutes);
app.use('/api/email-list', emailListRoutes);
app.use('/api/chatbot', chatbotRoutes);
app.use('/api/tags', tagRoutes);


// Serve an HTML file on the root route to indicate the server is running
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ServerRunning.html'));
});

// Health Check Route
app.get('/api/health', (req, res) => {
  res.status(200).json({ success: true, message: 'API is healthy.' });
  logger.info('Health check passed');
});

// Error Handling Middleware
app.use(errorMiddleware);

module.exports = app;
