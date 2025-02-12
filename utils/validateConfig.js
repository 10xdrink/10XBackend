// utils/validateConfig.js
const Joi = require('joi');
const logger = require('./logger');

const configSchema = Joi.object({
  PORT: Joi.number().default(5000),
  MONGO_URI: Joi.string().uri().required(),
  REDIS_URL: Joi.string().uri().required(),
  CLOUDINARY_CLOUD_NAME: Joi.string().required(),
  CLOUDINARY_API_KEY: Joi.string().required(),
  CLOUDINARY_API_SECRET: Joi.string().required(),
  JWT_SECRET: Joi.string().min(32).required(),
  JWT_REFRESH_SECRET: Joi.string().min(32).required(),
  SENDGRID_API_KEY: Joi.string().when('EMAIL_SERVICE', { is: 'sendgrid', then: Joi.required() }),
  AWS_ACCESS_KEY_ID: Joi.string().when('EMAIL_SERVICE', { is: 'ses', then: Joi.required() }),
  AWS_SECRET_ACCESS_KEY: Joi.string().when('EMAIL_SERVICE', { is: 'ses', then: Joi.required() }),
  AWS_REGION: Joi.string().when('EMAIL_SERVICE', { is: 'ses', then: Joi.required() }),
  FROM_EMAIL: Joi.string().email().required(),
  EMAIL_SERVICE: Joi.string().valid('sendgrid', 'ses').required(),
  GOOGLE_CLIENT_ID: Joi.string().optional(),
  GOOGLE_CLIENT_SECRET: Joi.string().optional(),
  GOOGLE_CALLBACK_URL: Joi.string().uri().optional(),
  PAYMENT_METHOD: Joi.string().valid('stripe', 'paypal').required(),
  STRIPE_SECRET_KEY: Joi.string().when('PAYMENT_METHOD', { is: 'stripe', then: Joi.required() }),
  PAYPAL_MODE: Joi.string().valid('sandbox', 'live').when('PAYMENT_METHOD', { is: 'paypal', then: Joi.required() }),
  PAYPAL_CLIENT_ID: Joi.string().when('PAYMENT_METHOD', { is: 'paypal', then: Joi.required() }),
  PAYPAL_CLIENT_SECRET: Joi.string().when('PAYMENT_METHOD', { is: 'paypal', then: Joi.required() }),
  STRIPE_WEBHOOK_SECRET: Joi.string().when('PAYMENT_METHOD', { is: 'stripe', then: Joi.required() }),
}).unknown(true); // Allow other environment variables

const validateConfig = () => {
  const { error, value } = configSchema.validate(process.env, { abortEarly: false });

  if (error) {
    logger.error('Config validation error:', error.details.map(d => d.message).join(', '));
    throw new Error('Config validation error');
  }

  // Optionally, you can replace process.env with the validated values
  Object.keys(value).forEach(key => {
    process.env[key] = value[key];
  });

  logger.info('Configuration validated successfully.');
};

module.exports = validateConfig;
