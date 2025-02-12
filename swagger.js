// swagger.js

const swaggerJsdoc = require('swagger-jsdoc');

// Swagger definition
const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: '10X Backend Documentation',
    version: '1.0.0',
    description: 'Comprehensive API documentation for the 10X Backend.',
  },
  servers: [
    {
      url: 'http://localhost:5000', // Development server
      description: 'Development Server',
    },
    {
      url: 'https://your-production-url.com', // Production server
      description: 'Production Server',
    },
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
    schemas: {
      // Define your data models here
      User: {
        type: 'object',
        properties: {
          id: {
            type: 'string',
            description: 'Unique identifier for the user',
          },
          name: {
            type: 'string',
            description: 'Full name of the user',
          },
          email: {
            type: 'string',
            description: 'Email address of the user',
          },
          role: {
            type: 'string',
            description: 'Role assigned to the user',
            enum: [
              'super-admin',
              'product-manager',
              'order-manager',
              'content-manager',
              'customer-support-manager',
              'marketing-manager',
              'analytics-viewer',
              'admin-assistant',
              'inventory-manager',
              'seo-manager',
              'sales-manager',
              'finance-manager',
              'user',
            ],
          },
          profilePicture: {
            type: 'string',
            description: 'URL of the user’s profile picture',
          },
          isActive: {
            type: 'boolean',
            description: 'Indicates if the user account is active',
          },
        },
      },
      // Add other schemas like Product, Order, etc.
      AuditLog: {
        type: 'object',
        properties: {
          _id: {
            type: 'string',
            description: 'Unique identifier for the audit log',
          },
          action: {
            type: 'string',
            description: 'Action performed',
          },
          changedBy: {
            type: 'string',
            description: 'User ID who performed the action',
          },
          createdAt: {
            type: 'string',
            format: 'date-time',
            description: 'Timestamp when the action was performed',
          },
        },
      },
      // Continue adding other schemas as needed
    },
  },
  security: [
    {
      bearerAuth: [],
    },
  ],
};

// Options for the swagger docs
const options = {
  swaggerDefinition,
  // Path to the API docs
  apis: ['./routes/*.js', './controllers/*.js'], // Adjust the paths according to your project structure
};

// Initialize swagger-jsdoc
const swaggerSpec = swaggerJsdoc(options);

module.exports = swaggerSpec;
