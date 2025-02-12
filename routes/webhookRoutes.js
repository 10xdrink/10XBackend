// routes/webhookRoutes.js

const express = require('express');
const router = express.Router();
const webhookController = require('../controllers/webhookController');
const bodyParser = require('body-parser');

// Stripe requires the raw body to construct the event
router.post(
  '/stripe',
  bodyParser.raw({ type: 'application/json' }),
  webhookController.stripeWebhook
);

module.exports = router;
