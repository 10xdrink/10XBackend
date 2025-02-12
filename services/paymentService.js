// services/paymentService.js

const Stripe = require('stripe');
const paypal = require('paypal-rest-sdk'); // Consider upgrading to @paypal/checkout-server-sdk for newer features
const logger = require('../utils/logger');
const Order = require('../models/Order'); // Ensure this model exists
const Transaction = require('../models/Transaction'); // Ensure this model exists
const request = require('request-promise-native'); // Using a modern promise-based HTTP client

// Initialize Stripe
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// Configure PayPal
paypal.configure({
  mode: process.env.PAYPAL_MODE || 'sandbox', // 'sandbox' or 'live'
  client_id: process.env.PAYPAL_CLIENT_ID,
  client_secret: process.env.PAYPAL_CLIENT_SECRET,
});

/**
 * Process a payment using Stripe or PayPal
 * @param {Object} order - The order object containing details like totalAmount, items, etc.
 * @param {Object} paymentDetails - Payment specific details
 * @param {string} paymentDetails.paymentMethod - 'stripe' or 'paypal'
 * @param {string} [paymentDetails.paymentMethodId] - Stripe payment method ID
 * @param {string} [paymentDetails.returnUrl] - PayPal return URL after payment approval
 * @param {string} [paymentDetails.cancelUrl] - PayPal cancel URL
 * @returns {Promise<Object>} - Payment result
 */
const processPayment = async (order, paymentDetails) => {
  const { paymentMethod } = paymentDetails;

  if (paymentMethod === 'stripe') {
    return await processStripePayment(order, paymentDetails);
  } else if (paymentMethod === 'paypal') {
    return await processPayPalPayment(order, paymentDetails);
  } else {
    throw new Error('Unsupported payment method');
  }
};

/**
 * Process payment using Stripe
 * @param {Object} order 
 * @param {Object} paymentDetails 
 * @returns {Promise<Object>}
 */
const processStripePayment = async (order, paymentDetails) => {
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(order.totalAmount * 100), // Amount in cents
      currency: 'usd', // Adjust currency as needed
      metadata: { orderId: order._id.toString() },
      payment_method: paymentDetails.paymentMethodId,
      confirm: true,
    });

    // Create a transaction record
    const transaction = await Transaction.create({
      order: order._id,
      paymentMethod: 'stripe',
      amount: order.totalAmount,
      status: paymentIntent.status,
      transactionId: paymentIntent.id,
      metadata: paymentIntent.metadata,
    });

    // Update order status based on payment intent status
    if (paymentIntent.status === 'succeeded') {
      order.status = 'paid';
      await order.save();
    } else {
      order.status = 'payment_pending';
      await order.save();
    }

    logger.info(`Stripe payment processed for order ${order._id}: ${paymentIntent.status}`);

    return { success: true, paymentIntent };
  } catch (error) {
    logger.error(`Stripe payment failed for order ${order._id}: ${error.message}`);
    throw new Error('Stripe payment failed');
  }
};

/**
 * Process payment using PayPal
 * @param {Object} order 
 * @param {Object} paymentDetails 
 * @returns {Promise<Object>}
 */
const processPayPalPayment = async (order, paymentDetails) => {
  const create_payment_json = {
    intent: 'sale',
    payer: {
      payment_method: 'paypal',
    },
    redirect_urls: {
      return_url: paymentDetails.returnUrl,
      cancel_url: paymentDetails.cancelUrl,
    },
    transactions: [
      {
        item_list: {
          items: order.items.map(item => ({
            name: item.product.title,
            sku: item.product._id.toString(),
            price: item.price.toFixed(2),
            currency: 'USD',
            quantity: item.quantity,
          })),
        },
        amount: {
          currency: 'USD',
          total: order.totalAmount.toFixed(2),
        },
        description: 'Purchase from eCommerce Platform',
        custom: order._id.toString(), // Store order ID for reference in webhook
      },
    ],
  };

  try {
    const payment = await new Promise((resolve, reject) => {
      paypal.payment.create(create_payment_json, function (error, payment) {
        if (error) {
          reject(error);
        } else {
          resolve(payment);
        }
      });
    });

    // Create a transaction record with initial status
    const transaction = await Transaction.create({
      order: order._id,
      paymentMethod: 'paypal',
      amount: order.totalAmount,
      status: 'created',
      transactionId: payment.id,
      metadata: { payment },
    });

    logger.info(`PayPal payment created for order ${order._id}: ${payment.id}`);

    return { success: true, payment };
  } catch (error) {
    logger.error(`PayPal payment creation failed for order ${order._id}: ${error.message}`);
    throw new Error('PayPal payment failed');
  }
};

/**
 * Verify Stripe webhook signature
 * @param {Object} req - Express request object
 * @returns {Promise<Object>} - Stripe event
 */
const verifyStripeWebhook = async (req) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    logger.info(`Stripe webhook verified: ${event.type}`);
    return event;
  } catch (err) {
    logger.error(`Stripe webhook verification failed: ${err.message}`);
    throw new Error('Stripe webhook verification failed');
  }
};

/**
 * Handle Stripe webhook events
 * @param {Object} event - Stripe event object
 * @returns {Promise<void>}
 */
const handleStripeEvent = async (event) => {
  switch (event.type) {
    case 'payment_intent.succeeded':
      const paymentIntent = event.data.object;
      await handleStripePaymentSucceeded(paymentIntent);
      break;
    case 'payment_intent.payment_failed':
      const failedPaymentIntent = event.data.object;
      await handleStripePaymentFailed(failedPaymentIntent);
      break;
    // Handle other event types as needed
    default:
      logger.warn(`Unhandled Stripe event type: ${event.type}`);
  }
};

/**
 * Handle successful Stripe payment
 * @param {Object} paymentIntent 
 * @returns {Promise<void>}
 */
const handleStripePaymentSucceeded = async (paymentIntent) => {
  try {
    const orderId = paymentIntent.metadata.orderId;
    const order = await Order.findById(orderId);
    if (!order) {
      logger.error(`Order not found for Stripe payment intent: ${paymentIntent.id}`);
      return;
    }

    order.status = 'paid';
    await order.save();

    // Update transaction status
    await Transaction.findOneAndUpdate(
      { transactionId: paymentIntent.id },
      { status: 'succeeded' }
    );

    logger.info(`Order ${orderId} marked as paid via Stripe`);
  } catch (error) {
    logger.error(`Error handling Stripe payment succeeded: ${error.message}`);
  }
};

/**
 * Handle failed Stripe payment
 * @param {Object} paymentIntent 
 * @returns {Promise<void>}
 */
const handleStripePaymentFailed = async (paymentIntent) => {
  try {
    const orderId = paymentIntent.metadata.orderId;
    const order = await Order.findById(orderId);
    if (!order) {
      logger.error(`Order not found for Stripe payment intent: ${paymentIntent.id}`);
      return;
    }

    order.status = 'payment_failed';
    await order.save();

    // Update transaction status
    await Transaction.findOneAndUpdate(
      { transactionId: paymentIntent.id },
      { status: 'failed' }
    );

    logger.info(`Order ${orderId} marked as payment failed via Stripe`);
  } catch (error) {
    logger.error(`Error handling Stripe payment failed: ${error.message}`);
  }
};

/**
 * Verify PayPal webhook signature
 * @param {Object} req - Express request object
 * @returns {Promise<Object>} - PayPal event
 */
const verifyPayPalWebhook = async (req) => {
  const eventBody = req.body;
  const transmissionId = req.headers['paypal-transmission-id'];
  const transmissionTime = req.headers['paypal-transmission-time'];
  const certUrl = req.headers['paypal-cert-url'];
  const authAlgo = req.headers['paypal-auth-algo'];
  const transmissionSig = req.headers['paypal-transmission-sig'];
  const webhookId = process.env.PAYPAL_WEBHOOK_ID;

  const verifyUrl = (process.env.PAYPAL_MODE === 'live') 
    ? 'https://api.paypal.com/v1/notifications/verify-webhook-signature' 
    : 'https://api.sandbox.paypal.com/v1/notifications/verify-webhook-signature';

  const verifyPayload = {
    auth_algo: authAlgo,
    cert_url: certUrl,
    transmission_id: transmissionId,
    transmission_sig: transmissionSig,
    transmission_time: transmissionTime,
    webhook_id: webhookId,
    webhook_event: eventBody,
  };

  try {
    const response = await request({
      uri: verifyUrl,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      auth: {
        user: process.env.PAYPAL_CLIENT_ID,
        pass: process.env.PAYPAL_CLIENT_SECRET,
      },
      body: JSON.stringify(verifyPayload),
    });

    const responseBody = JSON.parse(response);
    if (responseBody.verification_status === 'SUCCESS') {
      logger.info(`PayPal webhook verified: ${responseBody.verification_status}`);
      return eventBody;
    } else {
      logger.error(`PayPal webhook verification failed: ${responseBody.verification_status}`);
      throw new Error('PayPal webhook verification failed');
    }
  } catch (error) {
    logger.error(`PayPal webhook verification error: ${error.message}`);
    throw new Error('PayPal webhook verification failed');
  }
};

/**
 * Handle PayPal webhook events
 * @param {Object} event - PayPal event object
 * @returns {Promise<void>}
 */
const handlePayPalEvent = async (event) => {
  const eventType = event.event_type;
  switch (eventType) {
    case 'PAYMENT.SALE.COMPLETED':
      const sale = event.resource;
      await handlePayPalPaymentCompleted(sale);
      break;
    case 'PAYMENT.SALE.DENIED':
      const deniedSale = event.resource;
      await handlePayPalPaymentDenied(deniedSale);
      break;
    // Handle other event types as needed
    default:
      logger.warn(`Unhandled PayPal event type: ${eventType}`);
  }
};

/**
 * Handle successful PayPal payment
 * @param {Object} sale - Sale object from PayPal event
 * @returns {Promise<void>}
 */
const handlePayPalPaymentCompleted = async (sale) => {
  try {
    const orderId = sale.custom; // Ensure 'custom' field contains orderId when creating the payment
    const order = await Order.findById(orderId);
    if (!order) {
      logger.error(`Order not found for PayPal sale: ${sale.id}`);
      return;
    }

    order.status = 'paid';
    await order.save();

    // Update transaction status
    await Transaction.findOneAndUpdate(
      { transactionId: sale.id },
      { status: 'succeeded' }
    );

    logger.info(`Order ${orderId} marked as paid via PayPal`);
  } catch (error) {
    logger.error(`Error handling PayPal payment completed: ${error.message}`);
  }
};

/**
 * Handle denied PayPal payment
 * @param {Object} sale - Sale object from PayPal event
 * @returns {Promise<void>}
 */
const handlePayPalPaymentDenied = async (sale) => {
  try {
    const orderId = sale.custom; // Ensure 'custom' field contains orderId when creating the payment
    const order = await Order.findById(orderId);
    if (!order) {
      logger.error(`Order not found for PayPal sale: ${sale.id}`);
      return;
    }

    order.status = 'payment_failed';
    await order.save();

    // Update transaction status
    await Transaction.findOneAndUpdate(
      { transactionId: sale.id },
      { status: 'failed' }
    );

    logger.info(`Order ${orderId} marked as payment failed via PayPal`);
  } catch (error) {
    logger.error(`Error handling PayPal payment denied: ${error.message}`);
  }
};

/**
 * Exported functions
 */
module.exports = {
  processPayment,
  verifyStripeWebhook,
  handleStripeEvent,
  verifyPayPalWebhook,
  handlePayPalEvent,
};
