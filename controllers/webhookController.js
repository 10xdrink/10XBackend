// controllers/webhookController.js

const Stripe = require('stripe');
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const Order = require('../models/Order');
const Transaction = require('../models/Transaction');
const Product = require('../models/Product');
const logger = require('../utils/logger');

/**
 * Handles Stripe webhook events.
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 */
exports.stripeWebhook = async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;

  try {
    event = stripe.webhooks.constructEvent(req.rawBody, sig, endpointSecret);
  } catch (err) {
    logger.error(`Webhook signature verification failed.`, err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle the event
  switch (event.type) {
    case 'payment_intent.succeeded':
      const paymentIntent = event.data.object;
      // Find the order associated with this payment intent
      const order = await Order.findOne({ 'paymentDetails.transactionId': paymentIntent.id });
      if (order) {
        order.paymentStatus = 'paid';
        order.status = 'processing';
        await order.save();

        // Create Transaction
        await Transaction.create({
          order: order._id,
          paymentMethod: order.paymentMethod,
          amount: order.finalAmount,
          status: 'completed',
          transactionId: paymentIntent.id,
          metadata: paymentIntent,
        });

        // Deduct stock
        for (const item of order.items) {
          await Product.findByIdAndUpdate(item.product, { $inc: { stock: -item.quantity } });
        }

        logger.info(`Order ${order.orderNumber} payment succeeded.`);
      }
      break;
    case 'payment_intent.payment_failed':
      const failedPaymentIntent = event.data.object;
      const failedOrder = await Order.findOne({ 'paymentDetails.transactionId': failedPaymentIntent.id });
      if (failedOrder) {
        failedOrder.paymentStatus = 'failed';
        failedOrder.status = 'failed';
        await failedOrder.save();

        logger.info(`Order ${failedOrder.orderNumber} payment failed.`);
      }
      break;
    // ... handle other event types as needed
    default:
      logger.warn(`Unhandled event type ${event.type}`);
  }

  // Return a response to acknowledge receipt of the event
  res.json({ received: true });
};
