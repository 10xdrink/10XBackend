// config/stripe.js

const Stripe = require('stripe');
const stripe = Stripe(process.env.STRIPE_SECRET_KEY); // Ensure STRIPE_SECRET_KEY is set in .env

module.exports = stripe;
