// models/Order.js

const mongoose = require('mongoose');
const ORDER_STATUS = require('../constants/orderStatus'); // Order status constants
const AddressSchema = require('./Address'); // Import the AddressSchema

// Order Item Schema
const OrderItemSchema = new mongoose.Schema(
  {
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product',
      required: [true, 'Please add a product'],
    },
    variant: {
      type: String,
      required: [true, 'Please add a variant'],
    },
    packaging: {
      type: String,
      required: [true, 'Please add a packaging'],
    },
    quantity: {
      type: Number,
      required: [true, 'Please add quantity'],
      min: [1, 'Quantity cannot be less than 1'],
    },
    price: {
      type: Number,
      required: [true, 'Please add price'],
      min: [0, 'Price cannot be negative'],
    },
  },
  { _id: false }
);

// Main Order Schema
const OrderSchema = new mongoose.Schema(
  {
    orderNumber: {
      type: String,
      unique: true,
      trim: true,
      default: function () {
        return `ORD-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
      },
    },
    customer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Please add a customer'],
    },
    items: {
      type: [OrderItemSchema],
      validate: {
        validator: function (items) {
          return items.length > 0;
        },
        message: 'Order must contain at least one item',
      },
      required: [true, 'Please add order items'],
    },
    totalAmount: {
      type: Number,
      required: true,
      min: [0, 'Total amount cannot be negative'],
    },
    status: {
      type: String,
      enum: Object.values(ORDER_STATUS),
      default: ORDER_STATUS.PENDING,
    },
    paymentMethod: {
      type: String,
      enum: ['cod', 'cash_on_delivery', 'razorpay', 'card', 'upi', 'paypal', 'stripe'],
      default: 'cod',
    },
    paymentStatus: {
      type: String,
      enum: ['paid', 'pending', 'failed', 'refunded'],
      default: 'pending',
    },
    shippingAddress: { type: AddressSchema, required: true },
    billingAddress: { type: AddressSchema, required: true },
    discount: {
      type: Number,
      default: 0,
      min: [0, 'Discount cannot be negative'],
      validate: {
        validator: function (value) {
          return value <= this.totalAmount;
        },
        message: 'Discount cannot exceed total amount',
      },
    },
    couponCode: {
      type: String,
      trim: true,
      default: null,
    },
    paymentDetails: {
      transactionId: { type: String, default: null, trim: true },
      fee: { type: Number, default: 0, min: [0, 'Fee cannot be negative'] },
    },
    cancellationReason: { type: String, default: null }, // Added for cancellation reason
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Virtual for final amount after discount
OrderSchema.virtual('finalAmount').get(function () {
  return this.totalAmount - this.discount;
});

// Method to calculate the total amount before saving
OrderSchema.methods.calculateTotal = function () {
  this.totalAmount = this.items.reduce((acc, item) => {
    if (item.price == null || isNaN(item.price)) {
      throw new Error('Invalid price in order item');
    }
    return acc + item.price * item.quantity;
  }, 0);

  // Discount is handled elsewhere; ensure finalAmount is accurate
  this.finalAmount = this.totalAmount - this.discount;
};

// Pre-save hook to calculate total amount and assign order number if not provided
OrderSchema.pre('save', async function (next) {
  if (!this.orderNumber) {
    this.orderNumber = `ORD-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  }
  this.calculateTotal();
  next();
});

// Indexes for faster retrieval and filtering
OrderSchema.index({ orderNumber: 1 });
OrderSchema.index({ customer: 1, status: 1 });
OrderSchema.index({ 'shippingAddress.country': 1, 'billingAddress.country': 1 });

module.exports = mongoose.model('Order', OrderSchema);
