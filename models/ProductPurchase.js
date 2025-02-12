// models/ProductPurchase.js

const mongoose = require('mongoose');

const ProductPurchaseSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product', // Assuming you have a Product model
      required: true,
    },
    quantity: {
      type: Number,
      default: 1,
      min: [1, 'Quantity cannot be less than 1'],
    },
    purchaseDate: {
      type: Date,
      default: Date.now,
    },
    // Add other relevant fields as needed
  },
  {
    timestamps: true, // Adds createdAt and updatedAt fields
  }
);

module.exports = mongoose.model('ProductPurchase', ProductPurchaseSchema);
