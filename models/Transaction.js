// models/Transaction.js

const mongoose = require('mongoose');
const crypto = require('crypto');

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'defaultEncryptionKey1234567890123456'; // 32 characters for AES-256
const IV_LENGTH = 16; // AES IV length

// Helper functions for encryption and decryption
const encrypt = (text) => {
  if (!text) return text;
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
};

const decrypt = (text) => {
  if (!text) return text;
  const textParts = text.split(':');
  if (textParts.length !== 2) return text;
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encryptedText = Buffer.from(textParts.join(''), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

// Transaction Schema
const TransactionSchema = new mongoose.Schema(
  {
    order: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Order',
      required: [true, 'Order reference is required'],
    },
    paymentMethod: {
      type: String,
      enum: ['card', 'upi'], // Updated to include 'card' and 'upi'
      required: [true, 'Payment method is required'],
    },
    amount: {
      type: Number,
      required: [true, 'Transaction amount is required'],
      min: [0, 'Amount cannot be negative'],
    },
    status: {
      type: String,
      enum: ['pending', 'completed', 'failed', 'refunded'],
      default: 'pending',
    },
    transactionId: {
      type: String,
      unique: true,
      sparse: true,
      trim: true,
      get: decrypt,
      set: encrypt,
    },
    receiptUrl: {
      type: String,
      trim: true,
      get: decrypt,
      set: encrypt,
    },
    refundedAmount: {
      type: Number,
      default: 0,
      min: [0, 'Refunded amount cannot be negative'],
    },
    metadata: {
      type: Map,
      of: String,
      default: {},
    },
  },
  { 
    timestamps: true,
    toJSON: { getters: true, virtuals: true },
    toObject: { getters: true, virtuals: true },
  }
);

// Middleware for encrypting sensitive fields on save
TransactionSchema.pre('save', function (next) {
  if (this.isModified('transactionId')) {
    this.transactionId = encrypt(this.transactionId);
  }
  if (this.isModified('receiptUrl')) {
    this.receiptUrl = encrypt(this.receiptUrl);
  }
  next();
});

// Static method to fetch transactions by order ID with optional status filter
TransactionSchema.statics.findByOrder = async function (orderId, status = null) {
  const query = { order: orderId };
  if (status) query.status = status;
  return this.find(query);
};

// Static method to calculate the total amount refunded
TransactionSchema.statics.calculateTotalRefunded = async function (orderId) {
  const transactions = await this.find({ order: orderId, status: 'refunded' });
  return transactions.reduce((sum, tx) => sum + tx.refundedAmount, 0);
};

// Indexes for optimized search
TransactionSchema.index({ order: 1 });
TransactionSchema.index({ status: 1 });

module.exports = mongoose.model('Transaction', TransactionSchema);
