// models/Coupon.js

const mongoose = require('mongoose');

const CouponSchema = new mongoose.Schema(
  {
    code: {
      type: String,
      required: [true, 'Please add a coupon code'],
      unique: true,
      uppercase: true,
      trim: true,
      maxlength: [15, 'Coupon code cannot exceed 15 characters'],
    },
    discount: {
      type: Number,
      required: [true, 'Please add a discount value'],
      min: [0, 'Discount cannot be negative'],
    },
    discountType: {
      type: String,
      enum: ['percentage', 'fixed'],
      required: [true, 'Please specify the discount type'],
    },
    expirationDate: {
      type: Date,
      required: [true, 'Please add an expiration date'],
      validate: {
        validator: function (value) {
          return value > Date.now();
        },
        message: 'Expiration date must be in the future',
      },
    },
    maxUses: {
      type: Number,
      default: null, // null means unlimited uses
      min: [1, 'Max uses must be at least 1 if specified'],
    },
    usedCount: {
      type: Number,
      default: 0,
      min: [0, 'Used count cannot be negative'],
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    applicableProducts: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product',
      },
    ],
    applicableCategories: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Category',
      },
    ],
  },
  { 
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Virtual to check if coupon is expired
CouponSchema.virtual('isExpired').get(function () {
  return this.expirationDate < Date.now();
});

// Method to apply coupon to the order total with validation
CouponSchema.methods.applyCoupon = function (orderTotal) {
  if (!this.isActive || this.isExpired) {
    return { success: false, discount: 0, message: 'Coupon is not applicable' };
  }

  let discountAmount = 0;
  if (this.discountType === 'percentage') {
    discountAmount = (this.discount / 100) * orderTotal; // Percentage discount
  } else if (this.discountType === 'fixed') {
    discountAmount = this.discount; // Fixed discount
  }

  // Ensure discount does not exceed the order total
  return { success: true, discount: Math.min(discountAmount, orderTotal) };
};

// Static method to validate coupon usage
CouponSchema.statics.canApplyCoupon = function (coupon) {
  if (!coupon.isActive) {
    return { success: false, message: 'Coupon is not active' };
  }
  if (coupon.isExpired) {
    return { success: false, message: 'Coupon has expired' };
  }
  if (coupon.maxUses !== null && coupon.usedCount >= coupon.maxUses) {
    return { success: false, message: 'Coupon has reached its maximum number of uses' };
  }
  return { success: true };
};

// Pre-save hook to validate and increment the used count safely
CouponSchema.pre('save', function (next) {
  if (this.isModified('usedCount') && this.usedCount < 0) {
    return next(new Error('Used count cannot be negative'));
  }
  if (this.isModified('expirationDate') && this.expirationDate < Date.now()) {
    return next(new Error('Expiration date cannot be in the past'));
  }
  next();
});

// Indexes for efficient querying
CouponSchema.index({ code: 1 });
CouponSchema.index({ isActive: 1, expirationDate: 1 });
CouponSchema.index({ applicableProducts: 1 });
CouponSchema.index({ applicableCategories: 1 });

module.exports = mongoose.model('Coupon', CouponSchema);
