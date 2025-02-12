// models/User.js

const mongoose = require('mongoose');
const AddressSchema = require('./Address'); // Import the AddressSchema

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please add a name'],
      trim: true,
    },
    email: {
      type: String,
      required: [true, 'Please add an email'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [
        /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
        'Please add a valid email',
      ],
    },
    password: {
      type: String,
      required: [true, 'Please add a password'],
      minlength: 6,
      select: false, // Do not return password by default
    },
    role: {
      type: String,
      enum: [
        'super-admin',
        'product-manager',
        'order-manager',
        'content-manager',
        'customer-support-manager',
        'marketing-manager',
        'analytics-viewer',
        'user',
      ],
      default: 'user',
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    profilePicture: {
      type: String,
      default: '', // URL to the profile picture
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date,
    deletionToken: String, // Field for deletion token
    deletionTokenExpire: Date, // Field for token expiration
    otp: {
      type: String,
    },
    otpExpire: {
      type: Date,
    },
    addresses: [AddressSchema], // Embedding the AddressSchema as subdocuments
  },
  { timestamps: true }
);

// Exclude password and other sensitive fields from JSON responses
UserSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  delete obj.resetPasswordToken;
  delete obj.resetPasswordExpire;
  delete obj.deletionToken;
  delete obj.deletionTokenExpire;
  delete obj.otp;
  delete obj.otpExpire;
  return obj;
};

module.exports = mongoose.model('User', UserSchema);
