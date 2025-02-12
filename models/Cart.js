const mongoose = require('mongoose');

// Subdocument schema for individual cart items
const CartItemSchema = new mongoose.Schema(
  {
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product',
      required: [true, 'Product ID is required'],
      index: true,
    },
    title: {
      type: String,
      required: [true, 'Product title is required'],
      trim: true,
    },
    variant: {
      type: String,
      required: [true, 'Product variant is required'],
      trim: true,
    },
    packaging: {
      type: String,
      required: [true, 'Product packaging is required'],
      enum: ['Bottle', 'Box', 'Canister', 'Packet', 'Container'], // Expand as needed
    },
    quantity: {
      type: Number,
      required: [true, 'Quantity is required'],
      min: [1, 'Quantity cannot be less than 1'],
    },
    price: {
      type: Number,
      required: [true, 'Price is required'],
      min: [0, 'Price cannot be negative'],
    },
    thumbnail: {
      type: String,
      required: [true, 'Product image URL is required'],
      match: [
        /^https?:\/\/.+\.(jpg|jpeg|png|gif|webp|svg)$/i,
        'Please enter a valid image URL',
      ],
    },
  },
  { _id: false }
);

// Main schema for cart
const CartSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User ID is required'],
      index: true,
    },
    items: [CartItemSchema],
    totalAmount: {
      type: Number,
      required: true,
      default: 0,
      min: [0, 'Total amount cannot be negative'],
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true, transform: (_, ret) => { delete ret.__v; } },
    toObject: { virtuals: true },
  }
);

// Method to calculate total amount
CartSchema.methods.calculateTotal = function () {
  this.totalAmount = this.items.reduce(
    (sum, item) => sum + item.price * item.quantity,
    0
  );
  return this.totalAmount;
};

// Pre-save middleware to calculate total
CartSchema.pre('save', function (next) {
  this.calculateTotal();
  next();
});

// Pre-findOneAndUpdate middleware to ensure total is recalculated and updated item details are logged
CartSchema.pre('findOneAndUpdate', async function (next) {
  const update = this.getUpdate();
  if (update && update.items) {
    // Fetch document before update to access old values
    const cart = await this.model.findOne(this.getQuery());
    if (cart) {
      cart.calculateTotal();

      // Log details for the updated items
      update.items.forEach((updatedItem) => {
        const existingItem = cart.items.find(
          (item) => item.product.toString() === updatedItem.product.toString()
        );
        if (existingItem) {
          console.log(`Updated quantity for item: ${existingItem.title}, new quantity: ${updatedItem.quantity}`);
        }
      });

      // Apply updated total to the document
      this.set({ totalAmount: cart.totalAmount });
    }
  }
  next();
});


// Pre-findOneAndUpdate middleware to ensure total is recalculated after update
CartSchema.pre('findOneAndUpdate', async function (next) {
  const update = this.getUpdate();
  if (update && update.$set && update.$set.items) {
    // Calculate total from updated items
    const updatedItems = update.$set.items;
    const updatedTotal = updatedItems.reduce((sum, item) => {
      return sum + item.price * item.quantity;
    }, 0);

    // Apply updated total to the document
    this.set({ totalAmount: updatedTotal });
  }
  next();
});


module.exports = mongoose.model('Cart', CartSchema);
