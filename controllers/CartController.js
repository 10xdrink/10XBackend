// controllers/CartController.js

const Cart = require('../models/Cart');
const Product = require('../models/Product');
const { validationResult } = require('express-validator');

// Adds an item to the user's cart
exports.addItemToCart = async (req, res) => {
  // Validate request
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation Errors:', errors.array());
    return res.status(400).json({ errors: errors.array() });
  }

  const userId = req.user.id;
  const { productId, variant, packaging, quantity } = req.body;

  console.log('Add to Cart Request Body:', req.body);

  try {
    // Fetch product details
    const product = await Product.findById(productId);
    if (!product) {
      console.log(`Product not found: ${productId}`);
      return res.status(404).json({ message: 'Product not found' });
    }

    // Validate variant
    const selectedVariant = product.variants.find(v => v.size === variant);
    if (!selectedVariant) {
      console.log(`Variant not found: ${variant} for product: ${productId}`);
      return res.status(400).json({ message: 'Variant not found for the selected product' });
    }

    // Validate packaging
    if (!product.packaging.includes(packaging)) {
      console.log(`Invalid packaging option: ${packaging} for product: ${productId}`);
      return res.status(400).json({ message: 'Invalid packaging option selected' });
    }

    // Find or create cart
    let cart = await Cart.findOne({ user: userId });
    if (!cart) {
      cart = new Cart({ user: userId, items: [] });
      console.log(`Created new cart for user: ${userId}`);
    }

    // Check if item already exists in cart
    const existingItem = cart.items.find(item =>
      item.product.toString() === productId &&
      item.variant === variant &&
      item.packaging === packaging
    );

    if (existingItem) {
      // Update quantity
      existingItem.quantity += quantity;
      console.log(`Updated quantity for item: ${existingItem._id}, new quantity: ${existingItem.quantity}`);
    } else {
      // Add new item
      cart.items.push({
        product: productId,
        title: product.title,
        variant,
        packaging,
        quantity,
        price: selectedVariant.price, // Use the variant price
        thumbnail: product.thumbnail,
      });
      console.log(`Added new item to cart: productId=${productId}, variant=${variant}, packaging=${packaging}`);
    }

    // Save cart
    await cart.save();

    // Populate the product field before sending the response
    await cart.populate('items.product');

    console.log('Cart updated successfully:', cart);

    res.status(200).json(cart);
  } catch (error) {
    console.error('Error adding item to cart:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Updates the quantity of an item in the cart
exports.updateCartItemQuantity = async (req, res) => {
  // Validate request
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation Errors:', errors.array());
    return res.status(400).json({ errors: errors.array() });
  }

  const userId = req.user.id;
  const { productId, variant, packaging, quantity } = req.body;

  console.log('Update Cart Item Request Body:', req.body);

  try {
    const cart = await Cart.findOne({ user: userId });
    if (!cart) {
      console.log(`Cart not found for user: ${userId}`);
      return res.status(404).json({ message: 'Cart not found' });
    }

    // Log current cart items
    console.log('Current Cart Items:', cart.items.map(item => ({
      productId: item.product.toString(),
      variant: item.variant,
      packaging: item.packaging,
      quantity: item.quantity,
    })));

    // Find item
    const item = cart.items.find(item =>
      item.product.toString() === productId &&
      item.variant === variant &&
      item.packaging === packaging
    );

    if (!item) {
      console.log(`Item not found in cart: productId=${productId}, variant=${variant}, packaging=${packaging}`);
      return res.status(404).json({ message: 'Item not found in cart' });
    }

    // Update quantity
    item.quantity = quantity;
    console.log(`Updated quantity for item: ${item._id}, new quantity: ${item.quantity}`);

    // Save cart
    await cart.save();

    // Populate the product field before sending the response
    await cart.populate('items.product');

    console.log('Cart updated successfully:', cart);

    res.status(200).json(cart);
  } catch (error) {
    console.error('Error updating cart item quantity:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Removes an item from the cart
exports.removeItemFromCart = async (req, res) => {
  // Validate request
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation Errors:', errors.array());
    return res.status(400).json({ errors: errors.array() });
  }

  const userId = req.user.id;
  const { productId, variant, packaging } = req.body;

  console.log('Remove Item from Cart Request Body:', req.body);

  try {
    const cart = await Cart.findOne({ user: userId });
    if (!cart) {
      console.log(`Cart not found for user: ${userId}`);
      return res.status(404).json({ message: 'Cart not found' });
    }

    // Log current cart items
    console.log('Current Cart Items:', cart.items.map(item => ({
      productId: item.product.toString(),
      variant: item.variant,
      packaging: item.packaging,
      quantity: item.quantity,
    })));

    const initialLength = cart.items.length;
    cart.items = cart.items.filter(
      item =>
        !(
          item.product.toString() === productId &&
          item.variant === variant &&
          item.packaging === packaging
        )
    );

    if (cart.items.length === initialLength) {
      console.log(`Item not found to remove: productId=${productId}, variant=${variant}, packaging=${packaging}`);
      return res.status(404).json({ message: 'Item not found in cart' });
    }

    // Save cart
    await cart.save();

    // Populate the product field before sending the response
    await cart.populate('items.product');

    console.log(`Removed item from cart: productId=${productId}, variant=${variant}, packaging=${packaging}`);

    res.status(200).json(cart);
  } catch (error) {
    console.error('Error removing item from cart:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Fetches the user's cart
exports.getCart = async (req, res) => {
  const userId = req.user.id;

  try {
    const cart = await Cart.findOne({ user: userId }).populate('items.product');
    if (!cart) {
      console.log(`Cart not found for user: ${userId}`);
      return res.status(404).json({ message: 'Cart not found' });
    }
    console.log(`Fetched cart for user: ${userId}`);
    // Log the populated cart for debugging
    console.log('Populated Cart:', JSON.stringify(cart, null, 2));
    res.status(200).json(cart);
  } catch (error) {
    console.error('Error fetching cart:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Clears all items from the user's cart
exports.clearCart = async (req, res) => {
  const userId = req.user.id;

  try {
    const cart = await Cart.findOne({ user: userId });
    if (!cart) {
      console.log(`Cart not found for user: ${userId}`);
      return res.status(404).json({ message: 'Cart not found' });
    }

    // Log cart items before clearing
    console.log('Clearing Cart Items:', cart.items.map(item => ({
      productId: item.product.toString(),
      variant: item.variant,
      packaging: item.packaging,
      quantity: item.quantity,
    })));

    // Clear items and save cart
    cart.items = [];
    await cart.save();

    console.log(`Cleared cart for user: ${userId}`);

    res.status(200).json({ message: 'Cart cleared successfully' });
  } catch (error) {
    console.error('Error clearing cart:', error);
    res.status(500).json({ message: 'Server error' });
  }
};