// tests/order.test.js
const request = require('supertest');
const app = require('../app');
const mongoose = require('mongoose');
const Order = require('../models/Order');
const User = require('../models/User');
const Product = require('../models/Product');
const jwt = require('jsonwebtoken');

let userToken;
let adminToken;
let productId;

describe('Order Routes', () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.MONGO_URI_TEST, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    // Create a user and get token
    const user = new User({
      name: 'Order User',
      email: 'orderuser@example.com',
      password: 'UserP@ssw0rd',
      role: 'user',
    });
    await user.save();
    userToken = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Create an admin and get token
    const admin = new User({
      name: 'Admin Order',
      email: 'adminorder@example.com',
      password: 'AdminP@ssw0rd',
      role: 'order-manager',
    });
    await admin.save();
    adminToken = jwt.sign(
      { id: admin._id, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Create a product
    const product = new Product({
      name: 'Order Product',
      price: 20,
      stock: 50,
      category: mongoose.Types.ObjectId(),
    });
    await product.save();
    productId = product._id;
  });

  afterAll(async () => {
    await Order.deleteMany({});
    await Product.deleteMany({});
    await User.deleteMany({});
    await mongoose.connection.close();
  });

  describe('POST /api/orders', () => {
    it('should create a new order', async () => {
      const res = await request(app)
        .post('/api/orders')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          items: [
            {
              product: productId,
              quantity: 2,
              price: 20,
            },
          ],
          shippingAddress: '123 Test St',
          billingAddress: '123 Test St',
          paymentMethod: 'stripe',
        });
      expect(res.statusCode).toEqual(201);
      expect(res.body.data).toHaveProperty('totalAmount', 40);
    });

    it('should not create order with insufficient stock', async () => {
      const res = await request(app)
        .post('/api/orders')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          items: [
            {
              product: productId,
              quantity: 1000, // Exceeds stock
              price: 20,
            },
          ],
          shippingAddress: '123 Test St',
          billingAddress: '123 Test St',
          paymentMethod: 'stripe',
        });
      expect(res.statusCode).toEqual(400);
      expect(res.body.message).toBe('Insufficient stock for product Order Product.');
    });
  });

  describe('GET /api/orders', () => {
    beforeAll(async () => {
      // Create multiple orders
      await Order.create([
        {
          orderNumber: 'ORD1001',
          customer: mongoose.Types.ObjectId(),
          items: [{ product: productId, quantity: 1, price: 20 }],
          totalAmount: 20,
          status: 'pending',
          paymentMethod: 'stripe',
          paymentStatus: 'pending',
          shippingAddress: '123 Test St',
          billingAddress: '123 Test St',
        },
        {
          orderNumber: 'ORD1002',
          customer: mongoose.Types.ObjectId(),
          items: [{ product: productId, quantity: 3, price: 20 }],
          totalAmount: 60,
          status: 'shipped',
          paymentMethod: 'paypal',
          paymentStatus: 'paid',
          shippingAddress: '456 Test Ave',
          billingAddress: '456 Test Ave',
        },
      ]);
    });

    it('should fetch all orders as admin', async () => {
      const res = await request(app)
        .get('/api/orders')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.statusCode).toEqual(200);
      expect(res.body.count).toBeGreaterThanOrEqual(2);
    });

    it('should fetch orders with status filter', async () => {
      const res = await request(app)
        .get('/api/orders')
        .set('Authorization', `Bearer ${adminToken}`)
        .query({ status: 'shipped' });
      expect(res.statusCode).toEqual(200);
      expect(res.body.data.every(order => order.status === 'shipped')).toBe(true);
    });

    it('should not allow user to fetch all orders', async () => {
      const res = await request(app)
        .get('/api/orders')
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.statusCode).toEqual(403);
      expect(res.body.message).toBe('Forbidden.');
    });
  });

  describe('PUT /api/orders/:id/status', () => {
    let orderId;
    beforeAll(async () => {
      const order = await Order.create({
        orderNumber: 'ORD1003',
        customer: mongoose.Types.ObjectId(),
        items: [{ product: productId, quantity: 2, price: 20 }],
        totalAmount: 40,
        status: 'processing',
        paymentMethod: 'stripe',
        paymentStatus: 'paid',
        shippingAddress: '789 Test Blvd',
        billingAddress: '789 Test Blvd',
      });
      orderId = order._id;
    });

    it('should update order status', async () => {
      const res = await request(app)
        .put(`/api/orders/${orderId}/status`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ status: 'shipped' });
      expect(res.statusCode).toEqual(200);
      expect(res.body.data).toHaveProperty('status', 'shipped');
    });

    it('should return 404 for updating non-existing order', async () => {
      const res = await request(app)
        .put(`/api/orders/${mongoose.Types.ObjectId()}/status`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ status: 'delivered' });
      expect(res.statusCode).toEqual(404);
      expect(res.body.message).toBe('Order not found.');
    });
  });

  describe('POST /api/orders/:id/cancel', () => {
    let orderId;
    beforeAll(async () => {
      const order = await Order.create({
        orderNumber: 'ORD1004',
        customer: mongoose.Types.ObjectId(),
        items: [{ product: productId, quantity: 1, price: 20 }],
        totalAmount: 20,
        status: 'pending',
        paymentMethod: 'cod',
        paymentStatus: 'pending',
        shippingAddress: '321 Test Ln',
        billingAddress: '321 Test Ln',
      });
      orderId = order._id;
    });

    it('should cancel an order', async () => {
      const res = await request(app)
        .post(`/api/orders/${orderId}/cancel`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ reason: 'Customer request' });
      expect(res.statusCode).toEqual(200);
      expect(res.body.message).toBe('Order cancelled successfully.');

      const order = await Order.findById(orderId);
      expect(order.status).toBe('cancelled');
    });

    it('should return 404 for cancelling non-existing order', async () => {
      const res = await request(app)
        .post(`/api/orders/${mongoose.Types.ObjectId()}/cancel`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ reason: 'Invalid order' });
      expect(res.statusCode).toEqual(404);
      expect(res.body.message).toBe('Order not found.');
    });
  });
});
