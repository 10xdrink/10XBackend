// tests/product.test.js
const request = require('supertest');
const app = require('../app');
const mongoose = require('mongoose');
const Product = require('../models/Product');
const User = require('../models/User');
const jwt = require('jsonwebtoken');

let adminToken;

describe('Product Routes', () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.MONGO_URI_TEST, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    // Create an admin user and get token
    const admin = new User({
      name: 'Admin User',
      email: 'admin@example.com',
      password: 'AdminP@ssw0rd', // Ensure hashing if applicable
      role: 'super-admin',
    });
    await admin.save();

    adminToken = jwt.sign(
      { id: admin._id, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
  });

  afterAll(async () => {
    await Product.deleteMany({});
    await User.deleteMany({});
    await mongoose.connection.close();
  });

  describe('POST /api/products', () => {
    it('should create a new product', async () => {
      const res = await request(app)
        .post('/api/products')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          name: 'Test Product',
          price: 99.99,
          stock: 10,
          description: 'A test product',
          category: mongoose.Types.ObjectId(),
          tags: [mongoose.Types.ObjectId()],
        });
      expect(res.statusCode).toEqual(201);
      expect(res.body.data).toHaveProperty('name', 'Test Product');
    });

    it('should not create a product without required fields', async () => {
      const res = await request(app)
        .post('/api/products')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          price: 49.99,
          stock: 5,
        });
      expect(res.statusCode).toEqual(422);
      expect(res.body.errors).toBeDefined();
    });
  });

  describe('GET /api/products', () => {
    beforeAll(async () => {
      // Create multiple products
      await Product.create([
        { name: 'Product 1', price: 50, stock: 5, category: mongoose.Types.ObjectId() },
        { name: 'Product 2', price: 150, stock: 15, category: mongoose.Types.ObjectId() },
      ]);
    });

    it('should fetch all products', async () => {
      const res = await request(app).get('/api/products');
      expect(res.statusCode).toEqual(200);
      expect(res.body.count).toBeGreaterThanOrEqual(2);
    });

    it('should fetch products with price filter', async () => {
      const res = await request(app).get('/api/products').query({ priceMin: 100 });
      expect(res.statusCode).toEqual(200);
      expect(res.body.data.every(p => p.price >= 100)).toBe(true);
    });
  });

  describe('GET /api/products/:id', () => {
    let productId;
    beforeAll(async () => {
      const product = await Product.create({
        name: 'Specific Product',
        price: 75,
        stock: 7,
        category: mongoose.Types.ObjectId(),
      });
      productId = product._id;
    });

    it('should fetch a product by ID', async () => {
      const res = await request(app).get(`/api/products/${productId}`);
      expect(res.statusCode).toEqual(200);
      expect(res.body.data).toHaveProperty('name', 'Specific Product');
    });

    it('should return 404 for non-existing product', async () => {
      const res = await request(app).get(`/api/products/${mongoose.Types.ObjectId()}`);
      expect(res.statusCode).toEqual(404);
      expect(res.body.message).toBe('Product not found.');
    });
  });

  describe('PUT /api/products/:id', () => {
    let productId;
    beforeAll(async () => {
      const product = await Product.create({
        name: 'Update Product',
        price: 60,
        stock: 6,
        category: mongoose.Types.ObjectId(),
      });
      productId = product._id;
    });

    it('should update a product', async () => {
      const res = await request(app)
        .put(`/api/products/${productId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          price: 65,
          stock: 8,
        });
      expect(res.statusCode).toEqual(200);
      expect(res.body.data).toHaveProperty('price', 65);
      expect(res.body.data).toHaveProperty('stock', 8);
    });

    it('should return 404 for updating non-existing product', async () => {
      const res = await request(app)
        .put(`/api/products/${mongoose.Types.ObjectId()}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          price: 80,
        });
      expect(res.statusCode).toEqual(404);
      expect(res.body.message).toBe('Product not found.');
    });
  });

  describe('DELETE /api/products/:id', () => {
    let productId;
    beforeAll(async () => {
      const product = await Product.create({
        name: 'Delete Product',
        price: 40,
        stock: 4,
        category: mongoose.Types.ObjectId(),
      });
      productId = product._id;
    });

    it('should deactivate a product', async () => {
      const res = await request(app)
        .delete(`/api/products/${productId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.statusCode).toEqual(200);
      expect(res.body.message).toBe('Product deactivated successfully.');

      const product = await Product.findById(productId);
      expect(product.isActive).toBe(false);
    });

    it('should return 404 for deleting non-existing product', async () => {
      const res = await request(app)
        .delete(`/api/products/${mongoose.Types.ObjectId()}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.statusCode).toEqual(404);
      expect(res.body.message).toBe('Product not found.');
    });
  });
});
