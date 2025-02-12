// tests/faq.test.js
const request = require('supertest');
const app = require('../app');
const mongoose = require('mongoose');
const FAQ = require('../models/FAQ');
const User = require('../models/User');
const Category = require('../models/Category');
const jwt = require('jsonwebtoken');

let adminToken;
let categoryId;

describe('FAQ Routes', () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.MONGO_URI_TEST, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    // Create a content manager and get token
    const admin = new User({
      name: 'FAQ Manager',
      email: 'faqmanager@example.com',
      password: 'FAQP@ssw0rd',
      role: 'content-manager',
    });
    await admin.save();
    adminToken = jwt.sign(
      { id: admin._id, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Create a category
    const category = new Category({
      name: 'General',
      type: 'blog', // Assuming FAQs are linked to blog categories
    });
    await category.save();
    categoryId = category._id;
  });

  afterAll(async () => {
    await FAQ.deleteMany({});
    await Category.deleteMany({});
    await User.deleteMany({});
    await mongoose.connection.close();
  });

  describe('POST /api/faqs', () => {
    it('should create a new FAQ', async () => {
      const res = await request(app)
        .post('/api/faqs')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          question: 'How to reset my password?',
          answer: 'Click on the forgot password link and follow the instructions.',
          categories: [categoryId],
        });
      expect(res.statusCode).toEqual(201);
      expect(res.body.data).toHaveProperty('question', 'How to reset my password?');
    });

    it('should not create FAQ without required fields', async () => {
      const res = await request(app)
        .post('/api/faqs')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          answer: 'Missing question field.',
        });
      expect(res.statusCode).toEqual(422);
      expect(res.body.errors).toBeDefined();
    });
  });

  describe('GET /api/faqs', () => {
    beforeAll(async () => {
      // Create multiple FAQs
      await FAQ.create([
        {
          question: 'How to contact support?',
          answer: 'You can contact support via email or phone.',
          categories: [categoryId],
        },
        {
          question: 'What is the return policy?',
          answer: 'You can return products within 30 days of purchase.',
          categories: [categoryId],
        },
      ]);
    });

    it('should fetch all FAQs', async () => {
      const res = await request(app).get('/api/faqs');
      expect(res.statusCode).toEqual(200);
      expect(res.body.count).toBeGreaterThanOrEqual(2);
    });

    it('should fetch FAQs filtered by category', async () => {
      const res = await request(app).get('/api/faqs').query({ category: categoryId });
      expect(res.statusCode).toEqual(200);
      expect(res.body.data.every(faq => faq.categories.includes(String(categoryId)))).toBe(true);
    });
  });

  describe('GET /api/faqs/:id', () => {
    let faqId;
    beforeAll(async () => {
      const faq = await FAQ.create({
        question: 'How to track my order?',
        answer: 'Use the order tracking feature in your account dashboard.',
        categories: [categoryId],
      });
      faqId = faq._id;
    });

    it('should fetch an FAQ by ID', async () => {
      const res = await request(app).get(`/api/faqs/${faqId}`);
      expect(res.statusCode).toEqual(200);
      expect(res.body.data).toHaveProperty('question', 'How to track my order?');
    });

    it('should return 404 for non-existing FAQ', async () => {
      const res = await request(app).get(`/api/faqs/${mongoose.Types.ObjectId()}`);
      expect(res.statusCode).toEqual(404);
      expect(res.body.message).toBe('FAQ not found.');
    });
  });

  describe('PUT /api/faqs/:id', () => {
    let faqId;
    beforeAll(async () => {
      const faq = await FAQ.create({
        question: 'Initial Question',
        answer: 'Initial Answer.',
        categories: [categoryId],
      });
      faqId = faq._id;
    });

    it('should update an FAQ', async () => {
      const res = await request(app)
        .put(`/api/faqs/${faqId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          answer: 'Updated Answer.',
        });
      expect(res.statusCode).toEqual(200);
      expect(res.body.data).toHaveProperty('answer', 'Updated Answer.');
    });

    it('should return 404 for updating non-existing FAQ', async () => {
      const res = await request(app)
        .put(`/api/faqs/${mongoose.Types.ObjectId()}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          question: 'New Question',
        });
      expect(res.statusCode).toEqual(404);
      expect(res.body.message).toBe('FAQ not found.');
    });
  });

  describe('DELETE /api/faqs/:id', () => {
    let faqId;
    beforeAll(async () => {
      const faq = await FAQ.create({
        question: 'Delete this FAQ',
        answer: 'This FAQ will be deleted.',
        categories: [categoryId],
      });
      faqId = faq._id;
    });

    it('should delete an FAQ', async () => {
      const res = await request(app)
        .delete(`/api/faqs/${faqId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.statusCode).toEqual(200);
      expect(res.body.message).toBe('FAQ deleted successfully.');

      const faq = await FAQ.findById(faqId);
      expect(faq).toBeNull();
    });

    it('should return 404 for deleting non-existing FAQ', async () => {
      const res = await request(app)
        .delete(`/api/faqs/${mongoose.Types.ObjectId()}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.statusCode).toEqual(404);
      expect(res.body.message).toBe('FAQ not found.');
    });
  });
});
