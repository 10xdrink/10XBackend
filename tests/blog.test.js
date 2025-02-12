// tests/blog.test.js
const request = require('supertest');
const app = require('../app');
const mongoose = require('mongoose');
const BlogPost = require('../models/BlogPost');
const User = require('../models/User');
const Category = require('../models/Category');
const jwt = require('jsonwebtoken');

let adminToken;
let categoryId;

describe('Blog Routes', () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.MONGO_URI_TEST, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    // Create a content manager and get token
    const admin = new User({
      name: 'Content Manager',
      email: 'contentmanager@example.com',
      password: 'ContentP@ssw0rd',
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
      name: 'Tech',
      type: 'blog',
    });
    await category.save();
    categoryId = category._id;
  });

  afterAll(async () => {
    await BlogPost.deleteMany({});
    await Category.deleteMany({});
    await User.deleteMany({});
    await mongoose.connection.close();
  });

  describe('POST /api/blogs', () => {
    it('should create a new blog post', async () => {
      const res = await request(app)
        .post('/api/blogs')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          title: 'Test Blog Post',
          content: 'This is a test blog post content.',
          categories: [categoryId],
          tags: [],
          status: 'published',
        });
      expect(res.statusCode).toEqual(201);
      expect(res.body.data).toHaveProperty('title', 'Test Blog Post');
    });

    it('should not create a blog post without required fields', async () => {
      const res = await request(app)
        .post('/api/blogs')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          content: 'Missing title.',
        });
      expect(res.statusCode).toEqual(422);
      expect(res.body.errors).toBeDefined();
    });
  });

  describe('GET /api/blogs', () => {
    beforeAll(async () => {
      // Create multiple blog posts
      await BlogPost.create([
        {
          title: 'Blog Post 1',
          content: 'Content for blog post 1.',
          categories: [categoryId],
          tags: [],
          status: 'published',
          author: mongoose.Types.ObjectId(),
        },
        {
          title: 'Blog Post 2',
          content: 'Content for blog post 2.',
          categories: [categoryId],
          tags: [],
          status: 'draft',
          author: mongoose.Types.ObjectId(),
        },
      ]);
    });

    it('should fetch all blog posts', async () => {
      const res = await request(app).get('/api/blogs');
      expect(res.statusCode).toEqual(200);
      expect(res.body.count).toBeGreaterThanOrEqual(2);
    });

    it('should fetch published blog posts only', async () => {
      const res = await request(app).get('/api/blogs').query({ status: 'published' });
      expect(res.statusCode).toEqual(200);
      expect(res.body.data.every(post => post.status === 'published')).toBe(true);
    });
  });

  describe('GET /api/blogs/:id', () => {
    let blogId;
    beforeAll(async () => {
      const blog = await BlogPost.create({
        title: 'Specific Blog Post',
        content: 'Specific blog post content.',
        categories: [categoryId],
        tags: [],
        status: 'published',
        author: mongoose.Types.ObjectId(),
      });
      blogId = blog._id;
    });

    it('should fetch a blog post by ID', async () => {
      const res = await request(app).get(`/api/blogs/${blogId}`);
      expect(res.statusCode).toEqual(200);
      expect(res.body.data).toHaveProperty('title', 'Specific Blog Post');
    });

    it('should return 404 for non-existing blog post', async () => {
      const res = await request(app).get(`/api/blogs/${mongoose.Types.ObjectId()}`);
      expect(res.statusCode).toEqual(404);
      expect(res.body.message).toBe('Blog post not found.');
    });
  });

  describe('PUT /api/blogs/:id', () => {
    let blogId;
    beforeAll(async () => {
      const blog = await BlogPost.create({
        title: 'Update Blog Post',
        content: 'Initial content.',
        categories: [categoryId],
        tags: [],
        status: 'draft',
        author: mongoose.Types.ObjectId(),
      });
      blogId = blog._id;
    });

    it('should update a blog post', async () => {
      const res = await request(app)
        .put(`/api/blogs/${blogId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          content: 'Updated content.',
          status: 'published',
        });
      expect(res.statusCode).toEqual(200);
      expect(res.body.data).toHaveProperty('content', 'Updated content.');
      expect(res.body.data).toHaveProperty('status', 'published');
    });

    it('should return 404 for updating non-existing blog post', async () => {
      const res = await request(app)
        .put(`/api/blogs/${mongoose.Types.ObjectId()}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          title: 'Non-existing Blog',
        });
      expect(res.statusCode).toEqual(404);
      expect(res.body.message).toBe('Blog post not found.');
    });
  });

  describe('DELETE /api/blogs/:id', () => {
    let blogId;
    beforeAll(async () => {
      const blog = await BlogPost.create({
        title: 'Delete Blog Post',
        content: 'Content to be deleted.',
        categories: [categoryId],
        tags: [],
        status: 'published',
        author: mongoose.Types.ObjectId(),
      });
      blogId = blog._id;
    });

    it('should delete a blog post', async () => {
      const res = await request(app)
        .delete(`/api/blogs/${blogId}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.statusCode).toEqual(200);
      expect(res.body.message).toBe('Blog post deleted successfully.');

      const blog = await BlogPost.findById(blogId);
      expect(blog).toBeNull();
    });

    it('should return 404 for deleting non-existing blog post', async () => {
      const res = await request(app)
        .delete(`/api/blogs/${mongoose.Types.ObjectId()}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(res.statusCode).toEqual(404);
      expect(res.body.message).toBe('Blog post not found.');
    });
  });
});
