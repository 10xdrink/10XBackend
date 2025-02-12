// tests/auth.test.js
const request = require('supertest');
const app = require('../app'); // Ensure your Express app is exported from app.js
const mongoose = require('mongoose');
const User = require('../models/User');
const jwt = require('jsonwebtoken');

describe('Authentication Routes', () => {
  beforeAll(async () => {
    // Connect to a test database
    await mongoose.connect(process.env.MONGO_URI_TEST, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
  });

  afterAll(async () => {
    // Clean up the database and close the connection
    await User.deleteMany({});
    await mongoose.connection.close();
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Test User',
          email: 'testuser@example.com',
          password: 'StrongP@ssw0rd',
          role: 'user',
        });
      expect(res.statusCode).toEqual(201);
      expect(res.body).toHaveProperty('token');
    });

    it('should not register a user with existing email', async () => {
      // First registration
      await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Test User',
          email: 'duplicate@example.com',
          password: 'StrongP@ssw0rd',
        });

      // Attempt duplicate registration
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Another User',
          email: 'duplicate@example.com',
          password: 'AnotherP@ssw0rd',
        });
      expect(res.statusCode).toEqual(400);
      expect(res.body.message).toBe('User already exists');
    });
  });

  describe('POST /api/auth/login', () => {
    beforeAll(async () => {
      // Create a user to login
      const user = new User({
        name: 'Login User',
        email: 'loginuser@example.com',
        password: 'HashedP@ssw0rd', // Ensure password is hashed
      });
      await user.save();
    });

    it('should login an existing user', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'loginuser@example.com',
          password: 'HashedP@ssw0rd', // Replace with plain password if hashing is handled in controller
        });
      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty('token');
    });

    it('should not login with incorrect password', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'loginuser@example.com',
          password: 'WrongPassword',
        });
      expect(res.statusCode).toEqual(401);
      expect(res.body.message).toBe('Invalid email or password.');
    });

    it('should not login non-existing user', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexisting@example.com',
          password: 'SomePassword',
        });
      expect(res.statusCode).toEqual(401);
      expect(res.body.message).toBe('Invalid email or password.');
    });
  });

  describe('GET /api/auth/me', () => {
    let token;
    beforeAll(async () => {
      // Register and login to get a token
      await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Me User',
          email: 'meuser@example.com',
          password: 'StrongP@ssw0rd',
        });
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'meuser@example.com',
          password: 'StrongP@ssw0rd',
        });
      token = res.body.token;
    });

    it('should get the current logged-in user', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${token}`);
      expect(res.statusCode).toEqual(200);
      expect(res.body.data).toHaveProperty('email', 'meuser@example.com');
    });

    it('should not get user without token', async () => {
      const res = await request(app).get('/api/auth/me');
      expect(res.statusCode).toEqual(401);
      expect(res.body.message).toBe('Unauthorized access.');
    });
  });
});
