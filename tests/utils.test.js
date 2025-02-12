// tests/utils.test.js
const { hashPassword, verifyPassword, encrypt, decrypt } = require('../utils/cryptoUtils');
const jwt = require('jsonwebtoken');

describe('Utility Functions', () => {
  describe('Password Hashing', () => {
    it('should hash and verify password correctly', () => {
      const password = 'SecureP@ssw0rd';
      const hashed = hashPassword(password);
      const isValid = verifyPassword(password, hashed);
      expect(isValid).toBe(true);
    });

    it('should fail verification with incorrect password', () => {
      const password = 'SecureP@ssw0rd';
      const wrongPassword = 'WrongP@ssw0rd';
      const hashed = hashPassword(password);
      const isValid = verifyPassword(wrongPassword, hashed);
      expect(isValid).toBe(false);
    });
  });

  describe('Encryption and Decryption', () => {
    beforeAll(() => {
      // Set encryption key and IV for testing
      process.env.ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // 64 hex chars
      process.env.IV = 'abcdef0123456789abcdef0123456789'; // 32 hex chars
    });

    it('should encrypt and decrypt text correctly', () => {
      const text = 'Sensitive Information';
      const encrypted = encrypt(text);
      const decrypted = decrypt(encrypted);
      expect(decrypted).toBe(text);
    });

    it('should not decrypt with incorrect encrypted text', () => {
      const encrypted = 'invalidencryptedtext';
      expect(() => decrypt(encrypted)).toThrow();
    });
  });

  describe('JWT Token Generation', () => {
    it('should generate and verify access token', () => {
      const payload = { id: 'user123', role: 'user' };
      const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      expect(decoded.id).toBe('user123');
      expect(decoded.role).toBe('user');
    });

    it('should fail verification with invalid token', () => {
      const invalidToken = 'invalid.token.here';
      expect(() => jwt.verify(invalidToken, process.env.JWT_SECRET)).toThrow();
    });
  });
});
