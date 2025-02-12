// routes/contactRoutes.js

const express = require('express');
const { submitContactMessage } = require('../controllers/ContactController');

const router = express.Router();

// Submit contact message (Public)
router.post('/', submitContactMessage);

module.exports = router;
