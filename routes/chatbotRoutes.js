// routes/chatbotRoutes.js

const express = require('express');
const router = express.Router();
const { submitForm } = require('../controllers/chatbotController');

router.post('/submit', submitForm);

module.exports = router;
