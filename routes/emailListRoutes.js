// routes/emailListRoutes.js

const express = require('express');
const router = express.Router();
const { addSubscriber } = require('../controllers/emailListController');

router.post('/', addSubscriber);

module.exports = router;
