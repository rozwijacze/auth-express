const express = require('express');
const { register, login, refreshToken } = require('../controllers/authController');

const router = express.Router();

router.post(`/register`, register);
router.post(`/login`, login);
router.post(`/refresh`, refreshToken);

module.exports = router;
