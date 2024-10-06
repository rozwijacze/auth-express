const express = require('express');
const { register, login, refreshToken, logout } = require('../controllers/authController');
const { auth } = require('../middlewares/authMiddleware');
const router = express.Router();

router.post(`/register`, register);
router.post(`/login`, login);
router.post(`/refresh`, refreshToken);
router.post(`/logout`, logout);

module.exports = router;
