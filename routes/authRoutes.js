const express = require('express');
const {
  register,
  login,
  refreshToken,
  logout,
  requestPasswordReset,
  requestEmailVerificationLink,
  verifyEmail,
  passwordReset,
} = require('../controllers/authController');
const router = express.Router();

router.post(`/register`, register);
router.post(`/login`, login);
router.post(`/refresh`, refreshToken);
router.post(`/logout`, logout);
router.post(`/email-verify-link`, requestEmailVerificationLink);
router.post(`/email-verify`, verifyEmail);
router.post(`/password-reset-link`, requestPasswordReset);
router.post(`/password-reset`, passwordReset);

module.exports = router;
