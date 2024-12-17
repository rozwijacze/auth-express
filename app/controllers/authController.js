const { generateTokens, generateAccessToken } = require('../helpers/tokenHelpers');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const Logger = require('../utils/Logger');
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const register = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const userExists = await User.findOne({ email });

    if (userExists) {
      return res.status(400).json({ message: 'Email already registered' });
    }


    const user = new User({ email, password, role: 'user' });

    try {
      await generateEmailVerificationLink(email);
      await user.save();
    } catch (validationError) {
      if (validationError.name === 'ValidationError') {
        const errors = Object.values(validationError.errors).map((err) => err.message);
        return res.status(400).json({
          message: 'Validation failed',
          errors: errors,
        });
      }

      if (validationError.code === 11000) {
        return res.status(400).json({
          message: 'A user with this email already exists',
        });
      }

      return res.status(500).json({
        message: 'Error creating user',
        error: validationError.message,
      });
    }

    return res.status(201).json({ message: 'User registered in database.' });
  } catch (err) {
    return res.status(500).json({
      message: 'Server error during registration',
      error: err.message,
    });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      return res.status(403).json({
        status: 'unverified',
        message: 'Email not verified',
      });
    }

    const { accessToken, refreshTokenData } = generateTokens(req, res, user);
    await addTokenToDB(user._id, refreshTokenData);

    return res.status(200).json({ accessToken });
  } catch (err) {
    return res.status(500).json({ message: 'Server error' });
  }
};

const refreshToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  const deviceInfo = req.headers['user-agent'];

  if (!refreshToken) {
    return res.status(401).json({ message: 'Refresh token not provided' });
  }

  try {
    const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(payload.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const tokenIndex = user.refreshTokens.findIndex((t) => t.token === refreshToken && t.deviceInfo === deviceInfo);

    if (tokenIndex === -1) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    const accessToken = generateAccessToken(user);
    await user.save();
    await removeExpiredTokens(user._id);

    return res.status(200).json({ accessToken });
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ message: 'Refresh token expired' });
    }
    if (err instanceof jwt.JsonWebTokenError) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }
    return res.status(500).json({ message: 'Server error' });
  }
};

const logout = async (req, res) => {
  const refreshTokenToInvalidate = req.cookies.refreshToken;

  if (!refreshTokenToInvalidate) {
    clearAllTokens(res);
    return res.status(200).json({ message: 'Logged out.' });
  }

  try {
    const payload = jwt.verify(refreshTokenToInvalidate, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findOneAndUpdate(
      { _id: payload.userId },
      { $pull: { refreshTokens: { token: refreshTokenToInvalidate } } },
      { new: true },
    );

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    clearAllTokens(res);
    return res.status(200).json({ message: 'Logged out.' });
  } catch (err) {
    clearAllTokens(res);
    if (err instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ message: 'Refresh token expired.' });
    } else if (err instanceof jwt.JsonWebTokenError) {
      return res.status(400).json({ message: 'Invalid refresh token.' });
    } else {
      return res.status(500).json({ message: 'Server error on logout.' });
    }
  }
};

const requestPasswordReset = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) return res.status(400).json({ message: 'User with that email cannot be found' });

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'No account with this email exists' });
    }

    if (!user.isVerified) {
      return res.status(403).json({
        message: 'Please verify your email before requesting password reset link',
      });
    }

    const resetToken = jwt.sign(
      {
        email: user.email,
      },
      process.env.RESET_PASSWORD_TOKEN_SECRET,
      { expiresIn: '30m' },
    );

    const appBaseUrl = process.env.FRONTEND_BASE_URL;
    const resetEndpoint = '/password-reset';

    const resetLink = `${appBaseUrl}${resetEndpoint}/${resetToken}`;

    await transporter
      .sendMail({
        to: email,
        subject: `${process.env.APP_NAME} - Password Reset`,
        html: `<div>Here is your password reset link: <a href="${resetLink}">CLICK</a></div>`,
      })
      .then(() => {
        Logger.info(`Reset Password Link sent to: ${email}`);
      })
      .catch((err) => {
        console.error(err);
      });

    return res.status(200).json({ message: 'Password reset link has been sent to your email' });
  } catch (error) {
    return res.status(500).json({ message: 'Internal server error while sending resetting password request' });
  }
};

const requestEmailVerificationLink = async (req, res) => {
  try {
    const { email } = req.body;

    await generateEmailVerificationLink(email);
    return res.status(200).json({ message: 'Email verification link sent on provided email.' });
  } catch (error) {
    return res.status(500).json({ message: 'Server error while requesting email verification link' });
  }
};

const verifyEmail = async (req, res) => {
  try {
    const { token } = req.body;

    const payload = jwt.verify(token, process.env.VERIFY_EMAIL_TOKEN_SECRET);

    const { email } = payload;

    const user = await User.findOne({ email });

    if (!user) return res.status(400).json({ message: 'Invalid link' });

    if (user.isVerified) return res.status(200).send({ message: 'User is already verified.' });
    await User.findByIdAndUpdate(user._id, { isVerified: true });

    const { accessToken, refreshTokenData } = generateTokens(req, res, user);
    await addTokenToDB(user._id, refreshTokenData);

    return res.status(200).json({ message: 'User has been verified.', accessToken });
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(400).json({ message: 'Invalid token' });
    }

    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ message: 'Token has expired' });
    }

    return res.status(500).json({ message: 'Internal server error while verifing email.' });
  }
};

const passwordReset = async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const decoded = jwt.verify(token, process.env.RESET_PASSWORD_TOKEN_SECRET);

    const user = await User.findOne({ email: decoded.email });

    if (!user) return res.status(400).json({ message: 'Invalid link' });

    if (!user.isVerified) {
      return res.status(403).json({
        message: 'Please verify your email before resetting password',
      });
    }

    user.password = newPassword;
    await user.save();

    return res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(400).json({ message: 'Invalid token' });
    }

    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ message: 'Token has expired' });
    }

    return res.status(500).json({ message: 'Server error' });
  }
};

const generateEmailVerificationLink = async (email) => {
  try {
    const baseUrl = process.env.FRONTEND_BASE_URL;
    const verificationPath = '/verify';

    const verificationToken = jwt.sign(
      {
        email,
      },
      process.env.VERIFY_EMAIL_TOKEN_SECRET,
      { expiresIn: '24h' },
    );

    const verificationLink = `${baseUrl}${verificationPath}/${verificationToken}`;

    await transporter
      .sendMail({
        to: email,
        subject: `${process.env.APP_NAME} - Email Verification`,
        html: `<div>Here is your verification link: <a href="${verificationLink}">CLICK</a></div>`,
      })
      .then(() => {
        Logger.info(`Email Verification Link sent to: ${email}`);
      })
      .catch((err) => {
        console.error('Error during sending email: ' + err);
      });
  } catch (error) {
    return res.status(500).json({ message: 'Server error while generating email verification link.' });
  }
};

const addTokenToDB = async (userId, refreshTokenData) => {
  const result = await User.updateOne({ _id: userId }, { $push: { refreshTokens: refreshTokenData } });
  result.modifiedCount > 0 ? Logger.info('Token successfully added') : Logger.warn('User not found or token not added');
};

const removeExpiredTokens = async (userId) => {
  await User.updateOne({ _id: userId }, { $pull: { refreshTokens: { expiresAt: { $lt: new Date() } } } });

  Logger.info('Expired tokens deleted');
};

const clearAllTokens = (res) => {
  res.clearCookie('accessToken', {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
  Logger.info('Access and refresh tokens removed from cookies');
};

module.exports = {
  register,
  login,
  refreshToken,
  logout,
  requestPasswordReset,
  requestEmailVerificationLink,
  verifyEmail,
  passwordReset,
};
