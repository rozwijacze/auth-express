const { generateTokens, generateAccessToken } = require('../helpers/helpers');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const Logger = require('../utils/Logger');

const register = async (req, res) => {
  try {
    const { accountName, password } = req.body;

    const userExists = await User.findOne({ accountName });

    if (userExists) {
      return res.status(400).json({ message: 'Accountname already registered' });
    }

    const usersCount = await User.countDocuments();
    const role = usersCount === 0 ? 'admin' : 'user';
    const user = new User({ accountName, password, role });
    await user.save();
    const { accessToken, refreshTokenData } = generateTokens(req, res, user);
    await addTokenToDB(user._id, refreshTokenData);

    return res.status(201).json({ accessToken });
  } catch (err) {
    return res.status(500).json({ message: 'Server error' });
  }
};

const login = async (req, res) => {
  try {
    const { accountName, password } = req.body;

    const user = await User.findOne({ accountName });

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
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
    return res.status(400).json({ message: 'No refresh token provided.' });
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
    clearAllTokens();
    return res.status(200).json({ message: 'Logged out.' });
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ message: 'Refresh token expired.' });
    } else if (err instanceof jwt.JsonWebTokenError) {
      return res.status(400).json({ message: 'Invalid refresh token.' });
    } else {
      return res.status(500).json({ message: 'Server error.' });
    }
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

const clearAllTokens = () => {
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

module.exports = { register, login, refreshToken, logout };
