const User = require('../models/User');
const jwt = require('jsonwebtoken');

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

    const { accessToken, refreshToken } = generateTokens(user);

    return res.status(201).json({ accessToken, refreshToken });
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

    const { accessToken, refreshToken } = generateTokens(user);

    return res.status(200).json({ accessToken, refreshToken });
  } catch (err) {
    return res.status(500).json({ message: 'Server error' });
  }
};

const generateTokens = (user) => {
  const accessToken = jwt.sign({ userId: user._id, role: user.role, accountName: user.accountName }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: '30m',
  });

  const refreshToken = jwt.sign({ userId: user._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

  return { accessToken, refreshToken };
};

const refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token is required' });
    }

    const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(payload.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const { accessToken: newAccessToken, refreshToken: newRefreshToken } = generateTokens(user);

    return res.status(200).json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
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

module.exports = { register, login, refreshToken };
