const jwt = require('jsonwebtoken');

const generateTokens = (req, res, user) => {
  const accessToken = generateAccessToken(user);
  const { refreshToken, refreshTokenData } = generateRefreshToken(req, res, user);
  return { accessToken, refreshToken, refreshTokenData };
};

const generateAccessToken = (user) => {
  const accessToken = jwt.sign(
    { userId: user._id, role: user.role, accountName: user.accountName },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: '30m',
    },
  );
  return accessToken;
};

const generateRefreshToken = (req, res, user) => {

  const refreshToken = jwt.sign({ userId: user._id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });

  const refreshTokenData = {
    token: refreshToken,
    deviceInfo: req.headers['user-agent'],
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    createdAt: new Date(),
  };

  return { refreshToken, refreshTokenData };
};

module.exports = { generateTokens, generateAccessToken, generateRefreshToken };
