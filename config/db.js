const mongoose = require('mongoose');
const User = require('../models/User');
require('dotenv').config();

const connectDb = async () => {
  try {
    await mongoose.connection.useDb('users-db');
    await mongoose.connect(process.env.MONGO_URI);

    console.log('Connected to MongoDB');
  } catch (err) {
    console.error('MongoDB connection error:', err);
  }
};

module.exports = connectDb;
