const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address'],
      maxlength: 48,
      minlength: 7,
    },
    password: {
      type: String,
      required: true,
      minlength: 7,
      maxlength: 64,
    },
    role: {
      type: String,
      enum: ['user', 'editor', 'admin'],
      default: 'user',
    },
    refreshTokens: [
      {
        token: String,
        deviceInfo: String,
        expiresAt: Date,
        createdAt: Date,
      },
    ],
    isVerified: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true },
);

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, process.env.SALT);
  next();
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
