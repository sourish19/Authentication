import { Schema, model } from 'mongoose';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

import { REFRESH_TOKEN, ACCESS_TOKEN } from '../utils/constants.utils.js';
import ApiError from '../utils/apiError.utils.js';

const userSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      unique: true,
    },
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    isEmailValid: {
      type: Boolean,
      default: false,
    },
    emailVerificationToken: {
      type: String,
    },
    emailVerificationTokenExpiry: {
      type: String,
    },
    resetPasswordToken: {
      type: String,
    },
    resetPasswordTokenExpiry: {
      type: String,
    },
    refreshToken: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);

userSchema.pre('save', async function (next) {
  const user = this;
  if (!user.isModified('password')) return next();
  try {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    user.password = hashedPassword;
    next();
  } catch (error) {
    console.error('Error occures in hashing password');
    next();
  }
});

userSchema.methods.comparePassword = async function (newPassword) {
  try {
    console.log('Pass-', newPassword);
    const user = this;
    const isValidPass = await bcrypt.compare(newPassword, user.password);
    return isValidPass;
  } catch (error) {
    throw new ApiError(error, 'Error comparing passwords', 500);
  }
};

userSchema.methods.generateRandomHashedTokens = () => {
  const token = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  const tokenExpiry = Date.now() + 1000 * 60 * 15; //15 min
  return { token, hashedToken, tokenExpiry };
};

userSchema.methods.generateAccessToken = async function () {
  try {
    const user = this;

    const accessToken = jwt.sign(
      {
        id: user._id,
        username: user.username,
        email: user.email,
      },
      ACCESS_TOKEN.secret,
      { expiresIn: ACCESS_TOKEN.expiry }
    );

    return accessToken;
  } catch (error) {
    throw new ApiError(error, 'Error creating Access Token Token', 500);
  }
};

userSchema.methods.generateRefreshToken = async function () {
  try {
    const user = this;

    const refreshToken = jwt.sign(
      {
        id: user._id,
      },
      REFRESH_TOKEN.secret,
      { expiresIn: REFRESH_TOKEN.expiry }
    );

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    user.refreshToken = hashedRefreshToken;

    return refreshToken;
  } catch (error) {
    throw new ApiError(error, 'Error creating Refresh Token', 500);
  }
};

const User = model('User', userSchema);

export default User;
