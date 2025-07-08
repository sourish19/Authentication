import { Schema, model } from 'mongoose';
import bcrypt from 'bcrypt';
import crypto from 'crypto';

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
    // console.log('hashed - ', hashedPassword);
    user.password = hashedPassword;
    next();
  } catch (error) {
    console.error('Error occures in hashing password');
    next();
  }
});

userSchema.methods.comparePassword = async (newPassword) => {
  const isValidPass = await bcrypt.compare(newPassword, this.password);
  return isValidPass;
};

userSchema.methods.generateRandomHashedTokens = () => {
  const token = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
  const tokenExpiry = Date.now() + 1000 * 60 * 15; //15 min
  return { token, hashedToken, tokenExpiry };
};

const User = model('User', userSchema);

export default User;
