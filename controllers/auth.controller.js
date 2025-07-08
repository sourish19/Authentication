import crypto from 'crypto';

import User from '../models/auth.model.js';
import ApiResponse from '../utils/apiResponse.utils.js';
import ApiError from '../utils/apiError.utils.js';
import asyncHandler from '../utils/asyncHandler.utils.js';
import {
  sendEmail,
  emailVerificationMailgenContent,
} from '../utils/mail.utils.js';

const registerUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;

  const findUser = await User.findOne({ $or: [{ username }, { email }] });

  if (findUser)
    throw new ApiError([{ username, email }], 'User already registered', 422);

  const newUser = await User.create({
    username,
    email,
    password,
  });

  const { token, hashedToken, tokenExpiry } =
    newUser.generateRandomHashedTokens();

  newUser.emailVerificationToken = hashedToken;
  newUser.emailVerificationTokenExpiry = tokenExpiry;

  await sendEmail({
    email: newUser?.email,
    subject: 'Please verify your email',
    mailgenContent: emailVerificationMailgenContent(
      newUser?.username,
      `${process.env.BASE_URL_WSL}user/verify-email/${token}`
    ),
  });

  await newUser.save();

  const createdUser = await User.findById(newUser._id).select(
    '-password -refreshToken -isEmailValid -emailVerificationToken -emailVerificationTokenExpiry'
  );

  if (!createdUser)
    // return res
    //   .status(400)
    //   .json(
    //     new ApiError([], 'Error occured during new user registration', 400)
    //   );
    throw new ApiError([], 'Error occured during new user registration', 400);

  return res.status(200).json(
    new ApiResponse(200, 'User Created Successfully & Email sent', {
      username: username,
      email: email,
    })
  );
});

const verifyEmail = asyncHandler(async (req, res) => {
  const { token } = req.params;

  if (!token) throw new ApiError([], 'Token is not there!', 400);

  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationTokenExpiry: { $gt: Date.now() },
  });

  if (!user) throw new ApiError([], 'Token is invalid!', 400);

  user.isEmailValid = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationTokenExpiry = undefined;

  await user.save();

  const createdUser = await User.findById(user._id).select(
    '-password -refreshToken '
  );

  return res.status(200).json(
    new ApiResponse(200, 'User Verified Successfully', {
      username: createdUser.username,
      email: createdUser.email,
      verified: createdUser.isEmailValid,
    })
  );
});

const loginUser = () => {};

export { registerUser, verifyEmail };
