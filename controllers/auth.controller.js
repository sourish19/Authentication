import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

import User from '../models/auth.model.js';
import ApiResponse from '../utils/apiResponse.utils.js';
import ApiError from '../utils/apiError.utils.js';
import asyncHandler from '../utils/asyncHandler.utils.js';
import { REFRESH_TOKEN } from '../utils/constants.utils.js';
import {
  sendEmail,
  emailVerificationMailgenContent,
  resetPasswordMailgenContent,
} from '../utils/mail.utils.js';

const cookiesOption = {
  options: {
    sameSite: 'strict',
    secure: false,
    httpOnly: true,
    path: '/',
    maxAge: 24 * 60 * 60 * 1000,
  },
};

const generateRefreshAccessToken = async (user) => {
  const refreshToken = await user.generateRefreshToken();
  const accessToken = await user.generateAccessToken();

  await user.save({ validateBeforeSave: false });

  return { accessToken, refreshToken };
};

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
    '-password -refreshToken -isEmailValid -emailVerificationToken -emailVerificationTokenExpiry -resetPasswordToken -resetPasswordTokenExpiry'
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

  if (!token) throw new ApiError([], 'Token not found!', 400);

  const hashedToken = crypto.createHash('sha256').update(token).digest('hex'); // same token generates same hash

  // Checks both the condition
  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationTokenExpiry: { $gt: Date.now() },
  }).select(
    '-password -refreshToken -resetPasswordToken -resetPasswordTokenExpiry'
  );

  if (!user) throw new ApiError([], 'User not found!', 400);

  if (user.isEmailValid)
    throw new ApiError([], 'Email is already verified!', 200);

  user.isEmailValid = true;
  user.emailVerificationToken = undefined;
  user.emailVerificationTokenExpiry = undefined;

  //   validateBeforeSave: false ➝ Skips validation on required fields like password, email
  //   Use this when we only want to update non-critical fields like tokens,flags,timestamps
  await user.save({ validateBeforeSave: false });

  const createdUser = await User.findById(user._id).select(
    '-password -refreshToken -resetPasswordToken -resetPasswordTokenExpiry -emailVerificationToken -emailVerificationTokenExpiry'
  );

  return res.status(200).json(
    new ApiResponse(200, 'User Verified Successfully', {
      username: createdUser.username,
      email: createdUser.email,
      verified: createdUser.isEmailValid,
    })
  );
});

const loginUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;

  const user = await User.findOne({ $or: [{ username }, { email }] }).select(
    '-isEmailValid -emailVerificationToken -emailVerificationTokenExpiry -resetPasswordToken -resetPasswordTokenExpiry'
  );

  if (!user)
    throw new ApiError([{ username, email }], 'User not registered', 422);

  if (user.refreshToken)
    throw new ApiError([{ username, email }], 'User already logedin', 422);

  const validPassword = await user.comparePassword(password);

  if (!validPassword)
    throw new ApiError(
      [{ username, email }],
      `Password & email dosen't match `,
      422
    );

  const { accessToken, refreshToken } = await generateRefreshAccessToken(user);

  const logedInUser = await User.findById(user._id).select(
    '-password -refreshToken -isEmailValid -emailVerificationToken -emailVerificationTokenExpiry -resetPasswordToken -resetPasswordTokenExpiry'
  );

  res
    .cookie('refreshToken', refreshToken, cookiesOption.options)
    .cookie('accessToken', accessToken, cookiesOption.options)
    .status(200)
    .json(
      new ApiResponse(200, 'User Logedin Successfully', {
        username: logedInUser.username,
        email: logedInUser.email,
      })
    );
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incommingRefreshToken = req.cookies?.refreshToken;

  if (!incommingRefreshToken)
    throw new ApiError([], 'Unauthorized request - User not logedin', 401);

  try {
    const decode = jwt.verify(incommingRefreshToken, REFRESH_TOKEN.secret);

    if (!decode) throw new ApiError([], 'Unauthorized request', 401);

    const user = await User.findById(decode.id);

    if (!user)
      throw new ApiError(
        [],
        'Unauthorized request - Invalid Refresh Token',
        401
      );

    const hashedRefToken = bcrypt.compare(
      incommingRefreshToken,
      user?.refreshToken
    );

    if (!hashedRefToken) throw new ApiError([], 'Invalid Refresh Token', 401);

    const { accessToken, refreshToken } =
      await generateRefreshAccessToken(user);

    res
      .status(200)
      .cookie('accessToken', accessToken, cookiesOption.options)
      .cookie('refreshToken', refreshToken, cookiesOption.options)
      .json(
        new ApiResponse(200, 'Successfully generated Refresh & Access token')
      );
  } catch (error) {
    throw new ApiError(
      error || [],
      error?.message || 'Expired Refresh Token',
      401
    );
  }
});

const logoutUser = asyncHandler(async (req, res) => {
  const user = req.user;

  const findUser = await User.findById(user.id).select(
    '-password -isEmailValid -emailVerificationToken -emailVerificationTokenExpiry -resetPasswordToken -resetPasswordTokenExpiry'
  );

  if (!findUser)
    throw new ApiError([], 'Unauthorized request - User not logedin', 401);

  findUser.refreshToken = undefined;

  await findUser.save({ validateBeforeSave: false });

  res.clearCookie('accessToken', cookiesOption.options);
  res.clearCookie('refreshToken', cookiesOption.options);

  res.status(200).json(new ApiResponse(200, 'User Logout successfully'));
});

const userProfile = asyncHandler(async (req, res) => {
  const user = req.user;

  const findUser = await User.findById(user.id).select(
    '-password -refreshToken -isEmailValid -emailVerificationToken -emailVerificationTokenExpiry -resetPasswordToken -resetPasswordTokenExpiry'
  );

  if (!findUser)
    throw new ApiError(error || [], error?.message || 'User not Found', 401);

  res.status(200).json(
    new ApiResponse(200, 'User profile', {
      username: findUser.username,
      email: findUser.email,
    })
  );
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const decodedUser = req.user;

  const { old_password, new_password, confirm_new_password } = req.body;

  const user = await User.findById(decodedUser.id).select(
    '-refreshToken -isEmailValid -emailVerificationToken -emailVerificationTokenExpiry -resetPasswordToken -resetPasswordTokenExpiry'
  );

  if (!user) throw new ApiError([], 'User not Found', 400);

  const validPassword = await user.comparePassword(old_password);

  console.log(validPassword);

  if (!validPassword) throw new ApiError([], 'Invalid Old Password', 400);

  // assign new password in plain text
  // We have a pre save method attached to user schema which automatically hashes the password whenever added/modified
  user.password = confirm_new_password;

  await user.save({ validateBeforeSave: false });

  res
    .status(201)
    .json(new ApiResponse(201, 'Password Change Successfully', []));
});

const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email }).select(
    '-password -refreshToken -emailVerificationToken -emailVerificationTokenExpiry'
  );

  if (!user) throw new ApiError([], 'User not found', 401);

  if (!user.isEmailValid) throw new ApiError([], 'Email is not verified', 401);

  // Here Frontend will redirect user to resend-email-verification route
  // from there backend will verify email and redirect again to forgot-password route

  const { token, hashedToken, tokenExpiry } = user.generateRandomHashedTokens();

  user.resetPasswordToken = hashedToken;
  user.resetPasswordTokenExpiry = tokenExpiry;

  await sendEmail({
    email: user?.email,
    subject: 'We Received a Request to Reset Your Password',
    mailgenContent: resetPasswordMailgenContent(
      user?.username,
      `${process.env.BASE_URL_WSL}user/reset-password/${token}`
    ),
  });

  await user.save({ validateBeforeSave: false });

  res
    .status(200)
    .json(
      new ApiResponse(200, 'Mail Sent for Reset Password', { email: email })
    );
});

const resetPassword = asyncHandler(async (req, res) => {
  const { resetPasswordToken } = req.params;
  const { confirm_new_password } = req.body;

  if (!resetPasswordToken) throw new ApiError([], 'Token Not Found', 400);

  const hashedResetPasswordToken = crypto
    .createHash('sha256')
    .update(resetPasswordToken)
    .digest('hex');

  const user = await User.findOne({
    resetPasswordToken: hashedResetPasswordToken,
    resetPasswordTokenExpiry: { $gt: Date.now() },
  }).select(
    '-password -refreshToken -isEmailValid -emailVerificationToken -emailVerificationTokenExpiry'
  );

  if (!user) throw new ApiError([], 'Invalid or expired token', 400);

  user.password = confirm_new_password;
  user.resetPasswordToken = undefined;
  user.resetPasswordTokenExpiry = undefined;

  await user.save();

  const updatedUser = await User.findById(user._id).select(
    '-password -refreshToken -isEmailValid -emailVerificationToken -emailVerificationTokenExpiry -resetPasswordToken -resetPasswordTokenExpiry'
  );

  res.status(200).json(
    new ApiResponse(200, 'Password reset successfully', {
      username: updatedUser.username,
      email: updatedUser.email,
    })
  );
});

const resendEmailVerification = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email }).select(
    '-password -refreshToken -resetPasswordToken -resetPasswordTokenExpiry'
  );

  if (!user) throw new ApiError([], 'nvalid or expired token', 400);

  if (user.isEmailValid)
    throw new ApiError([], 'User email already verified', 400);

  const { token, hashedToken, tokenExpiry } = user.generateRandomHashedTokens();

  user.emailVerificationToken = hashedToken;
  user.emailVerificationTokenExpiry = tokenExpiry;

  await sendEmail({
    email: user?.email,
    subject: 'Please verify your email',
    mailgenContent: emailVerificationMailgenContent(
      user?.username,
      `${process.env.BASE_URL_WSL}user/verify-email/${token}`
    ),
  });
  //   validateModifiedOnly: true ➝ Validates only the fields that were changed, not the entire document
  //   Use this for partial updates (e.g., profile edits) to improve performance and avoid unnecessary validation
  //   In this case i dont need this but for future refrence just adding this part
  await user.save({ validateModifiedOnly: true });

  return res.status(200).json(
    new ApiResponse(200, 'Verification Email Sent Successfully', {
      email: email,
    })
  );
});

export {
  registerUser,
  verifyEmail,
  loginUser,
  logoutUser,
  refreshAccessToken,
  userProfile,
  resetPassword,
  forgotPassword,
  changeCurrentPassword,
  resendEmailVerification,
};

//https://dev.to/smitterhane/a-meticulous-jwt-api-authentication-guide-youve-been-looking-for-47dg#create-authentication-middleware


