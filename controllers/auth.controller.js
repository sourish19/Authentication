import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

import User from '../models/auth.model.js';
import ApiResponse from '../utils/apiResponse.utils.js';
import ApiError from '../utils/apiError.utils.js';
import asyncHandler from '../utils/asyncHandler.utils.js';
import { REFRESH_TOKEN } from '../utils/constants.utils.js';
import {
  sendEmail,
  emailVerificationMailgenContent,
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

  await user.save();

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

  const hashedToken = crypto.createHash('sha256').update(token).digest('hex'); // same token generates same hash

  // Checks both the condition
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

const loginUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;

  const user = await User.findOne({ $or: [{ username }, { email }] });

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
    '-password -refreshToken -isEmailValid -emailVerificationToken -emailVerificationTokenExpiry'
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
    throw new ApiError(
      error || [],
      'Unauthorized request - User not logedin',
      401
    );

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

    const hashedRefToken = bcrypt.compare(incommingRefreshToken, user?.refreshToken);

    if (!hashedRefToken)
      throw new ApiError(
        error || [],
        error?.message || 'Invalid Refresh Token',
        401
      );

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

  if (!user)
    throw new ApiError(
      error || [],
      'Unauthorized request - User not logedin',
      401
    );

  const findUser = await User.findById(user.id);

  if (!findUser)
    throw new ApiError(
      error || [],
      'Unauthorized request - User not logedin',
      401
    );

  findUser.refreshToken = undefined;

  await findUser.save();

  res.clearCookie('accessToken', cookiesOption.options);
  res.clearCookie('refreshToken', cookiesOption.options);

  res.status(200).json(new ApiResponse(200, 'User Logout successfully'));
});

const userProfile = asyncHandler(async(req,res)=>{
  
})

export { registerUser, verifyEmail, loginUser, logoutUser, refreshAccessToken, userProfile };

//https://dev.to/smitterhane/a-meticulous-jwt-api-authentication-guide-youve-been-looking-for-47dg#create-authentication-middleware
