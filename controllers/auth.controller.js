import User from '../models/auth.model.js';
import ApiResponse from '../utils/apiResponse.utils.js';
import ApiError from '../utils/apiError.utils.js';
import asyncHandler from '../utils/asyncHandler.utils.js';

const registerUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;

  const findUser = await User.findOne({ email, username });

  if (findUser)
    throw new ApiError([{ username, email }], 'User already registered', 422);

  const newUser = await User.create({ username, email, password });

  await newUser.save();

  const createdUser = await User.findOne({ email, username }).select(
    '-password -refreshToken -isEmailValid -emailVerificationToken -emailVerificationTokenExpiry'
  );

  if (!createdUser)
    throw new ApiError([], 'Error occured during new user registration');

  return res.status(200).json(
    new ApiResponse(200, 'User Created Successfully & Email sent', {
      username: username,
      email: email,
    })
  );
});

export { registerUser };
