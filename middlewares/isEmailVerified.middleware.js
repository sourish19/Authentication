import User from '../models/auth.model.js';
import ApiError from '../utils/apiError.utils.js';
import asyncHandler from '../utils/asyncHandler.utils.js';

const isEmailVerified = asyncHandler(async (error, req, res, next) => {
  const user = req.user;

  if (!user)
    throw new ApiError(error || [], error.message || 'User is not there', 401);

  const findUser = User.findById(user.id).select(
    '-password -refreshToken -emailVerificationToken -emailVerificationTokenExpiry -resetPasswordToken -resetPasswordTokenExpiry'
  );

  if (!findUser)
    throw new ApiError(error || [], error.message || 'User not found', 401);

  if (findUser.isEmailValid) next();

  throw new ApiError(
    error || [],
    error.message || 'User Email not Verified',
    401
  );
});

export default isEmailVerified;
