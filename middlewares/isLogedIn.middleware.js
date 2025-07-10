import jwt from 'jsonwebtoken';

import asyncHandler from '../utils/asyncHandler.utils.js';
import { ACCESS_TOKEN } from '../utils/constants.utils.js';
import ApiError from '../utils/apiError.utils.js';

const isLogedIn = asyncHandler(async (req, res, next) => {
  const accessToken = req.cookies?.accessToken;

  if (!accessToken) throw new ApiError([], 'Invalid request', 401);

  try {
    const decoded = jwt.verify(accessToken, ACCESS_TOKEN.secret);

    if (!decoded) {
      // Client should make a request to /api/v1/users/refresh-token if they have refreshToken present in their cookie
      // Then they will get a new access token which will allow them to refresh the access token without logging out the user
      throw new ApiError([], 'Unauthorized request', 401);
    }

    req.user = decoded;

    next();
  } catch (error) {
    // Client should make a request to /api/v1/users/refresh-token if they have refreshToken present in their cookie
    // Then they will get a new access token which will allow them to refresh the access token without logging out the user
    throw new ApiError([], 'Access Token Expired', 401);
  }
});

export default isLogedIn;
