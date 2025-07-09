import jwt from 'jsonwebtoken';

import asyncHandler from '../utils/asyncHandler.utils.js';
import { ACCESS_TOKEN } from '../utils/constants.utils.js';
import ApiError from '../utils/apiError.utils.js';

const isLogedIn = (req, res, next) => {
  try {
    const accessToken = req.cookies?.accessToken;

    if (!accessToken) throw new ApiError([], 'Unauthorized request', 401);

    const decoded = jwt.verify(accessToken, ACCESS_TOKEN.secret);

    if (!decoded) {
      const refreshToken = req.cookies?.refreshToken;

      if (!refreshToken) throw new ApiError([], 'Unauthorized request', 401);
    }

    req.user = decoded;

    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      const refreshToken = req.cookies?.refreshToken;
      if (!refreshToken) throw new ApiError([], 'Access Token Expired', 401);
    }
  }
};

export default isLogedIn;

// Client should make a request to /api/v1/users/refresh-token if they have refreshToken present in their cookie
// Then they will get a new access token which will allow them to refresh the access token without logging out the user
