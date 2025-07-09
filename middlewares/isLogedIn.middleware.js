import jwt from 'jsonwebtoken';

import asyncHandler from '../utils/asyncHandler.utils.js';
import { ACCESS_TOKEN } from '../utils/constants.utils.js';
import ApiError from '../utils/apiError.utils.js';

const isLogedIn = asyncHandler(async (req, res, next) => {
  const { accessToken } = req.cookies;

  const validAccessToken = jwt.verify(accessToken, ACCESS_TOKEN.secret);
});
