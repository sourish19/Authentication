import ApiResponse from '../utils/apiResponse.utils.js';
import ApiError from '../utils/apiError.utils.js';
import asyncHandler from '../utils/asyncHandler.utils.js';

const registerUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;
});

module.exports = {
  registerUser,
};
