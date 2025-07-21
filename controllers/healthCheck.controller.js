import asyncHandler from '../utils/asyncHandler.util.js';
import ApiResponse from '../utils/apiResponse.util.js';

const healthCheck = asyncHandler(async (req, res) => {
  res
    .status(200)
    .json(new ApiResponse(200, { message: 'Server running successfully' }, []));
});

export default healthCheck;
