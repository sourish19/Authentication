const customErrorResponse = (err, req, res, next) => {
  if (err.statusCode) {
    // This is ApiError
    return res.status(err.statusCode).json({
      error: err.error,
      message: err.message,
      statusCode: err.statusCode,
      success: false,
    });
  }

  // For other errors
  res.status(500).json({
    error: [],
    message: err.message || 'Internal Server Error',
    statusCode: 500,
    success: false,
  });
};

export default customErrorResponse;
