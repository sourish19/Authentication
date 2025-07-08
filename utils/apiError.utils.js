class ApiError extends Error {
  constructor(
    error = [],
    message = 'Something went wrong.',
    statusCode,
    stack
  ) {
    super(message);
    this.error = error;
    this.message = message;
    this.statusCode = statusCode;
    this.success = false;

    if (stack) {
      this.stack = stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

export default ApiError;
