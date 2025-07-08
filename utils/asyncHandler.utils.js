const asyncHandler = (reqHandler) => async (req, res, next) => {
  try {
    await reqHandler(req, res, next);
  } catch (error) {
    next(error);
  }
};

export default asyncHandler;
