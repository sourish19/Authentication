const asyncHandler = (reqHandler) => async (req, res, next) => {
  try {
    await reqHandler(req, res);
  } catch (error) {
    next(error);
  }
};

export default asyncHandler;
