const asyncHandler = (reqHandler) => async (req, res, next) => {
  try {
    await reqHandler();
  } catch (error) {
    next(error);
  }
};

export default asyncHandler;
