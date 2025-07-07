import { validationResult } from 'express-validator';
import ApiError from '../utils/apiError.utils.js';

const validate = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) return next();

  const formatedErrors = {};

  errors.array().map((e) => {
    if (!formatedErrors[e.path]) {
      formatedErrors[e.path] = [];
    }
    formatedErrors[e.path].push(e.msg);
  });

  throw new ApiError(formatedErrors, 'Received data is not valid', 422);
};

export default validate;
