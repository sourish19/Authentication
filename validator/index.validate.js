import { body } from 'express-validator';

const userValidation = () => {
  return [
    body('username')
      .trim()
      .toLowerCase()
      .notEmpty() // .notEmpty() Checks if there is any value & .isEmpty() checks if the fiels is empty
      .withMessage('UserName is required'),
    body('email')
      .trim()
      .notEmpty()
      .withMessage('Email is required')
      .isEmail()
      .normalizeEmail()
      .withMessage('not a email'),
    body('password')
      .notEmpty()
      .withMessage('Password is required')
      .isLength({ min: 5 })
      .withMessage('Password must be at least 5 characters long'),
  ];
};

export default userValidation;
