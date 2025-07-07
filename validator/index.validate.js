import { body } from 'express-validator';

const userValidation = () => {
  return [
    body('username')
      .notEmpty()
      .withMessage('UserName is required')
      .trim()
      .toLowerCase(),
    body('email')
      .isEmpty()
      .withMessage('Email is required')
      .isEmail()
      .normalizeEmail()
      .trim()
      .withMessage('Not a valid e-mail address'),
    body('password')
      .isEmpty()
      .withMessage('Password is required')
      .isLength({ min: 5 })
      .withMessage('Password must be at least 8 characters long'),
  ];
};

export default userValidation;
