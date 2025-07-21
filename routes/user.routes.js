import { Router } from 'express';
import {
  registerUser,
  verifyEmail,
  loginUser,
  refreshAccessToken,
  logoutUser,
  userProfile,
  changeCurrentPassword,
  forgotPassword,
  resetPassword,
  resendEmailVerification,
} from '../controllers/auth.controller.js';
import {
  userRegistrationValidation,
  userChangePasswordValidation,
  userResetPasswordValidation,
  userEmailValidation,
} from '../validator/index.validate.js';
import validate from '../middlewares/userValidate.middleware.js';
import isLogedIn from '../middlewares/isLogedIn.middleware.js';

const router = Router();

// Unsecured Routes
router
  .route('/register')
  .post(userRegistrationValidation(), validate, registerUser);
router.route('/verify-email/:token').get(verifyEmail);
router.route('/login').post(userRegistrationValidation(), validate, loginUser);
router.route('/refresh-access-token').patch(refreshAccessToken);
router
  .route('/resend-email-verification')
  .patch(userEmailValidation(), validate, resendEmailVerification);
router
  .route('/forgot-password')
  .patch(userEmailValidation(), validate, forgotPassword);
router
  .route('/reset-password/:resetPasswordToken')
  .patch(userResetPasswordValidation(), validate, resetPassword);

// Secure Routes
router.route('/logout').patch(isLogedIn, logoutUser);
router.route('/profile').get(isLogedIn, userProfile);
router
  .route('/change-current-password')
  .patch(
    isLogedIn,
    userChangePasswordValidation(),
    validate,
    changeCurrentPassword
  );

export default router;
