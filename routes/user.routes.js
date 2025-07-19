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
  userPasswordValidation,
  userEmailValidation,
} from '../validator/index.validate.js';
import validate from '../middlewares/userValidate.middleware.js';
import isLogedIn from '../middlewares/isLogedIn.middleware.js';
import isEmailVerified from '../middlewares/isEmailVerified.middleware.js';

const router = Router();

// Unsecure Routes
router
  .route('/register')
  .post(userRegistrationValidation(), validate, registerUser);
router.route('/verify-email/:token').get(verifyEmail);
router.route('/login').post(userRegistrationValidation(), validate, loginUser);
router.route('/refresh-access-token').patch(refreshAccessToken);
router.route('/forgot-password').get(forgotPassword);
router
  .route('/reset-password')
  .patch(isLogedIn, isEmailVerified, resetPassword);
router
  .route('/resend-email-verification')
  .patch(userEmailValidation(), validate, resendEmailVerification);

// Secure Routes
router.route('/logout').patch(isLogedIn, logoutUser);
router.route('/profile').get(isLogedIn, userProfile);
router
  .route('/change-current-password')
  .patch(isLogedIn, userPasswordValidation(), validate, changeCurrentPassword);

export default router;
