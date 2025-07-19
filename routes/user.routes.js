import { Router } from 'express';
import {
  registerUser,
  verifyEmail,
  loginUser,
  refreshAccessToken,
  logoutUser,
  userProfile,
} from '../controllers/auth.controller.js';
import userValidation from '../validator/index.validate.js';
import validate from '../middlewares/userValidate.middleware.js';
import isLogedIn from '../middlewares/isLogedIn.middleware.js';

const router = Router();

// Unsecure Routes
router.route('/register').post(userValidation(), validate, registerUser);
router.route('/verify-email/:token').get(verifyEmail);
router.route('/login').post(userValidation(), validate, loginUser);
router.route('/refreshAccessToken').patch(refreshAccessToken);

// Secure Routes
router.route('/logout').patch(isLogedIn, logoutUser);
router.route('/profile').get(isLogedIn, userProfile);

export default router;
