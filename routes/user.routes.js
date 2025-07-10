import { Router } from 'express';
import {
  registerUser,
  verifyEmail,
  loginUser,
  refreshAccessToken,
  logoutUser,
} from '../controllers/auth.controller.js';
import userValidation from '../validator/index.validate.js';
import validate from '../middlewares/userValidate.middleware.js';

const router = Router();

router.route('/register').post(userValidation(), validate, registerUser);
router.route('/verify-email/:token').get(verifyEmail);
router.route('/login').post(userValidation(), validate, loginUser);
router.route('/refreshAccessToken').put(refreshAccessToken);
router.route('/logut').get(logoutUser);

export default router;
