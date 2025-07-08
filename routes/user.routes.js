import { Router } from 'express';
import { registerUser, verifyEmail } from '../controllers/auth.controller.js';
import userValidation from '../validator/index.validate.js';
import validate from '../middlewares/userValidate.middleware.js';

const router = Router();

router.route('/register').post(userValidation(), validate, registerUser);
router.route('/verify-email/:token').get(verifyEmail);

export default router;
