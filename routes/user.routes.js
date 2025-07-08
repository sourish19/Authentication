import { Router } from 'express';
import { registerUser } from '../controllers/auth.controller.js';
import userValidation from '../validator/index.validate.js';
import validate from '../middlewares/userValidate.middleware.js';

const router = Router();

router.route('/').get((req, res) => {
  res.status(200).json({ status: 'ok' });
});

router.route('/user/register').post(userValidation(), validate, registerUser);

export default router;
