import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import router from './routes/user.routes.js';
import customErrorResponse from './middlewares/errors.middleware.js';

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/api/v1/user', router);
app.use(customErrorResponse);

export default app;
