import express from 'express';
import cookieParser from 'cookie-parser';
import router from './routes/user.routes.js';
import customErrorResponse from './middlewares/errors.middleware.js';
import healthCheckRoute from './routes/healthCheck.route.js';

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use('/api/v1/health-check', healthCheckRoute);
app.use('/api/v1/user', router);
app.use(customErrorResponse);

export default app;
