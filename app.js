import express from 'express';
import router from './routes/user.routes.js';
import customErrorResponse from './middlewares/errors.middleware.js';

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/api/v1/user', router);
app.use(customErrorResponse);

export default app;
