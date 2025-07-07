import express from 'express';
import router from './routes/user.routes.js';

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use('/api/v1', router);

export default app;
