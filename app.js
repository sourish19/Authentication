import express from 'express';
import router from './routes/user.routes.js';

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/api/v1', router);
app.use((err, req, res, next) => {
  if (err.statusCode) {
    // This is your ApiError
    return res.status(err.statusCode).json({
      error: err.error,
      message: err.message,
      statusCode: err.statusCode,
      success: false,
    });
  }

  // For other errors
  res.status(500).json({
    error: [],
    message: err.message || 'Internal Server Error',
    statusCode: 500,
    success: false,
  });
});

export default app;
