# AUTHENTICATION

A modular Node.js/Express backend for user authentication, email verification, and password management, using MongoDB and JWT. Includes robust validation, error handling, and email notifications.

---

## Features
- User registration with email verification
- Login and JWT-based authentication (access & refresh tokens)
- Password reset via email
- Change password (with validation)
- User profile endpoint
- Secure route protection middleware
- Request validation and structured error responses
- Health check endpoint

---

## Tech Stack
- **Node.js** (ES Modules)
- **Express.js**
- **MongoDB** (via Mongoose)
- **JWT** for authentication
- **Nodemailer** & **Mailgen** for transactional emails
- **express-validator** for request validation
- **dotenv** for environment variables

---

## Getting Started

### Prerequisites
- Node.js v16+
- MongoDB instance (local or cloud)

### Installation
```bash
npm install
```

### Environment Variables
Create a `.env` file in the root with the following variables:

```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
BASE_URL_WSL=http://localhost:5000/api/v1/

# JWT secrets and expiry
AUTH_ACCESS_TOKEN_SECRET=your_access_token_secret
AUTH_ACCESS_TOKEN_EXPIRY=15m
AUTH_REFRESH_TOKEN_SECRET=your_refresh_token_secret
AUTH_REFRESH_TOKEN_EXPIRY=7d

# Mailtrap or SMTP credentials
MAILTRAP_MAIL=your_from_email@example.com
MAILTRAP_HOST=smtp.mailtrap.io
MAILTRAP_PORT=2525
MAILTRAP_USERNAME=your_mailtrap_username
MAILTRAP_PASSWORD=your_mailtrap_password
```

### Running the App
```bash
npm start
```

---

## API Endpoints
All endpoints are prefixed with `/api/v1`.

### Auth/User Routes
| Method | Endpoint                                   | Description                        | Protected |
|--------|--------------------------------------------|------------------------------------|-----------|
| POST   | `/register`                                | Register new user                  | No        |
| GET    | `/verify-email/:token`                     | Verify email                       | No        |
| POST   | `/login`                                   | Login user                         | No        |
| PATCH  | `/refresh-access-token`                    | Refresh JWT access token           | No        |
| PATCH  | `/resend-email-verification`               | Resend verification email          | No        |
| PATCH  | `/forgot-password`                         | Request password reset email       | No        |
| PATCH  | `/reset-password/:resetPasswordToken`      | Reset password                     | No        |
| PATCH  | `/logout`                                  | Logout user                        | Yes       |
| GET    | `/profile`                                 | Get user profile                   | Yes       |
| PATCH  | `/change-current-password`                 | Change current password            | Yes       |

### Health Check
| Method | Endpoint         | Description                |
|--------|------------------|----------------------------|
| GET    | `/health`        | Server health check        |

---

## Project Structure
```
practice_Auth/
├── app.js                  # Express app setup
├── index.js                # Entry point, DB connect, server start
├── controllers/            # Route handlers (auth, healthCheck)
├── database/               # MongoDB connection logic
├── middlewares/            # Auth, validation, error middlewares
├── models/                 # Mongoose User model
├── routes/                 # API route definitions
├── utils/                  # Helpers: error, response, mail, constants
├── validator/              # express-validator rules
└── ...
```

---

## Validation & Error Handling
- Uses `express-validator` for request validation (see `validator/`)
- Centralized error handling middleware returns structured JSON errors

---

## Email Functionality
- Uses Mailgen for beautiful transactional emails
- Requires SMTP credentials (Mailtrap recommended for dev)

---

## Author
Sourish Dey 
