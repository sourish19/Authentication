import User from '../models/auth.model.js';
import ApiResponse from '../utils/apiResponse.utils.js';
import ApiError from '../utils/apiError.utils.js';
import asyncHandler from '../utils/asyncHandler.utils.js';
import {
  sendEmail,
  emailVerificationMailgenContent,
} from '../utils/mail.utils.js';

const registerUser = asyncHandler(async (req, res) => {
  const { username, email, password } = req.body;

  const findUser = await User.findOne({ $or: [{ username }, { email }] });

  if (findUser)
    throw new ApiError([{ username, email }], 'User already registered', 422);

  const newUser = await User.create({ username, email, password });

  const token = generateRandomTokens();

  await sendEmail({
    email: newUser?.email,
    subject: 'Please verify your email',
    mailgenContent: emailVerificationMailgenContent(
      newUser.username,
      `${process.env.BASE_URL}/api/v1/users/verify-email/${token}`
    ),
  });

  await newUser.save();

  const createdUser = await User.findOne(newUser._id).select(
    '-password -refreshToken -isEmailValid -emailVerificationToken -emailVerificationTokenExpiry'
  );

  if (!createdUser)
    // return res
    //   .status(400)
    //   .json(
    //     new ApiError([], 'Error occured during new user registration', 400)
    //   );
    throw new ApiError([], 'Error occured during new user registration', 400);

  return res.status(200).json(
    new ApiResponse(200, 'User Created Successfully & Email sent', {
      username: username,
      email: email,
    })
  );
});

const loginUser = () => {};

export { registerUser };

/*
  User provides username, email, password
  User clicks on signup,
  Two crypto tokens are generated 
    One tokes is hashed and send to user db as emailVerification and also has a exipry
    Another token which is not hashed is send via email and also gives the user when the token will expire

  At the very moment user might not verify the email 
    If User clicks on the expired token it will not get verified 
    User will go to the verify email route and will again generate the token -- it will check if the user is logedin 
    Same way two tokens will get generated and so on...
    And when the user clicks on the url it gets verified and both the emailtoken & expiry will set to undefined 
*/
