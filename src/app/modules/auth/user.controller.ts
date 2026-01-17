import axios from 'axios';
import { OAuth2Client } from 'google-auth-library';
import catchAsync from '../../utils/catchAsync';
import { Request, Response } from 'express';
import User from '../user/user.model';
import httpStatus  from 'http-status';
import AppError from '../../error/AppError';
import jwt, { JwtPayload, Secret  } from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import config from '../../config';
import sendResponse from '../../utils/sendResponse';
import { authServices, } from './user.service';
// import { AuthServices } from './user.service';



const googleClient = new OAuth2Client('YOUR_GOOGLE_CLIENT_ID'); // Replace with your Google Client ID







const userRegistration = catchAsync(async (req: Request, res: Response) => {
  // register service থেকে OTP generate হবে, user DB-এ এখনো save হবে না
  const { email } = req.body;
  const result = await authServices.register(req.body);

  sendResponse(res, {
    statusCode: httpStatus.CREATED,
    success: true,
    message: `OTP sent to ${email}. Please verify to complete registration`,
    data: { email }, // শুধু email পাঠাচ্ছি
  });
});







const verifyEmailController = catchAsync(async (req: Request, res: Response) => {
  const { email, otp } = req.body;

  // verifyOtp service → OTP check + DB save
  const user = await authServices.verifyEmail(email, Number(otp));

  sendResponse(res, {
    statusCode: httpStatus.CREATED,
    success: true,
    message: 'OTP verified successfully. User registration complete.',
    data: {
      _id: user._id,
      email: user.email,
      fullName: user.fullName,
      phoneNumber: user.phoneNumber,
      countryCode: user.countryCode,
      gender: user.gender,
      role: user.role,
      isVerified: user.isVerified,
    },
  });
});




// npm install apple-auth jsonwebtoken



const appleLogin = async (req: Request, res: Response) => {
  const { idToken } = req.body;

  // Decode Apple token
  const decoded: any = jwt.decode(idToken);

  if (!decoded) {
    throw new AppError(400, 'Invalid Apple token');
  }

  const {
    email,
    sub, // Apple user unique id
  } = decoded;

  let user = await User.findOne({ email });

  if (!user) {
    user = await User.create({
      email,
      fullName: 'Apple User',
      accountType: 'apple',
      isVerified: true,
    });
  }

  const accessToken = jwt.sign(
    { id: user._id, role: user.role },
    config.jwt.jwt_access_secret as string,
    { expiresIn: '24h' }
  );

  res.json({
    success: true,
    accessToken,
    user,
  });
};















const login = catchAsync(async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email }).select('+password');

  if (!user || !user?.password) {
    throw new AppError(httpStatus.NOT_FOUND, 'User not found');
  }

  const isPasswordMatched = await bcrypt.compare(password, user.password);
  if (!isPasswordMatched) {
    throw new AppError(httpStatus.UNAUTHORIZED, 'Incorrect password');
  }

  const accessToken = jwt.sign(
    {
      id: user._id,
      role: user.role,
    },
    config.jwt.jwt_access_secret as Secret,
    { expiresIn: '24h' },
  );

  const refreshToken = jwt.sign(
    {
      id: user._id,
      role: user.role,
    },
    config.jwt.jwt_refresh_secret as Secret,
    { expiresIn: '7d' },
  );

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Login successful',
    data: {
      user,
      accessToken,
      refreshToken,
    },
  });
});

const resetPassword = catchAsync(async (req: Request, res: Response) => {
  const token = req.headers.token as string;
  const { newPassword } = req.body;

  if (!token) throw new AppError(httpStatus.UNAUTHORIZED, 'Token missing');

  let decoded: JwtPayload;
  try {
    decoded = jwt.verify(
      token,
      config.jwt.jwt_access_secret as Secret,
    ) as JwtPayload;
  } catch {
    throw new AppError(httpStatus.FORBIDDEN, 'Token expired or invalid');
  }

  if (!decoded?.id || !decoded?.allowReset) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      'OTP not verified or reset not allowed',
    );
  }

  const user = await User.findById(decoded.id);
  if (!user) throw new AppError(httpStatus.NOT_FOUND, 'User not found');

  user.password = newPassword; // raw password
  await user.save();

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Password reset successfully',
    data: { user },
  });
});

// 3. Change Password - for logged-in users
const changePassword = catchAsync(async (req: Request, res: Response) => {
  const userId = req.user?.id;
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(userId).select('+password');
  if (!user) throw new AppError(httpStatus.NOT_FOUND, 'User not found');

  const isMatch = await bcrypt.compare(oldPassword, user.password);
  if (!isMatch)
    throw new AppError(httpStatus.BAD_REQUEST, 'Old password is incorrect');

  // const hashedPassword = await bcrypt.hash(newPassword, 12);
  // user.password = hashedPassword;
  // await user.save();
  user.password = newPassword; // raw password
  await user.save();

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Password changed successfully',
    data: { user },
  });
});

const refreshToken = catchAsync(async (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    throw new AppError(httpStatus.BAD_REQUEST, 'Refresh token is required');
  }

  try {
    const decoded = jwt.verify(
      refreshToken,
      config.jwt.jwt_refresh_secret as Secret,
    ) as JwtPayload;
    const token = jwt.sign(
      { id: decoded.id, role: decoded.role },
      config.jwt.jwt_access_secret as Secret,
      { expiresIn: '24h' },
    );




    sendResponse(res, {
      statusCode: httpStatus.OK,
      success: true,
      message: 'Access token refreshed',
      data: { token },
    });
  } catch {
    throw new AppError(
      httpStatus.FORBIDDEN,
      'Invalid or expired refresh token',
    );
  }
});

const googleLogin = catchAsync(async (req: Request, res: Response) => {
  const { idToken } = req.body;
  if (!idToken) {
    throw new AppError(httpStatus.BAD_REQUEST, 'Google idToken is required');
  }
  const ticket = await googleClient.verifyIdToken({
    idToken,
    audience: 'YOUR_GOOGLE_CLIENT_ID', // Google Client ID
  });
  const payload = ticket.getPayload();
  if (!payload?.email) {
    throw new AppError(httpStatus.BAD_REQUEST, 'Invalid Google token');
  }

  let user = await User.findOne({ email: payload.email });
  if (!user) {
    user = await User.create({
      email: payload.email,
      fullName: payload.name,
      isVerified: true,
    });
  }

  const accessToken = jwt.sign(
    { id: user._id, role: user.role },
    config.jwt.jwt_access_secret as Secret,
    { expiresIn: '24h' },
  );
  const refreshToken = jwt.sign(
    { id: user._id, role: user.role },
    config.jwt.jwt_refresh_secret as Secret,
    { expiresIn: '7d' },
  );

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Google login successful',
    data: {
      user,
      accessToken,
      refreshToken,
    },
  });
});

const facebookLogin = catchAsync(async (req: Request, res: Response) => {
  const { accessToken } = req.body;
  if (!accessToken) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      'Facebook accessToken is required',
    );
  }

  // Verify token and get user info from Facebook
  const fbRes = await axios.get(
    `https://graph.facebook.com/me?fields=id,name,email&access_token=${accessToken}`,
  );
  const { email, name } = fbRes.data;
  if (!email) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      'Unable to get email from Facebook',
    );
  }

  let user = await User.findOne({ email });
  if (!user) {
    user = await User.create({
      email,
      fullName: name,
      isVerified: true,
    });
  }

  const accessTokenJwt = jwt.sign(
    { id: user._id, role: user.role },
    config.jwt.jwt_access_secret as Secret,
    { expiresIn: '24h' },
  );
  const refreshToken = jwt.sign(
    { id: user._id, role: user.role },
    config.jwt.jwt_refresh_secret as Secret,
    { expiresIn: '7d' },
  );

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Facebook login successful',
    data: {
      user,
      accessToken: accessTokenJwt,
      refreshToken,
    },
  });
});


// neja korce ai api gulla oky

const codeVerification = catchAsync(async (req: Request, res: Response) => {
 const { email } = req.body;

 
  const otp = await authServices.sendVerificationCode(email);

  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'OTP sent successfully, please verify before reset password',
    data: { email, otp }, // 🔒 prod এ otp response দিও না, শুধুমাত্র email
  });
});







export const verifyOtpController = catchAsync(async (req, res) => {
  const { email, otp } = req.body;
  await authServices.userVerifyOtp(email, Number(otp));
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'OTP verified successfully. You can now reset your password.',
    data: { email },
  });
});




export const authControllers = {
  login,
  resetPassword,
  verifyOtpController,
  codeVerification,
  changePassword,
  refreshToken,
  googleLogin,
  facebookLogin,
  userRegistration,
  verifyEmailController,
};
