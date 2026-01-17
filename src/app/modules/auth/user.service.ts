import jwt, { JwtPayload, Secret } from 'jsonwebtoken';
import config from "../../config";
import AppError from "../../error/AppError";
import User from "../user/user.model";
import { createToken, verifyToken } from "./auth.utils";
import { TchangePassword, Tlogin, TRegister, TresetPassword } from "./user.interface";
import  httpStatus  from 'http-status';
import { generateOtp } from "../../utils/otpGenerator";
import moment from 'moment';
import { sendEmail } from '../../utils/mailSender';
import bcrypt from "bcrypt";
import { UserRole } from '../user/user.interface';



// otpCache: in-memory Map or Redis
const otpCache = new Map<string, { payload: TRegister; otp: number; expiresAt: Date }>();

const register = async (payload: TRegister) => {
  // check existing email
  const isEmailExist = await User.isUserExist(payload.email);
  if (isEmailExist) {
    throw new AppError(httpStatus.BAD_REQUEST, 'Email already exists');
  }

  // phone check
  const isPhoneExist = await User.isUserExistByNumber(
    payload.countryCode,
    payload.phoneNumber
  );
  if (isPhoneExist) {
    throw new AppError(httpStatus.BAD_REQUEST, 'Phone number already exists');
  }

  // generate OTP
  const otp = generateOtp();
  const expiresAt = moment().add(5, 'minute').toDate();

  otpCache.set(payload.email, { payload, otp, expiresAt });

  // send OTP email
  await sendEmail(
    payload.email,
    'Verify your email',
    `<div>
      <h4>Your verification OTP</h4>
      <h2>${otp}</h2>
      <p>Valid till: ${expiresAt.toLocaleString()}</p>
    </div>`
  );

  return { email: payload.email };
};



const verifyEmail = async (email: string, otpInput: number) => {
  const otpData = otpCache.get(email);
  if (!otpData) {
    throw new AppError(httpStatus.BAD_REQUEST, 'No OTP request found');
  }

  if (moment().isAfter(otpData.expiresAt)) {
    otpCache.delete(email);
    throw new AppError(httpStatus.BAD_REQUEST, 'OTP expired');
  }

  if (otpData.otp !== otpInput) {
    throw new AppError(httpStatus.BAD_REQUEST, 'Invalid OTP');
  }

  // ✅ OTP verified → now save user in DB
  const payload = otpData.payload;

  const user = await User.create({
    email: payload.email,
    password: payload.password,
    fullName: payload.fullName,
    phoneNumber: payload.phoneNumber,
    countryCode: payload.countryCode,
    gender: payload.gender,
    role: UserRole.customer,
    isVerified: true,
    verification: {
      otp: null,
      expiresAt: null,
      status: true,
    },
  });

  // OTP remove from cache
  otpCache.delete(email);

  return user;
};





const login = async (payload: Tlogin) => {
  const user = await User.isUserExist(payload?.email as string);
  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'User Not Found');
  }
  if (!user?.isActive) {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked ! !');
  }
  if (user?.isDeleted) {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted !');
  }
  if (!user?.isVerified) {
    throw new AppError(httpStatus.BAD_REQUEST, 'user is not verified !');
  }

  if (!(await User.isPasswordMatched(payload.password, user.password))) {
    throw new AppError(httpStatus.BAD_REQUEST, 'password do not match');
  }

  const jwtPayload = {
    userId: user?._id.toString(),
    role: user?.role,
  };
  const accessToken = createToken(
    jwtPayload,
    config.jwt.jwt_access_secret as string,
    config.jwt.jwt_access_expires_in as string,
  );

  const refreshToken = createToken(
    jwtPayload,
    config.jwt.jwt_refresh_secret as string,
    config.jwt.jwt_refresh_expires_in as string,
  );
  return {
    accessToken,
    refreshToken,
  };
};
//change password
const changePassword = async (id: string, payload: TchangePassword) => {
  const user = await User.IsUserExistbyId(id);
  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'User not found');
  }

  const isOldPasswordValid = await User.isPasswordMatched(
    payload.oldPassword,
    user.password,
  );

  if (!isOldPasswordValid) {
    throw new AppError(httpStatus.FORBIDDEN, 'Old password does not match!');
  }

  if (payload.newPassword !== payload.confirmPassword) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      'New password and confirm password do not match!',
    );
  }

  const isSameAsOld = await User.isPasswordMatched(
    payload.newPassword,
    user.password,
  );

  if (isSameAsOld) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      'New password cannot be same as old password!',
    );
  }

  const hashedPassword = await bcrypt.hash(
    payload.newPassword,
    Number(config.bcrypt_salt_rounds),
  );

  const result = await User.findByIdAndUpdate(
    id,
    {
      $set: {
        password: hashedPassword,
        passwordChangedAt: new Date(),
      },
    },
    { new: true },
  );

  return result;
};

// forgot password

const forgotPassword = async (email: string) => {
  const user = await User.isUserExist(email);

  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'user not found ');
  }
  if (user?.isDeleted) {
    throw new AppError(httpStatus.NOT_FOUND, 'user not found');
  }
  if (user?.status === 'blocked') {
    throw new AppError(httpStatus.FORBIDDEN, 'your account is inactive');
  }
  const jwtPayload = {
    email: email,
    id: user?._id.toString(),
  };
  const token = jwt.sign(jwtPayload, config.jwt.jwt_access_secret as Secret, {
    expiresIn: '5m',
  });
  const currentTime = new Date();
  const otp = generateOtp();
  const expiresAt = moment(currentTime).add(5, 'minute');
  await User.findByIdAndUpdate(user?._id, {
    verification: {
      otp,
      expiresAt,
    },
  });
  await sendEmail(
    email,
    'your reset password otp is:',
    `<div><h5>your otp is: ${otp}</h5>
    <p>valid for:${expiresAt.toLocaleString()}</p>
    </div>`,
  );
  // send the mail here
  return { email, token };
};

const resetPassword = async (token: string, payload: TresetPassword) => {
  let decode;
  try {
    decode = jwt.verify(
      token,
      config.jwt.jwt_access_secret as string,
    ) as JwtPayload;
  } catch (err) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      'Session has exipired. please try again',
    );
  }
  const user = await User.findById(decode?.id).select('isDeleted verification');

  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'user not found');
  }
  if (new Date() > user?.verification?.expiresAt) {
    throw new AppError(httpStatus.FORBIDDEN, 'sessions expired');
  }
  if (!user?.verification?.status) {
    throw new AppError(httpStatus.FORBIDDEN, 'Otp is not verified yet!');
  }
  if (payload?.newPassword !== payload?.confirmPassword) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      'New password and Confirm password do not match!',
    );
  }
  const hashedPassword = await bcrypt.hash(
    payload?.newPassword,
    Number(config.bcrypt_salt_rounds),
  );
  const result = await User.findByIdAndUpdate(decode?.id, {
    password: hashedPassword,
    passwordChangedAt: new Date(),
    verification: {
      otp: 0,
      status: false,
    },
  });
  return result;
};

const refreshToken = async (token: string) => {
  // checking if the given token is valid
  console.log('hitted');
  const decoded = verifyToken(token, config.jwt.jwt_refresh_secret as string);
  const { userId } = decoded;
  console.log(decoded);
  const user = await User.IsUserExistbyId(userId);

  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'This user is not found !');
  }
  const isDeleted = user?.isDeleted;

  if (isDeleted) {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted !');
  }
  // checking if the user is blocked
  const userStatus = user?.status;

  if (userStatus === 'blocked') {
    throw new AppError(httpStatus.FORBIDDEN, 'This user is blocked ! !');
  }

  const jwtPayload = {
    userId: user.id!,
    role: user.role!,
  };

  const accessToken = createToken(
    jwtPayload,
    config.jwt.jwt_access_secret as string,
    config.jwt.jwt_access_expires_in as string,
  );

  return {
    accessToken,
  };
};



// OTP cache for password reset
const passwordResetOtpCache = new Map<string, { otp: number; expiresAt: Date }>();

export const sendVerificationCode = async (email: string) => {
  const user = await User.isUserExist(email);
  if (!user) throw new AppError(404, 'Email not found');

  const otp = generateOtp();
  const expiresAt = moment().add(10, 'minute').toDate();

  passwordResetOtpCache.set(email, { otp, expiresAt });

  // await sendEmail(
  //   email,
  //   'Password Reset OTP',
  //   `<div>
  //     <h4>Your password reset OTP</h4>
  //     <h2>${otp}</h2>
  //     <p>Valid till: ${expiresAt.toLocaleString()}</p>
  //   </div>`
  // );

  await sendEmail(
  email,
  'Password Reset OTP',
  `
  <div style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
    <!-- Email Container -->
    <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 10px; padding: 30px; text-align: center; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">

      <!-- Logo -->
      <img src="https://yourdomain.com/logo.png" alt="Your Logo" style="width: 120px; margin-bottom: 20px;" />

      <!-- Heading -->
      <h2 style="color: #333;">Password Reset OTP</h2>
      <p style="color: #555; font-size: 16px;">Use the OTP below to reset your password. It is valid for 10 minutes.</p>

      <!-- OTP Box with animation -->
      <div style="
        display: inline-block;
        padding: 15px 25px;
        font-size: 32px;
        letter-spacing: 8px;
        color: #fff;
        background: #4CAF50;
        border-radius: 8px;
        font-weight: bold;
        margin: 20px 0;
        animation: pulse 1.5s infinite;
      ">
        ${otp}
      </div>

      <!-- Expiry info -->
      <p style="color: #888; font-size: 14px;">Valid till: ${expiresAt.toLocaleString()}</p>

      <!-- Footer -->
      <p style="color: #aaa; font-size: 12px; margin-top: 30px;">If you did not request this, please ignore this email.</p>
    </div>
  </div>

  <!-- Animation keyframes -->
  <style>
    @keyframes pulse {
      0% { transform: scale(1); box-shadow: 0 0 5px #4CAF50; }
      50% { transform: scale(1.05); box-shadow: 0 0 15px #4CAF50; }
      100% { transform: scale(1); box-shadow: 0 0 5px #4CAF50; }
    }
  </style>
  `
);

  return otp; 
};



// Verified users map (email → VERIFIED)
export const verifiedUsers = new Map<string, string>();

// 2️⃣ Verify OTP
export const userVerifyOtp = async (email: string, otpInput: number) => {
   const user = await User.findOne({ email });
  if (!user || !user.verification) throw new AppError(400, 'OTP not found or expired');

  // if (user.verification.status) throw new AppError(400, 'OTP already verified');

  // if (user.verification.otp !== otpInput) throw new AppError(400, 'Invalid OTP');

  // if (moment().isAfter(user.verification.expiresAt)) throw new AppError(400, 'OTP expired');

  // Mark verified
  user.verification.status = true;
  await user.save();

  // Save in-memory for password reset API
  verifiedUsers.set(email, 'VERIFIED');

  return { email };
};






export const userResetPasswordService = async (
  email: string,
  newPassword: string,
) => {
  const user = await User.findOne({ email }).select('+password');

  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'User not found');
  }

  if (!user.verification || user.verification.status !== true) {
    throw new AppError(httpStatus.BAD_REQUEST, 'OTP not verified');
  }

  // ✅ set new password
  user.password = newPassword;

  // ✅ clear OTP data
 user.verification = {
  otp: null,
  expiresAt: null,
  status: false,
} as any;

  await user.save();

  return null;
};







export const authServices = {
  register,
  verifyEmail,
  login,
  userVerifyOtp,
  sendVerificationCode,
  changePassword,
  forgotPassword,
  resetPassword,
  refreshToken,
};
