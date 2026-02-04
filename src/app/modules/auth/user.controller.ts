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
import { authServices, userResetPasswordService, } from './user.service';
import { UserRole } from '../user/user.interface';
// import { AuthServices } from './user.service';
import * as appleSignin from 'apple-signin-auth';
import { ApplePayload } from './user.interface';



// const googleClient = new OAuth2Client('23601987612-4e3n9lf08s8hnh0o9m8ag8n22f82u2ki.apps.googleusercontent.com'); // Replace with your Google Client ID
const googleClient = new OAuth2Client('23601987612-ko94q8ki1ui42igekam6f87kamceuvu4.apps.googleusercontent.com');

export const googleLogin = async (req: Request, res: Response) => {
  const { idToken } = req.body;
  if (!idToken) return res.status(400).json({ success: false, message: 'idToken required' });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: '23601987612-ko94q8ki1ui42igekam6f87kamceuvu4.apps.googleusercontent.com',
    });

    const payload = ticket.getPayload();
    console.log('Google payload:', payload);
    if (!payload?.email) return res.status(400).json({ success: false, message: 'Invalid Google token' });

    // let user = await User.findOne({ email: payload.email });
    // if (!user) {
    //   user = await User.create({
    //     email: payload.email,
    //     fullName: payload.name,
    //     isVerified: true,
    //     accountType: 'google',
    //   });
    // }


    let user = await User.findOne({ email: payload.email });
if (!user) {
  user = await User.create({
    email: payload.email,
    fullName: payload.name,
    isVerified: true,
    accountType: 'google',
    gender: 'Male',
    password: '12231',
    countryCode: '+880',
    phoneNumber: '0172287587',
    image: {
      id: 'google', // যেকোনো default id
      url: payload.picture || 'https://example.com/default.png',
    },
  });
}

    const accessToken = jwt.sign({ id: user._id, role: user.role }, config.jwt.jwt_access_secret as string, { expiresIn: '24h' });
    const refreshToken = jwt.sign({ id: user._id, role: user.role }, config.jwt.jwt_refresh_secret as string, { expiresIn: '7d' });

    res.json({ success: true, user, accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Google login failed', err });
  }
};


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

// export const appleLogin = async (req: Request, res: Response) => {
//   const { idToken } = req.body;

//   if (!idToken) {
//     throw new AppError(400, 'Apple idToken required');
//   }

//   jwt.verify(idToken, getAppleKey, async (err, decoded: any) => {
//     if (err) {
//       throw new AppError(401, 'Invalid Apple token');
//     }

//     const { email, sub } = decoded;

//     let user = await User.findOne({ email });

//     if (!user) {
//       user = await User.create({
//         email,
//         fullName: 'Apple User',
//         accountType: 'apple',
//         isVerified: true,
//         password: 'apple-login', // dummy password
//         gender: 'Male',          // required field
//         countryCode: 'NA',
//         phoneNumber: sub,        // unique value
//       });
//     }

//     const accessToken = jwt.sign(
//       { id: user._id, role: user.role },
//       process.env.JWT_ACCESS_SECRET!,
//       { expiresIn: '24h' }
//     );

//     const refreshToken = jwt.sign(
//       { id: user._id, role: user.role },
//       process.env.JWT_REFRESH_SECRET!,
//       { expiresIn: '7d' }
//     );

//     res.json({
//       success: true,
//       user,
//       accessToken,
//       refreshToken,
//     });
//   });
// };













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

// const googleLogin = catchAsync(async (req: Request, res: Response) => {
//   const { idToken } = req.body;
//   if (!idToken) {
//     throw new AppError(httpStatus.BAD_REQUEST, 'Google idToken is required');
//   }
//   const ticket = await googleClient.verifyIdToken({
//     idToken,
//     audience: '23601987612-4e3n9lf08s8hnh0o9m8ag8n22f82u2ki.apps.googleusercontent.com', // Google Client ID
//   });
//   const payload = ticket.getPayload();
//   if (!payload?.email) {
//     throw new AppError(httpStatus.BAD_REQUEST, 'Invalid Google token');
//   }

//   let user = await User.findOne({ email: payload.email });
//   if (!user) {
//     user = await User.create({
//       email: payload.email,
//       fullName: payload.name,
//       isVerified: true,
//     });
//   }

//   const accessToken = jwt.sign(
//     { id: user._id, role: user.role },
//     config.jwt.jwt_access_secret as Secret,
//     { expiresIn: '24h' },
//   );
//   const refreshToken = jwt.sign(
//     { id: user._id, role: user.role },
//     config.jwt.jwt_refresh_secret as Secret,
//     { expiresIn: '7d' },
//   );

//   sendResponse(res, {
//     statusCode: httpStatus.OK,
//     success: true,
//     message: 'Google login successful',
//     data: {
//       user,
//       accessToken,
//       refreshToken,
//     },
//   });
// });

// const facebookLogin = catchAsync(async (req: Request, res: Response) => {
//   const { accessToken } = req.body;
//   if (!accessToken) {
//     throw new AppError(
//       httpStatus.BAD_REQUEST,
//       'Facebook accessToken is required',
//     );
//   }

//   // Verify token and get user info from Facebook
//   const fbRes = await axios.get(
//     `https://graph.facebook.com/me?fields=id,name,email&access_token=${accessToken}`,
//   );

//   console.log('FB DATA:', fbRes.data);

//   const { email, name } = fbRes.data;
//   if (!email) {
//     throw new AppError(
//       httpStatus.BAD_REQUEST,
//       'Unable to get email from Facebook',
//     );
//   }

//   let user = await User.findOne({ email });
//   if (!user) {
//     user = await User.create({
//       email,
//       fullName: name,
//       isVerified: true,
//     });
//   }

//   const accessTokenJwt = jwt.sign(
//     { id: user._id, role: user.role },
//     config.jwt.jwt_access_secret as Secret,
//     { expiresIn: '24h' },
//   );
//   const refreshToken = jwt.sign(
//     { id: user._id, role: user.role },
//     config.jwt.jwt_refresh_secret as Secret,
//     { expiresIn: '7d' },
//   );

//   sendResponse(res, {
//     statusCode: httpStatus.OK,
//     success: true,
//     message: 'Facebook login successful',
//     data: {
//       user,
//       accessToken: accessTokenJwt,
//       refreshToken,
//     },
//   });
// });







export const facebookLogin = catchAsync(
  async (req: Request, res: Response) => {
    const { accessToken } = req.body;

    if (!accessToken) {
      throw new AppError(
        httpStatus.BAD_REQUEST,
        'Facebook accessToken is required',
      );
    }

    // 🔹 Get user info from Facebook
    const fbRes = await axios.get(
      'https://graph.facebook.com/me',
      {
        params: {
          fields: 'id,name,email',
          access_token: accessToken,
        },
      },
    );

    console.log('FB DATA:', fbRes.data);

    const { id, name, email } = fbRes.data;

    // 🔹 Fallback email (VERY IMPORTANT)
    const finalEmail = email || `${id}@facebook.com`;

    // 🔹 Find or create user
    let user = await User.findOne({ email: finalEmail });

    if (!user) {
      user = await User.create({
        email: finalEmail,
        fullName: name,
        accountType: 'facebook', // অবশ্যই দিতে হবে
        isVerified: true,
        role: UserRole.customer,
      });
    }

    // 🔹 Generate JWT tokens
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

    // 🔹 Send response
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
  },
);



const linkedInLogin = catchAsync(async (req: Request, res: Response) => {
  const { accessToken } = req.body;

  if (!accessToken) {
    throw new AppError(httpStatus.BAD_REQUEST, "LinkedIn accessToken is required");
  }

  try {
    // 1. Get basic profile
    const profileRes = await axios.get("https://api.linkedin.com/v2/me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    // 2. Get email
    const emailRes = await axios.get(
      "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const email = emailRes.data.elements[0]["handle~"].emailAddress;
    const name = `${profileRes.data.localizedFirstName} ${profileRes.data.localizedLastName}`;

    if (!email) {
      throw new AppError(httpStatus.BAD_REQUEST, "Unable to get email from LinkedIn");
    }

    // 3. Find or create user
    let user = await User.findOne({ email });

    if (!user) {
      user = await User.create({
        email,
        fullName: name,
        isVerified: true,
        accountType: "linkedin", // important
        role: UserRole.customer,
      });
    }

    // 4. Generate tokens
    const accessTokenJwt = jwt.sign(
      { id: user._id, role: user.role },
      config.jwt.jwt_access_secret as Secret,
      { expiresIn: "24h" }
    );

    const refreshToken = jwt.sign(
      { id: user._id, role: user.role },
      config.jwt.jwt_refresh_secret as Secret,
      { expiresIn: "7d" }
    );

    // 5. Send response
    sendResponse(res, {
      statusCode: httpStatus.OK,
      success: true,
      message: "LinkedIn login successful",
      data: { user, accessToken: accessTokenJwt, refreshToken },
    });
  } catch (err) {
    console.error(err);
    throw new AppError(httpStatus.INTERNAL_SERVER_ERROR, "LinkedIn login failed");
  }
});




export const appleLogin = catchAsync(async (req: Request, res: Response) => {
  const { identityToken } = req.body;

  if (!identityToken) {
    throw new AppError(httpStatus.BAD_REQUEST, 'Apple identity token is required');
  }

  // 🔹 Verify the Apple JWT
  let applePayload: ApplePayload;
  try {
    applePayload = await appleSignin.verifyIdToken(identityToken, {
      audience: config.apple.client_id, // Bundle ID (iOS) or Service ID (Web)
      ignoreExpiration: false,
    }) as ApplePayload;
  } catch (err) {
    throw new AppError(httpStatus.UNAUTHORIZED, 'Invalid Apple identity token');
  }

  console.log('Apple payload:', applePayload);

  const { sub: appleId, email, name } = applePayload;

  // 🔹 Fallback email if Apple doesn't provide it
  const finalEmail = email || `${appleId}@apple.com`;

  // 🔹 Find existing user
  let user = await User.findOne({ email: finalEmail });

  // 🔹 Create user if not found
  if (!user) {
    const fullName = name?.firstName
      ? `${name.firstName} ${name.lastName || ''}`
      : 'Apple User';

    user = await User.create({
      email: finalEmail,
      fullName,
      accountType: 'apple',
      isVerified: true,
      role: UserRole.customer,
    });
  }

  // 🔹 Generate JWT tokens
  const accessTokenJwt = jwt.sign(
    { id: user._id, role: user.role },
    config.jwt.jwt_access_secret as Secret,
    { expiresIn: '24h' }
  );

  const refreshToken = jwt.sign(
    { id: user._id, role: user.role },
    config.jwt.jwt_refresh_secret as Secret,
    { expiresIn: '7d' }
  );

  // 🔹 Send response
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'Apple login successful',
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

    if (!email) {
      throw new AppError(httpStatus.BAD_REQUEST, 'Email is required');
    }

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
   if (!email || !otp) {
      throw new AppError(httpStatus.BAD_REQUEST, 'Email and OTP are required');
    }

  await authServices.userVerifyOtp(email, Number(otp));
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'OTP verified successfully. You can now reset your password.',
    data: { email },
  });
});


export const userResetPassword = catchAsync(
  async (req: Request, res: Response) => {
    const { email, newPassword, confirmPassword } = req.body;

    if (!email || !newPassword || !confirmPassword) {
      throw new AppError(
        httpStatus.BAD_REQUEST,
        'Email, newPassword and confirmPassword are required',
      );
    }

    if (newPassword !== confirmPassword) {
      throw new AppError(httpStatus.BAD_REQUEST, 'Passwords do not match');
    }

    await userResetPasswordService(email, newPassword);

    sendResponse(res, {
      statusCode: httpStatus.OK,
      success: true,
      message: 'Password reset successful',
      data: {},
    });
  },
);

export const authControllers = {
  login,
  resetPassword,
  verifyOtpController,
  codeVerification,
  changePassword,
  refreshToken,
  linkedInLogin,
  googleLogin,
  facebookLogin,
  userRegistration,
  appleLogin,
  verifyEmailController,
};
