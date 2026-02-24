import { Request, Response } from "express";
import catchAsync from "../../../utils/catchAsync";
import AppError from "../../../error/AppError";
import { Admin } from "./admin.model";
import httpStatus from 'http-status';
import sendResponse from "../../../utils/sendResponse";
import jwt from 'jsonwebtoken';
import { adminService } from "./admin.service";
import config from "../../../config";
import { sendEmail } from "../../../utils/mailSender";


// import { Request, Response } from 'express';
// import catchAsync from '../../../utils/catchAsync';
// import sendResponse from '../../../utils/sendResponse';
// import httpStatus from 'http-status';
// import { Admin } from './admin.model';

// import config from '../../../config';

// import AppError from '../../../error/AppError';
// import { uploadToS3 } from '../../../utils/fileHelper';




export const adminRegister = catchAsync( async (req: Request, res: Response) => {
    const { email, password, role, fullName, phoneNumber } = req.body;

    // 🔎 Check admin already exists
    const isAdminExist = await Admin.findOne({ email });
    if (isAdminExist) {
      throw new AppError(httpStatus.CONFLICT, 'Admin already exists');
    }

    // 🧾 Create admin (password auto hash হবে)
    const admin = await Admin.create({
      email,
      password,
      role, // admin / super_admin
      fullName,
      phoneNumber,
    });

    sendResponse(res, {
      statusCode: httpStatus.CREATED,
      success: true,
      message: 'Admin registered successfully',
      data: {
        id: admin._id,
        email: admin.email,
        role: admin.role,
      },
    });
  },
);












const adminLogin = catchAsync(async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const admin = await Admin.findOne({ email }).select('+password');
  if (!admin) throw new AppError(httpStatus.NOT_FOUND, 'Admin not found');

  const isMatch = await admin.isPasswordMatched(password);
  if (!isMatch)
    throw new AppError(httpStatus.UNAUTHORIZED, 'Incorrect password');

  const token = jwt.sign(
    { id: admin._id, role: admin.role },
    config.jwt.jwt_access_secret as string,
    {
      expiresIn: config.jwt.jwt_access_expires_in as jwt.SignOptions['expiresIn'],
    },
  );

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'Admin login successful',
    data: {
      admin: {
        id: admin._id,
        email: admin.email,
        role: admin.role,
      },
      token,
    },
  });
});


const getProfile = catchAsync(async (req: Request, res: Response) => {
  const admin = await Admin.findById(req.user.id).select('-password');
  if (!admin) {
    throw new AppError(httpStatus.NOT_FOUND, 'Admin not found');
  }

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'Admin profile retrieved successfully',
    data: admin,
  });
});

const updateProfile = catchAsync(async (req: Request, res: Response) => {
  // let image;
  // if (req.file) {
  //   image = await uploadToS3(req.file, 'admin-profile/');
  // }

  const result = await adminService.updateAdminProfile(req.user.id, {
    ...req.body,
    // ...(image && { image }),
  });

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'Profile updated',
    data: result,
  });
});

const changePassword = catchAsync(async (req: Request, res: Response) => {
  await adminService.changePassword(
    req.user.id,
    req.body.oldPassword,
    req.body.newPassword,
  );
  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'Password changed successfully',
    data: {},
  });
});

const verifiedAdmins = new Map<string, string>();

// global in-memory Map (for demo only)
const otpStore = new Map<string, string>();

const forgotPassword = catchAsync(async (req: Request, res: Response) => {
  const otp = await adminService.setForgotOtp(req.body.email);
  otpStore.set(otp.toString(), req.body.email); // store otp → email

await sendEmail(
  req.body.email,
  'Admin Password Reset OTP',
  `Your OTP is ${otp}. It is valid for 10 minutes.` // <=== html/string argument
);

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'OTP sent successfully, please verify before reset password',
    data: { otp },
  });
});

const verifyOtp = catchAsync(async (req: Request, res: Response) => {
  const { otp } = req.body;

  const email = otpStore.get(otp.toString());
  if (!email) {
    throw new AppError(400, 'OTP mismatch or expired');
  }

  await adminService.verifyOtp(email, otp);
  otpStore.delete(otp.toString()); // optional cleanup
  verifiedAdmins.set(email, 'VERIFIED');

  const token = jwt.sign({ email }, config.jwt.jwt_access_secret as string,{
    expiresIn: '15m',
  });

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'OTP verified. Use this token to reset password.',
    data: { token },
  });
});

const resetPassword = catchAsync(async (req: Request, res: Response) => {
  const { newPassword, confirmPassword } = req.body;

  if (newPassword !== confirmPassword)
    throw new AppError(400, 'Passwords do not match');

  // Find verified email
  const matchedEmail = [...verifiedAdmins.entries()].find(
    ([email, status]) => status === 'VERIFIED',
  )?.[0];

  if (!matchedEmail) throw new AppError(400, 'OTP not verified');

  await adminService.resetPassword(matchedEmail, newPassword);
  verifiedAdmins.delete(matchedEmail); // Clean up

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'Password reset successful',
    data: {},
  });
});







// social.service.ts
import axios from "axios";

// keep the key in an environment variable, fallback to hard‑coded only for local testing
const YOUTUBE_API_KEY = process.env.YOUTUBE_API_KEY || "AIzaSyAMLTu3H38-hb9jnUREr28YNB5KeHI4eyA";

// helper: strip @ and whitespace, try to extract a channel ID when possible
function normalizeInput(input: string): string {
  let value = input.trim();
  // remove leading @ if present
  if (value.startsWith("@")) {
    value = value.slice(1);
  }
  // if the user pasted a full URL, pull out the last segment
  const urlMatch = value.match(/(?:youtube\.com\/(?:channel\/|user\/|@)?)([A-Za-z0-9_-]+)/i);
  if (urlMatch && urlMatch[1]) {
    value = urlMatch[1];
  }
  return value;
}

// simple pattern to detect a channel ID (usually starts with UC and is ~24 chars)
function looksLikeChannelId(str: string): boolean {
  return /^UC[a-zA-Z0-9_-]{22,}$/i.test(str);
}

export const getYoutubeChannelDataService = async (input: string) => {
  const clean = normalizeInput(input);
  let channelId: string | null = null;

  // if the cleaned input already *looks* like a channel id we can skip search
  if (looksLikeChannelId(clean)) {
    channelId = clean;
  } else {
    // first try the search endpoint
    console.log("youtube service search q=", clean);
    const searchRes = await axios.get("https://www.googleapis.com/youtube/v3/search", {
      params: {
        part: "snippet",
        q: clean,
        type: "channel",
        maxResults: 1,
        key: YOUTUBE_API_KEY
      }
    });

    console.log("youtube search response", JSON.stringify(searchRes.data, null, 2));
    const searchItems = searchRes.data.items;
    if (searchItems && searchItems.length > 0) {
      channelId = searchItems[0].snippet.channelId;
    }
  }

  if (!channelId) {
    // attempt an old-style username lookup via forUsername parameter
    console.log("youtube service trying forUsername lookup", clean);
    try {
      const usernameRes = await axios.get("https://www.googleapis.com/youtube/v3/channels", {
        params: {
          part: "id",
          forUsername: clean,
          key: YOUTUBE_API_KEY
        }
      });
      const usernameItems = usernameRes.data.items;
      if (usernameItems && usernameItems.length > 0) {
        channelId = usernameItems[0].id;
      }
    } catch (e) {
      // ignore - we'll handle not found below
    }
  }

  if (!channelId) {
    console.warn("youtube service no channel id from input", clean);
    const err: any = new Error("CHANNEL_NOT_FOUND");
    err.code = "CHANNEL_NOT_FOUND";
    throw err;
  }

  // fetch full channel details
  const channelRes = await axios.get("https://www.googleapis.com/youtube/v3/channels", {
    params: {
      part: "snippet,statistics,contentDetails",
      id: channelId,
      key: YOUTUBE_API_KEY
    }
  });

  const items = channelRes.data.items;
  if (!items || items.length === 0) {
    const err: any = new Error("CHANNEL_NOT_FOUND");
    err.code = "CHANNEL_NOT_FOUND";
    throw err;
  }

  const channel = items[0];
  const uploadsPlaylistId = channel.contentDetails?.relatedPlaylists?.uploads;
  if (!uploadsPlaylistId) {
    const err: any = new Error("UPLOADS_PLAYLIST_NOT_FOUND");
    err.code = "UPLOADS_PLAYLIST_NOT_FOUND";
    throw err;
  }

  // fetch recent videos
  const videoRes = await axios.get("https://www.googleapis.com/youtube/v3/playlistItems", {
    params: {
      part: "snippet",
      playlistId: uploadsPlaylistId,
      maxResults: 10,
      key: YOUTUBE_API_KEY
    }
  });

  const videoItems = videoRes.data.items || [];

  return {
    channel: {
      id: channel.id,
      title: channel.snippet?.title || "No title",
      description: channel.snippet?.description || "",
      subscribers: channel.statistics?.subscriberCount || "0",
      views: channel.statistics?.viewCount || "0",
      videos: channel.statistics?.videoCount || "0",
      thumbnail: channel.snippet?.thumbnails?.high?.url || ""
    },
    videos: videoItems.map((item: any) => ({
      videoId: item.snippet?.resourceId?.videoId || "",
      title: item.snippet?.title || "No title",
      thumbnail: item.snippet?.thumbnails?.high?.url || "",
      publishedAt: item.snippet?.publishedAt || ""
    }))
  };
};















export const adminControllers = {
  adminRegister,
  adminLogin,
  updateProfile,
  changePassword,
  forgotPassword,
  verifyOtp,
  resetPassword,
  getProfile,
};