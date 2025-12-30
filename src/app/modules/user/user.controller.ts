import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import { userServices } from "./user.service";
import sendResponse from "../../utils/sendResponse";
import httpStatus from 'http-status';

// Get current user's profile
const getme = catchAsync(async (req: Request, res: Response) => {
  const result = await userServices.getme(req.user.id);
  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'User retrieved successfully',
    data: result,
  });
});

// Update user phone number (only phoneNumber & countryCode allowed)
const updatePhoneNumber = catchAsync(async (req: Request, res: Response) => {
  const result = await userServices.updatePhoneNumber(req.user.id, req.body);
  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'Phone number updated successfully',
    data: result,
  });
});

// const updateProfile = catchAsync(async (req: Request, res: Response) => {
//   let image;

//   // Upload image if provided
//   if (req.file) {
//     image = await uploadToS3(req.file, 'profile/');
//   }

//   // Determine which user's profile is being updated
//   const isAdmin = req.user.role === 'admin' || req.user.role === 'sup_admin';
//   const userIdToUpdate = isAdmin && req.params.id ? req.params.id : req.user.id;

//   // 🔍 DEBUG: Log all relevant IDs
//   console.log('🔍 DEBUG - Profile Update:');
//   console.log('  - req.user.id:', req.user.id, typeof req.user.id);
//   console.log('  - req.params.id:', req.params.id, typeof req.params.id);
//   console.log('  - userIdToUpdate:', userIdToUpdate, typeof userIdToUpdate);
//   console.log('  - isAdmin:', isAdmin);

//   // If admin is updating their own profile, make gender optional
//   const isAdminUpdatingSelf = isAdmin && userIdToUpdate === req.user.id;

//   // Build update data
//   const updateData: Record<string, any> = {
//     ...req.body,
//     ...(image && { image }),
//   };

//   // Remove gender if admin is updating their own profile and gender is missing
//   if (isAdminUpdatingSelf && !req.body.gender) {
//     delete updateData.gender;
//   }

//   // Call the service to update
//   const result = await userServices.updateProfile(userIdToUpdate, updateData);

//   // ===== SOCKET.IO ROOM & SOCKET DEBUG LOGS =====
//   console.log('🔍 DEBUG - Socket Rooms:');
//   console.log('  - All rooms:', Array.from(io.sockets.adapter.rooms.keys()));

//   const roomExists = io.sockets.adapter.rooms.has(userIdToUpdate.toString());
//   console.log(
//     `  - Room for userIdToUpdate (${userIdToUpdate}) exists:`,
//     roomExists,
//   );

//   if (roomExists) {
//     const roomSockets = io.sockets.adapter.rooms.get(userIdToUpdate.toString());
//     console.log(
//       `  - Room ${userIdToUpdate} sockets count:`,
//       roomSockets?.size,
//       'Socket IDs:',
//       roomSockets ? Array.from(roomSockets) : [],
//     );
//   } else {
//     console.log(`❌ Room not found for userId: ${userIdToUpdate}`);
//   }

//   // ===== SAVE NOTIFICATION + EMIT REALTIME =====
//   try {
//     await saveNotification({
//       userId: userIdToUpdate.toString(),
//       title: 'Profile Updated',
//       userType: 'User',

//       message: 'Your profile has been updated successfully.',
//       type: 'profile',
//     });
//     console.log(`📤 Notification saved & emitted to room: ${userIdToUpdate}`);
//   } catch (error) {
//     console.error('❌ Error saving/emitting notification:', error);
//   }

//   // Respond with updated user info and context
//   sendResponse(res, {
//     statusCode: 200,
//     success: true,
//     message: 'Profile updated successfully',
//     data: {
//       updatedUser: result,
//       updatedBy: {
//         id: req.user.id,
//         role: req.user.role,
//         actingOn: userIdToUpdate,
//       },
//     },
//   });
// });

// Get single user (used by admin)
const getsingleUser = catchAsync(async (req: Request, res: Response) => {
  const result = await userServices.getSingleUser(req.params.id);
  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'User retrieved successfully',
    data: result,
  });
});

// Get all users (used by admin)
const getAllUsers = catchAsync(async (req: Request, res: Response) => {
  const result = await userServices.getAllUsers(req.query);

  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'Users retrieved successfully',
    data: result.data,
    meta: result.meta,
  });
});

// Delete own account (soft delete)
const deleteAccount = catchAsync(async (req: Request, res: Response) => {
  const result = await userServices.deleteAccount(
    req.user.id,
    req.body.password,
  );
  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'User account deleted successfully',
    data: result,
  });
});
//total users count by admin
const getTotalUsersCount = catchAsync(async (_req: Request, res: Response) => {
  const count = await userServices.getTotalUsersCount();
  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'Total users count fetched successfully',
    data: count,
  });
});
//monthly user starts by admin
const getMonthlyUserStats = catchAsync(async (_req: Request, res: Response) => {
  const result = await userServices.getMonthlyUserStats();
  sendResponse(res, {
    statusCode: 200,
    success: true,
    message: 'Monthly user stats fetched successfully',
    data: result,
  });
});
//Get 12-month user growth overview by admin
const getUserGrowthOverview = catchAsync(
  async (req: Request, res: Response) => {
    const year = req.query.year
      ? parseInt(req.query.year as string)
      : undefined;
    const result = await userServices.getUserGrowthPercentage(year);

    sendResponse(res, {
      statusCode: 200,
      success: true,
      message: '12-month user growth fetched successfully',
      data: result,
    });
  },
);
const blockUser = catchAsync(async (req: Request, res: Response) => {
  const result = await userServices.blockUser(req.params.id);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'User blocked successfully',
    data: result,
  });
});

const unblockUser = catchAsync(async (req: Request, res: Response) => {
  const result = await userServices.unblockUser(req.params.id);
  sendResponse(res, {
    statusCode: httpStatus.OK,
    success: true,
    message: 'User unblocked successfully',
    data: result,
  });
});

export const userControllers = {
  getme,
  updateProfile,
  getsingleUser,
  getAllUsers,
  deleteAccount,
  updatePhoneNumber,
  getTotalUsersCount,
  getMonthlyUserStats,
  getUserGrowthOverview,
  blockUser,
  unblockUser,
};
