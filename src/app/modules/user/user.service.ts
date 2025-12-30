import AppError from "../../error/AppError";
import  httpStatus  from 'http-status';
import User from "./user.model";
import { TUser } from "./user.interface";
import bcrypt from "bcrypt";
import QueryBuilder from "../../builder/QueryBuilder";
import { subMonths, startOfMonth } from 'date-fns';




const getme = async (id: string) => {
  const result = await User.findById(id);

  if (!result) {
    throw new AppError(httpStatus.NOT_FOUND, 'User not found');
  }

  return {
    email: result.email,
    fullName: result.fullName,
    countryCode: result.countryCode,
    phoneNumber: result.phoneNumber,
    image: result.image ?? {},
  };
};

//update user profile

const updateProfile = async (id: string, payload: Partial<TUser>) => {
  const user = await User.findById(id);
  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'User not found');
  }

  const restrictedFields = ['phoneNumber', 'role', 'email'];
  restrictedFields.forEach((field) => {
    if (field in payload) {
      throw new AppError(
        httpStatus.BAD_REQUEST,
        `${field} is not allowed to update`,
      );
    }
  });

  // Allow updating image, fullName, gender
  const updatedUser = await User.findByIdAndUpdate(id, payload, {
    new: true,
  });

  return updatedUser;
};

const getAllUsers = async (query: Record<string, any>) => {
  const usersQuery = new QueryBuilder(
    User.find({ isDeleted: { $ne: true } }),
    query,
  )
    .search(['fullName', 'email', 'phoneNumber']) // searchable fields
    .filter()
    .paginate()
    .sort()
    .fields();

  const data = await usersQuery.modelQuery;
  const meta = await usersQuery.countTotal();

  return { data, meta };
};

const getSingleUser = async (id: string) => {
  const result = await User.findById(id);

  if (!result || result.isDeleted) {
    throw new AppError(httpStatus.NOT_FOUND, 'User not found');
  }

  return result;
};

const deleteAccount = async (id: string, password: string) => {
  const user = await User.IsUserExistbyId(id);

  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'User not found');
  }

  const isPasswordMatched = await bcrypt.compare(password, user.password);

  if (!isPasswordMatched) {
    throw new AppError(httpStatus.NOT_ACCEPTABLE, 'Password does not match!');
  }

  const result = await User.findByIdAndUpdate(
    id,
    { $set: { isDeleted: true } },
    { new: true },
  );

  return result;
};

const updatePhoneNumber = async (id: string, payload: Partial<TUser>) => {
  const allowedPayload = {
    phoneNumber: payload.phoneNumber,
    countryCode: payload.countryCode,
  };

  const result = await User.findByIdAndUpdate(id, allowedPayload, {
    new: true,
  });

  return result;
};
//Get total users count excluding soft-deleted users
const getTotalUsersCount = async () => {
  const count = await User.countDocuments({ isDeleted: { $ne: true } });
  return count;
};
//Get monthly user starts
const getMonthlyUserStats = async () => {
  const startOfCurrentMonth = new Date();
  startOfCurrentMonth.setDate(1);
  startOfCurrentMonth.setHours(0, 0, 0, 0);

  const startOfPreviousMonth = new Date(startOfCurrentMonth);
  startOfPreviousMonth.setMonth(startOfPreviousMonth.getMonth() - 1);

  const endOfPreviousMonth = new Date(startOfCurrentMonth);

  const currentMonthUsers = await User.countDocuments({
    isDeleted: { $ne: true },
    createdAt: { $gte: startOfCurrentMonth },
  });

  const previousMonthUsers = await User.countDocuments({
    isDeleted: { $ne: true },
    createdAt: { $gte: startOfPreviousMonth, $lt: startOfCurrentMonth },
  });

  const difference = currentMonthUsers - previousMonthUsers;
  const percentageChange =
    previousMonthUsers > 0
      ? (difference / previousMonthUsers) * 100
      : currentMonthUsers > 0
        ? 100
        : 0;

  return {
    currentCount: currentMonthUsers,
    previousCount: previousMonthUsers,
    percentageChange: parseFloat(percentageChange.toFixed(2)),
    trend: percentageChange >= 0 ? 'up' : 'down',
  };
};
const getUsersLast12Months = async (year?: number) => {
  const now = new Date();
  const baseDate = year ? new Date(year, 11, 31) : now;
  const start = startOfMonth(subMonths(baseDate, 11));

  const users = await User.aggregate([
    {
      $match: {
        isDeleted: { $ne: true },
        createdAt: { $gte: start, $lte: baseDate },
      },
    },
    {
      $group: {
        _id: {
          year: { $year: '$createdAt' },
          month: { $month: '$createdAt' },
        },
        total: { $sum: 1 },
      },
    },
    {
      $sort: {
        '_id.year': 1,
        '_id.month': 1,
      },
    },
  ]);

  const data: { month: string; total: number }[] = [];
  for (let i = 11; i >= 0; i--) {
    const date = subMonths(baseDate, i);
    const month = date.toLocaleString('default', { month: 'short' });
    const year = date.getFullYear();

    const found = users.find(
      (u) => u._id.year === year && u._id.month === date.getMonth() + 1,
    );

    data.push({ month, total: found?.total || 0 });
  }

  return data;
};

const getUserGrowthPercentage = async (year?: number) => {
  const users = await getUsersLast12Months(year);
  const first = users[0]?.total || 0;
  const last = users[11]?.total || 0;

  const difference = last - first;
  const percentageChange =
    first > 0 ? (difference / first) * 100 : last > 0 ? 100 : 0;

  return {
    users,
    growthPercentage: parseFloat(percentageChange.toFixed(2)),
    trend: percentageChange >= 0 ? 'up' : 'down',
  };
};
const blockUser = async (id: string) => {
  const user = await User.findById(id);
  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'User not found');
  }

  if (user.role === 'admin' || user.role === 'super_admin') {
    throw new AppError(httpStatus.BAD_REQUEST, 'You cannot block an admin');
  }
  if (!user.isActive) {
    throw new AppError(httpStatus.BAD_REQUEST, 'User is already blocked');
  }
  user.isActive = false;
  await user.save();

  return user;
};

const unblockUser = async (id: string) => {
  const user = await User.findById(id);
  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, 'User not found');
  }
  if (user.isActive) {
    throw new AppError(httpStatus.BAD_REQUEST, 'User is already active');
  }

  user.isActive = true;
  await user.save();

  return user;
};

export const userServices = {
  getme,
  updateProfile,
  getSingleUser,
  deleteAccount,
  updatePhoneNumber,
  getAllUsers,
  getTotalUsersCount,
  getMonthlyUserStats,
  getUsersLast12Months,
  getUserGrowthPercentage,
  blockUser,
  unblockUser,
};
