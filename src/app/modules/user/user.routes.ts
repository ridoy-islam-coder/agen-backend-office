import { Router } from "express";
import auth from "../../middleware/auth.middleware";
import { USER_ROLE } from "./user.constant";
import { userControllers } from "./user.controller";
import validateRequest from "../../middleware/validateRequest";
import { authValidation } from "../auth/auth.validation";

const router = Router();

// For login user (user & admin both)
router.patch(
  '/update-profile',
  auth(USER_ROLE.user, USER_ROLE.admin, USER_ROLE.sup_admin),
//   upload.single('file'),
  userControllers.updateProfile,
);
//toatal user count
router.get(
  '/total-count',
  auth(USER_ROLE.admin, USER_ROLE.sup_admin),
  userControllers.getTotalUsersCount,
);
router.get(
  '/monthly-user-stats',
  auth(USER_ROLE.admin),
  userControllers.getMonthlyUserStats,
);
router.get(
  '/user-growth-overview',
  auth(USER_ROLE.admin),
  userControllers.getUserGrowthOverview,
);

// For admin to update others
router.patch(
  '/:id',
  auth(USER_ROLE.admin, USER_ROLE.sup_admin),
//   upload.single('file'),
  userControllers.updateProfile,
);

router.patch(
  '/phone/update',
  auth(USER_ROLE.user),
  userControllers.updatePhoneNumber,
);
router.get(
  '/profile',
  auth(USER_ROLE.admin, USER_ROLE.user),
  userControllers.getme,
);
// Block user
router.patch(
  '/block/:id',
  auth(USER_ROLE.admin, USER_ROLE.sup_admin),
  userControllers.blockUser,
);

// Unblock user
router.patch(
  '/unblock/:id',
  auth(USER_ROLE.admin, USER_ROLE.sup_admin),
  userControllers.unblockUser,
);

router.get(
  '/:id',
  auth(USER_ROLE.vendor, USER_ROLE.admin),
  userControllers.getsingleUser,
);
router.get(
  '/',
  auth(USER_ROLE.vendor, USER_ROLE.admin),
  userControllers.getAllUsers,
);

router.delete(
  '/',
  auth(USER_ROLE.user, USER_ROLE.sup_admin, USER_ROLE.admin),
  validateRequest(authValidation.deleteAccountZodSchema),
  userControllers.deleteAccount,
);
export const userRoutes = router;