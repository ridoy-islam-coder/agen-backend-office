import { Router } from 'express';

import { adminControllers } from './admin.controller';
// import upload from '../../../middleware/fileUpload';
import auth from '../../../middleware/auth.middleware';

const router = Router();

router.post('/login', adminControllers.adminLogin);
router.get('/me', auth('admin'), adminControllers.getProfile);

router.patch(
  '/update-profile',
  auth('admin', 'super_admin'),
//   upload.single('file'),
  adminControllers.updateProfile,
);
router.patch(
  '/change-password',
  auth('admin', 'super_admin'),
  adminControllers.changePassword,
);
router.post('/forgot-password', adminControllers.forgotPassword);
router.post('/verify-otp', adminControllers.verifyOtp);
router.post('/reset-password', adminControllers.resetPassword);

export const adminRoutes = router;
