import { Router } from 'express';

import { adminControllers } from './admin.controller';
// import upload from '../../../middleware/fileUpload';
import auth from '../../../middleware/auth.middleware';
import { getYoutubeChannelDataController } from './admin.service';

const router = Router();

router.post('/adminRegister', adminControllers.adminRegister);

router.post('/login', adminControllers.adminLogin);
router.get('/me', auth('admin'), adminControllers.getProfile);

router.patch('/update-profile',auth('admin', 'super_admin'),//   upload.single('file'),
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


router.get("/youtube/:username",getYoutubeChannelDataController);

export const adminRoutes = router;
