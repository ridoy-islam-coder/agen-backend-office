import { Router } from 'express';




const router = Router();
const moduleRoutes = [
  {
    path: '/users',
    route: userRoutes,
  },

  {
    path: '/auth',
    route: authRoutes,
  },
  {
    path: '/admin',
    route: adminRoutes,
  },
  {
    path: '/rules',
    route: ruleRoutes,
  },
  {
    path: '/subscription',
    route: SubscriptionRoutes,
  },
  {
    path: '/payment',
    route: PaymentRoutes,
  },
  {
    path: '/otp',
    route: otpRoutes,
  },
  {
    path: '/wallet',
    route: walletRoutes,
  },
  {
    path: '/notifications',
    route: NotificationRoutes,
  },
  {
    path: '/onboarding',
    route: onboardingRoutes,
  },
];
moduleRoutes.forEach((route) => router.use(route.path, route.route));

export default router;
