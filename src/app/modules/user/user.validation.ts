import { z } from 'zod';

// Main user schema
const createUserZodSchema = z.object({
  body: z.object({
    email: z.string().email(),
    image: z
      .object({
        id: z.number(),
        url: z.string().url(),
      })
      .optional(),
    fullName: z.string().min(1),
    password: z.string().min(6),
    countryCode: z.string(),
    phoneNumber: z.string(),
    needsPasswordChange: z.boolean().optional(),
    passwordChangedAt: z.coerce.date().optional(),
    accountType: z
      .enum(['custom', 'google', 'facebook'])
      .optional()
      .default('custom'),
    // role: z.enum(Object.values(UserRole) as [string, ...string[]]),
    isActive: z.boolean().optional().default(true),
    isVerified: z.boolean().optional().default(false),
    isDeleted: z.boolean().optional().default(false),
    verification: z
      .object({
        otp: z.number(),
        expiresAt: z.coerce.date(),
        status: z.boolean(),
      })
      .optional(),
  }),
});

const userValidation = {
  createUserZodSchema,
};

export default userValidation;
