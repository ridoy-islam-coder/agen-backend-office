// import { z } from 'zod';

// const refreshTokenValidationSchema = z.object({
//   cookies: z.object({
//     refreshToken: z.string({
//       required_error: 'Refresh token is required!',
//     }),
//   }),
// });
// const loginZodSchema = z.object({
//   body: z.object({
//     email: z.string().email({ message: 'Invalid email address' }),
//     password: z
//       .string()
//       .min(6, { message: 'Password must be at least 6 characters' }),
//   }),
// });
// const deleteAccountZodSchema = z.object({
//   body: z.object({
//     password: z.string({
//       required_error: 'Password is required',
//     }),
//   }),
// });
// export const authValidation = {
//   refreshTokenValidationSchema,
//   loginZodSchema,
//   deleteAccountZodSchema,
// };
import { z } from 'zod';

const loginZodSchema = z.object({
  body: z.object({
    email: z.string({ required_error: 'Email is required' }).email(),
    password: z.string({ required_error: 'Password is required' }),
  }),
});

const refreshTokenValidationSchema = z.object({
  body: z.object({
    refreshToken: z.string({ required_error: 'Refresh token is required' }),
  }),
});

const changePasswordZodSchema = z.object({
  body: z.object({
    oldPassword: z.string({ required_error: 'Old password is required' }),
    newPassword: z
      .string({ required_error: 'New password is required' })
      .min(6, 'Password must be at least 6 characters'),
  }),
});

const resetPasswordZodSchema = z
  .object({
    body: z.object({
      newPassword: z
        .string({ required_error: 'New password is required' })
        .min(6, 'Password must be at least 6 characters'),
      confirmPassword: z.string({
        required_error: 'Confirm password is required',
      }),
    }),
  })
  .refine((data) => data.body.newPassword === data.body.confirmPassword, {
    message: 'Passwords do not match',
    path: ['body.confirmPassword'],
  });

const forgotPasswordZodSchema = z.object({
  body: z.object({
    email: z.string().email({ message: 'Must be a valid email address' }),
  }),
});

const deleteAccountZodSchema = z.object({
  body: z.object({
    password: z.string({ required_error: 'Password is required' }),
  }),
});

export const authValidation = {
  loginZodSchema,
  refreshTokenValidationSchema,
  changePasswordZodSchema,
  resetPasswordZodSchema,
  forgotPasswordZodSchema,
  deleteAccountZodSchema,
};
