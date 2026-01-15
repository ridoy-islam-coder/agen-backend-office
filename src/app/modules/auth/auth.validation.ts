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

// const loginZodSchema = z.object({
//   body: z.object({
//     email: z.string({ required_error: 'Email is required' }).email(),
//     password: z.string({ required_error: 'Password is required' }),
//   }),
// });

// const refreshTokenValidationSchema = z.object({
//   body: z.object({
//     refreshToken: z.string({ required_error: 'Refresh token is required' }),
//   }),
// });

// const changePasswordZodSchema = z.object({
//   body: z.object({
//     oldPassword: z.string({ required_error: 'Old password is required' }),
//     newPassword: z
//       .string({ required_error: 'New password is required' })
//       .min(6, 'Password must be at least 6 characters'),
//   }),
// });

// const resetPasswordZodSchema = z
//   .object({
//     body: z.object({
//       newPassword: z
//         .string({ required_error: 'New password is required' })
//         .min(6, 'Password must be at least 6 characters'),
//       confirmPassword: z.string({
//         required_error: 'Confirm password is required',
//       }),
//     }),
//   })
//   .refine((data) => data.body.newPassword === data.body.confirmPassword, {
//     message: 'Passwords do not match',
//     path: ['body.confirmPassword'],
//   });

// const forgotPasswordZodSchema = z.object({
//   body: z.object({
//     email: z.string().email({ message: 'Must be a valid email address' }),
//   }),
// });

// const deleteAccountZodSchema = z.object({
//   body: z.object({
//     password: z.string({ required_error: 'Password is required' }),
//   }),
// });

export const registerZodSchema = z.object({
  body: z.object({
    email: z
      .string()
      .nonempty('Email is required')
      .email('Must be a valid email'),

    password: z
      .string()
      .nonempty('Password is required')
      .min(6, 'Password must be at least 6 characters'),

    fullName: z
      .string()
      .nonempty('Full name is required'),

    phoneNumber: z
      .string()
      .nonempty('Phone number is required'),

    countryCode: z
      .string()
      .nonempty('Country code is required'),

    // gender: z
    //   .enum(['Male', 'Female'], {
    //     required_error: 'Gender is required',
    //   }),
  }),
});


export const verifyEmailZodSchema = z.object({
  body: z.object({
    email: z
      .string()
      .nonempty('Email is required')
      .email('Must be a valid email'),

    otp: z
      .number()
      .refine((val) => val !== undefined && val !== null, {
        message: 'OTP is required',
      }),
  }),
});

export const loginZodSchema = z.object({
  body: z.object({
    email: z.string().nonempty('Email is required').email('Must be a valid email'),
    password: z.string().nonempty('Password is required'),
  }),
});

export const refreshTokenValidationSchema = z.object({
  body: z.object({
    refreshToken: z.string().nonempty('Refresh token is required'),
  }),
});

export const changePasswordZodSchema = z.object({
  body: z.object({
    oldPassword: z.string().nonempty('Old password is required'),
    newPassword: z.string().nonempty('New password is required').min(6, 'Password must be at least 6 characters'),
  }),
});

export const resetPasswordZodSchema = z
  .object({
    body: z.object({
      newPassword: z.string().nonempty('New password is required').min(6, 'Password must be at least 6 characters'),
      confirmPassword: z.string().nonempty('Confirm password is required'),
    }),
  })
  .refine((data) => data.body.newPassword === data.body.confirmPassword, {
    message: 'Passwords do not match',
    path: ['body.confirmPassword'],
  });

export const forgotPasswordZodSchema = z.object({
  body: z.object({
    email: z.string().nonempty('Email is required').email('Must be a valid email address'),
  }),
});

export const deleteAccountZodSchema = z.object({
  body: z.object({
    password: z.string().nonempty('Password is required'),
  }),
});
export const authValidation = {
  registerZodSchema,
  verifyEmailZodSchema,
  loginZodSchema,
  refreshTokenValidationSchema,
  changePasswordZodSchema,
  resetPasswordZodSchema,
  forgotPasswordZodSchema,
  deleteAccountZodSchema,
};
