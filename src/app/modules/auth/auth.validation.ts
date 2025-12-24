import { z } from 'zod'
import { USER_ROLES } from '../../../enum/user'
import { VERIFICATION_TYPE } from '../verification/verification.interface'

const verifyAccountZodSchema = z.object({
  body: z.object({
    email: z
      .string()
      .optional()
      .refine(value => !value || /^\S+@\S+\.\S+$/.test(value), {
        message: 'Invalid email format',
      }),
    type: z.nativeEnum(VERIFICATION_TYPE, { required_error: "Verification type is requried." }),
    oneTimeCode: z.string().min(1, { message: 'OTP is required' }),
  }).strict(),
})

const forgetPasswordZodSchema = z.object({
  body: z.object({
    email: z.string().email({ message: 'Invalid email format.' }),
    phone: z
      .string()
      .optional()
      .refine(value => !value || /^\+?[1-9]\d{1,14}$/.test(value), {
        message: 'Invalid phone number format',
      }),
  }),
})

const resetPasswordZodSchema = z.object({
  body: z.object({
    newPassword: z.string().min(8, { message: 'Password is required' }),
    confirmPassword: z
      .string()
      .min(8, { message: 'Confirm Password is required' }),
  }),
})

const loginZodSchema = z.object({
  body: z
    .object({
      email: z.string().email({ message: 'Invalid email format.' }),
      phone: z
        .string()
        .optional()
        .refine(value => !value || /^\+?[1-9]\d{1,14}$/.test(value), {
          message: 'Invalid phone number format',
        }),
      fcmToken: z.string().min(1).optional(),
      password: z.string().min(6, { message: "Password is required, and must be 6 character long." }),
    })
    .strict(),
})

const resendOtpZodSchema = z.object({
  body: z.object({
    email: z
      .string()
      .optional()
      .refine(value => !value || /^\S+@\S+\.\S+$/.test(value), {
        message: 'Invalid email format',
      }),
    phone: z
      .string()
      .optional()
      .refine(value => !value || /^\+?[1-9]\d{1,14}$/.test(value), {
        message: 'Invalid phone number format',
      }),
    type: z.nativeEnum(VERIFICATION_TYPE, { required_error: "Verification type is requried." }),

  }),
})

const changePasswordZodSchema = z.object({
  body: z
    .object({
      currentPassword: z.string({
        required_error: 'Current password is required',
      }),
      newPassword: z
        .string({
          required_error: 'New password is required',
        })
        .min(8, 'Password must be at least 8 characters'),
      confirmPassword: z.string({
        required_error: 'Confirm password is required',
      }),
    })
    .refine(data => data.newPassword === data.confirmPassword, {
      message: 'Passwords do not match',
      path: ['confirmPassword'],
    }),
})

const deleteAccount = z.object({
  body: z.object({
    password: z.string({
      required_error: 'Password is required',
    }),
  }),
})

const createUserZodSchema = z.object({
  body: z
    .object({
      email: z
        .string({ required_error: 'Email is required' })
        .email({ message: 'Invalid email format' }),
      password: z
        .string({ required_error: 'Password is required' })
        .min(6, { message: 'Password must be at least 6 characters' })
        .max(20, { message: 'Password must be at most 20 characters' })
        .regex(/^(?=.*[A-Za-z])(?=.*\d)/, {
          message: 'Password must contain at least one letter and one number',
        }),
      name: z.string({ required_error: 'Name is required' }),
      phone: z.string({ required_error: 'Phone is required' }).optional(),
      address: z.string().optional(),
      role: z.enum(
        [
          USER_ROLES.ADMIN,
          USER_ROLES.USER,
          USER_ROLES.GUEST,
          USER_ROLES.CUSTOMER,
        ],
        {
          message: 'Role must be one of admin, user, guest',
        },
      ),
    })
    .strict(),
})

const socialLoginZodSchema = z.object({
  body: z.object({
    appId: z.string({ required_error: 'App ID is required' }),
    fcmToken: z.string({ required_error: 'Device token is required' }),
  }),
})

export const AuthValidations = {
  verifyAccountZodSchema,
  forgetPasswordZodSchema,
  resetPasswordZodSchema,
  loginZodSchema,
  resendOtpZodSchema,
  changePasswordZodSchema,
  createUserZodSchema,
  deleteAccount,
  socialLoginZodSchema,
}
