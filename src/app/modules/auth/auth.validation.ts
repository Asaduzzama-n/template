import { z } from 'zod'
import { USER_ROLES } from '../../../enum/user'
import { VERIFICATION_TYPE } from '../verification/verification.interface'

const passwordSchema = z
  .string({ required_error: 'Password is required' })
  .min(8, { message: 'Password must be at least 8 characters' })
  .max(64, { message: 'Password must be at most 64 characters' })
  .regex(/[A-Z]/, { message: 'Password must contain at least one uppercase letter' })
  .regex(/[a-z]/, { message: 'Password must contain at least one lowercase letter' })
  .regex(/\d/, { message: 'Password must contain at least one number' })
  .regex(/[@$!%*?&#^()_\-+={}\[\]|:;<>,.?/~`]/, {
    message: 'Password must contain at least one special character',
  })

const signupZodSchema = z.object({
  body: z
    .object({
      name: z.string({ required_error: 'Name is required' }).trim().min(2),
      email: z
        .string({ required_error: 'Email is required' })
        .email({ message: 'Invalid email format' })
        .toLowerCase(),
      password: passwordSchema,
      phone: z.string().optional(),
      address: z.string().optional(),
      role: z.enum([USER_ROLES.ADMIN, USER_ROLES.USER, USER_ROLES.CUSTOMER], {
        errorMap: () => ({ message: 'Invalid user role selected' }),
      }).default(USER_ROLES.USER),
    })
    .strict(),
})

const loginZodSchema = z.object({
  body: z
    .object({
      email: z.string().email({ message: 'Invalid email format' }).toLowerCase(),
      password: z.string().min(1, 'Password is required'),
      fcmToken: z.string().optional(),
    })
    .strict(),
})

const verifyAccountZodSchema = z.object({
  body: z
    .object({
      email: z.string().email().toLowerCase(),
      type: z.nativeEnum(VERIFICATION_TYPE),
      oneTimeCode: z.string().min(1, 'OTP is required'),
    })
    .strict(),
})

const forgetPasswordZodSchema = z.object({
  body: z
    .object({
      email: z.string().email().toLowerCase(),
    })
    .strict(),
})

const resetPasswordZodSchema = z.object({
  body: z
    .object({
      newPassword: passwordSchema,
      confirmPassword: z.string(),
    })
    .strict()
    .refine((data) => data.newPassword === data.confirmPassword, {
      message: 'Passwords do not match',
      path: ['confirmPassword'],
    }),
})

const changePasswordZodSchema = z.object({
  body: z
    .object({
      currentPassword: z.string().min(1, 'Current password is required'),
      newPassword: passwordSchema,
      confirmPassword: z.string(),
    })
    .strict()
    .refine((data) => data.newPassword === data.confirmPassword, {
      message: 'New passwords do not match',
      path: ['confirmPassword'],
    }),
})

const resendOtpZodSchema = z.object({
  body: z
    .object({
      email: z.string().email().toLowerCase(),
      type: z.nativeEnum(VERIFICATION_TYPE),
    })
    .strict(),
})

const socialLoginZodSchema = z.object({
  body: z
    .object({
      appId: z.string().min(1, 'App ID is required'),
      fcmToken: z.string().min(1, 'FCM token is required'),
    })
    .strict(),
})

const deleteAccountZodSchema = z.object({
  body: z
    .object({
      password: z.string().min(1, 'Password is required to confirm deletion'),
    })
    .strict(),
})

export const AuthValidations = {
  signupZodSchema,
  loginZodSchema,
  verifyAccountZodSchema,
  forgetPasswordZodSchema,
  resetPasswordZodSchema,
  changePasswordZodSchema,
  resendOtpZodSchema,
  socialLoginZodSchema,
  deleteAccountZodSchema,
}
