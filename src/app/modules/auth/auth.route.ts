import express from 'express'
import passport from 'passport'
import rateLimit from 'express-rate-limit'
import { AuthControllers } from './auth.controller'
import validateRequest from '../../middleware/validateRequest'
import { AuthValidations } from './auth.validation'
import { USER_ROLES } from '../../../enum/user'
import auth from '../../middleware/auth'

const router = express.Router()

// ─── Rate Limiters ───────────────────────────────────────────────────────────

const createLimiter = (max: number, windowMinutes: number = 15) => 
  rateLimit({
    windowMs: windowMinutes * 60 * 1000,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      success: false,
      message: `Too many attempts from this IP, please try again after ${windowMinutes} minutes.`,
    },
  })

const signupLimiter = createLimiter(5)     // 5 signups per 15 min
const loginLimiter = createLimiter(10)     // 10 logins per 15 min
const otpLimiter = createLimiter(5)       // 5 OTP requests per 15 min
const forgetPwdLimiter = createLimiter(3)  // 3 requests per 15 min

// ─── Routes ──────────────────────────────────────────────────────────────────

router.post(
  '/signup',
  signupLimiter,
  validateRequest(AuthValidations.signupZodSchema),
  AuthControllers.signup,
)

router.post(
  '/login',
  loginLimiter,
  validateRequest(AuthValidations.loginZodSchema),
  AuthControllers.login,
)

router.post(
  '/admin-login',
  loginLimiter,
  validateRequest(AuthValidations.loginZodSchema),
  AuthControllers.adminLogin,
)

router.post(
  '/social-login',
  loginLimiter,
  validateRequest(AuthValidations.socialLoginZodSchema),
  AuthControllers.socialLogin,
)

// Google OAuth
router.get(
  '/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }),
)

router.get(
  '/google/callback',
  passport.authenticate('google', { session: false }),
  AuthControllers.googleAuthCallback,
)

// Verification
router.post(
  '/verify-account',
  otpLimiter,
  validateRequest(AuthValidations.verifyAccountZodSchema),
  AuthControllers.verifyAccount,
)

router.post(
  '/resend-otp',
  auth(USER_ROLES.GUEST),
  otpLimiter,
  validateRequest(AuthValidations.resendOtpZodSchema),
  AuthControllers.resendOtp,
)

// Password Management
router.post(
  '/forget-password',
  forgetPwdLimiter,
  validateRequest(AuthValidations.forgetPasswordZodSchema),
  AuthControllers.forgetPassword,
)

router.post(
  '/reset-password',
  validateRequest(AuthValidations.resetPasswordZodSchema),
  AuthControllers.resetPassword,
)

router.post(
  '/change-password',
  auth(USER_ROLES.ADMIN, USER_ROLES.USER, USER_ROLES.CUSTOMER),
  validateRequest(AuthValidations.changePasswordZodSchema),
  AuthControllers.changePassword,
)

// Account Management
router.delete(
  '/delete-account',
  auth(USER_ROLES.ADMIN, USER_ROLES.USER, USER_ROLES.CUSTOMER),
  validateRequest(AuthValidations.deleteAccountZodSchema),
  AuthControllers.deleteAccount,
)

router.post('/refresh-token', AuthControllers.refreshToken)

export const AuthRoutes = router
