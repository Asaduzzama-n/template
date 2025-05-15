import express from 'express'
import passport from 'passport'
import { PassportAuthController } from './passport.auth/passport.auth.controller'

import { CustomAuthController } from './custom.auth/custom.auth.controller'
import validateRequest from '../../middleware/validateRequest'
import { AuthValidations } from './auth.validation'
import { USER_ROLES } from '../../../enum/user'
import auth, { tempAuth } from '../../middleware/auth'

const router = express.Router()

router.post(
  '/signup',
  validateRequest(AuthValidations.createUserZodSchema),
  CustomAuthController.createUser,
)

router.post(
  '/login',
  validateRequest(AuthValidations.loginZodSchema),
  passport.authenticate('local', { session: false }),
  PassportAuthController.login,
)

router.get(
  '/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }),
)

router.get(
  '/google/callback',
  passport.authenticate('google', { session: false }),
  PassportAuthController.googleAuthCallback,
)

router.post(
  '/verify-account',
  tempAuth(
    USER_ROLES.ADMIN,
    USER_ROLES.USER,
    USER_ROLES.GUEST,
    USER_ROLES.CUSTOMER,
  ),
  validateRequest(AuthValidations.verifyAccountZodSchema),
  CustomAuthController.verifyAccount,
)

router.post(
  '/custom-login',
  validateRequest(AuthValidations.loginZodSchema),
  CustomAuthController.customLogin,
)

router.post(
  '/forget-password',
  validateRequest(AuthValidations.resetPasswordZodSchema),
  CustomAuthController.forgetPassword,
)
router.post(
  '/reset-password',
  tempAuth(
    USER_ROLES.ADMIN,
    USER_ROLES.USER,
    USER_ROLES.GUEST,
    USER_ROLES.CUSTOMER,
  ),
  validateRequest(AuthValidations.resetPasswordZodSchema),
  CustomAuthController.resetPassword,
)

router.post(
  '/resend-otp',
  tempAuth(
    USER_ROLES.ADMIN,
    USER_ROLES.USER,
    USER_ROLES.GUEST,
    USER_ROLES.CUSTOMER,
  ),
  validateRequest(AuthValidations.resendOtpZodSchema),
  CustomAuthController.resendOtp,
)

router.post(
  '/change-password',
  auth(USER_ROLES.ADMIN, USER_ROLES.USER, USER_ROLES.GUEST),
  validateRequest(AuthValidations.changePasswordZodSchema),
  CustomAuthController.changePassword,
)
router.post('/refresh-token', CustomAuthController.getRefreshToken)

export const AuthRoutes = router
