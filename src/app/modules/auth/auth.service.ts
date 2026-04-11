import { StatusCodes } from 'http-status-codes'
import mongoose, { Types } from 'mongoose'
import { JwtPayload } from 'jsonwebtoken'
import { User } from '../user/user.model'
import { Verification } from '../verification/verification.model'
import { Token } from '../token/token.model'
import { VerificationService } from '../verification/verification.service'
import { AuthCache } from './auth.cache'
import { AuthHelper } from './auth.helper'
import { AUTH_MESSAGES } from './auth.constants'
import { IAuthResponse, IVerifyAccountPayload, ISocialLoginPayload } from './auth.interface'
import { ILoginData, IChangePassword, IAuthResetPassword } from '../../../interfaces/auth'
import { IUser } from '../user/user.interface'
import { USER_ROLES, USER_STATUS } from '../../../enum/user'
import { VERIFICATION_TYPE } from '../verification/verification.interface'
import { emailTemplate } from '../../../shared/emailTemplate'
import { emailHelper } from '../../../helpers/emailHelper'
import ApiError from '../../../errors/ApiError'
import cryptoToken from '../../../utils/crypto'
import { errorLogger } from '../../../shared/logger'
import { jwtHelper } from '../../../helpers/jwtHelper'
import config from '../../../config'

// ═══ REGISTRATION ══════════════════════════════════════════════════════════

/**
 * Creates a new user and sends an activation OTP.
 */
const signup = async (payload: IUser) => {
  const session = await mongoose.startSession()
  try {
    session.startTransaction()
    payload.email = AuthHelper.sanitizeEmail(payload.email)

    const user = await User.create([payload], { session })
    if (!user.length) throw new ApiError(StatusCodes.BAD_REQUEST, 'Failed to create user account.')

    const { otp } = await VerificationService.createInitialVerification(
      payload.email,
      VERIFICATION_TYPE.ACCOUNT_ACTIVATION,
      session,
    )

    const signupEmail = emailTemplate.createAccount({
      name: payload.name!,
      email: payload.email!,
      otp,
    })

    await session.commitTransaction()
    emailHelper.sendEmail(signupEmail)

    return AUTH_MESSAGES.SIGNUP_SUCCESS
  } catch (error: any) {
    await session.abortTransaction()
    if (error.code === 11000) {
      throw new ApiError(StatusCodes.BAD_REQUEST, 'An account with this email already exists.')
    }
    throw error
  } finally {
    await session.endSession()
  }
}

/**
 * Handles login for both social providers and manual social token exchange.
 */
const socialLogin = async (payload: ISocialLoginPayload): Promise<IAuthResponse> => {
  const { appId, fcmToken } = payload
  let user = await User.findOne({ 
    appId, 
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] } 
  })

  if (!user) {
    user = (await User.create({
      appId,
      fcmToken,
      status: USER_STATUS.ACTIVE,
      verified: true // Social users are pre-verified
    })) as any
  } else {
    await User.findByIdAndUpdate(user._id, { $set: { fcmToken } })
  }

  const tokens = AuthHelper.createTokenPair(user!._id, user!.role, user!.name, user!.email)

  return AuthHelper.buildAuthResponse(StatusCodes.OK, AUTH_MESSAGES.VERIFY_SUCCESS(user!.name!), {
    role: user!.role,
    ...tokens
  })
}

/**
 * Passport callback handler for Google OAuth.
 */
const handleGoogleLogin = async (payload: IUser & { profile: any }): Promise<IAuthResponse> => {
  const { emails, photos, displayName, id } = payload.profile
  const email = AuthHelper.sanitizeEmail(emails[0].value)

  let user = await User.findOne({
    email,
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] },
  })

  if (!user) {
    const session = await mongoose.startSession()
    try {
      session.startTransaction()
      const [newUser] = await User.create([{
        email,
        profile: photos[0]?.value,
        name: displayName,
        verified: true,
        password: cryptoToken(), // Random unusable password
        status: USER_STATUS.ACTIVE,
        appId: id,
        role: payload.role,
      }], { session })

      const tokens = AuthHelper.createTokenPair(newUser._id, newUser.role, newUser.name, newUser.email)
      await session.commitTransaction()
      return AuthHelper.buildAuthResponse(StatusCodes.OK, AUTH_MESSAGES.VERIFY_SUCCESS(newUser.name!), {
        role: newUser.role,
        ...tokens
      })
    } catch (error) {
      await session.abortTransaction()
      throw error
    } finally {
      await session.endSession()
    }
  }

  const tokens = AuthHelper.createTokenPair(user._id, user.role, user.name, user.email)
  return AuthHelper.buildAuthResponse(StatusCodes.OK, AUTH_MESSAGES.LOGIN_SUCCESS(user.name!), {
    role: user.role,
    ...tokens
  })
}

// ═══ LOGIN ═════════════════════════════════════════════════════════════════

const login = async (payload: ILoginData, requireRole?: string): Promise<IAuthResponse> => {
  const email = AuthHelper.sanitizeEmail(payload.email)
  const user = await User.findOne({
    email,
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] },
  }).select('+password +authentication').lean()

  if (!user) throw new ApiError(StatusCodes.BAD_REQUEST, AUTH_MESSAGES.INVALID_CREDENTIALS)
  if (user.status === USER_STATUS.RESTRICTED) throw new ApiError(StatusCodes.FORBIDDEN, AUTH_MESSAGES.ACCOUNT_RESTRICTED)
  if (requireRole && user.role !== requireRole) throw new ApiError(StatusCodes.FORBIDDEN, AUTH_MESSAGES.ADMIN_ONLY_LOGIN)

  const { isRestricted, restrictionLeftAt, wrongLoginAttempts = 0 } = user.authentication || {}
  AuthHelper.assertNotLocked(isRestricted, restrictionLeftAt)

  const isMatch = await AuthHelper.isPasswordMatched(payload.password, user.password)
  if (!isMatch) {
    await AuthHelper.handleFailedPasswordAttempt(user._id, wrongLoginAttempts)
    throw new ApiError(StatusCodes.BAD_REQUEST, AUTH_MESSAGES.INVALID_CREDENTIALS)
  }

  if (!user.verified) {
    await VerificationService.validateOtpRequest(email, VERIFICATION_TYPE.ACCOUNT_ACTIVATION)
    const { otp } = await VerificationService.upsertVerification(email, VERIFICATION_TYPE.ACCOUNT_ACTIVATION)
    emailHelper.sendEmail(emailTemplate.createAccount({ email, name: user.name || '', otp }))
    throw new ApiError(StatusCodes.FORBIDDEN, AUTH_MESSAGES.UNVERIFIED_ACCOUNT)
  }

  await AuthHelper.resetSecurityCounters(user._id, payload.fcmToken)
  const tokens = AuthHelper.createTokenPair(user._id, user.role, user.name, user.email)

  return AuthHelper.buildAuthResponse(StatusCodes.OK, AUTH_MESSAGES.LOGIN_SUCCESS(user.name!), {
    role: user.role,
    ...tokens
  })
}

const refreshToken = async (token: string) => {
  try {
    const decoded = jwtHelper.verifyToken(token, config.jwt.jwt_refresh_secret as string)
    const { authId, iat } = decoded

    const user = await User.findById(authId).select('+authentication').lean()
    if (!user) throw new ApiError(StatusCodes.NOT_FOUND, AUTH_MESSAGES.ACCOUNT_NOT_FOUND)
    
    if (user.status === USER_STATUS.DELETED) throw new ApiError(StatusCodes.FORBIDDEN, AUTH_MESSAGES.ACCOUNT_DELETED)
    if (user.status === USER_STATUS.RESTRICTED) throw new ApiError(StatusCodes.FORBIDDEN, AUTH_MESSAGES.ACCOUNT_RESTRICTED)

    if (user.authentication?.passwordChangedAt && AuthHelper.isTokenInvalidated(user.authentication.passwordChangedAt, iat!)) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, AUTH_MESSAGES.SESSION_EXPIRED_PASSWORD)
    }

    const { accessToken } = AuthHelper.createTokenPair(user._id, user.role, user.name, user.email)
    return { accessToken }
  } catch (error) {
    if (error instanceof ApiError) throw error
    if (error instanceof Error && error.name === 'TokenExpiredError') {
      throw new ApiError(StatusCodes.UNAUTHORIZED, AUTH_MESSAGES.REFRESH_TOKEN_EXPIRED)
    }
    throw new ApiError(StatusCodes.FORBIDDEN, AUTH_MESSAGES.INVALID_REFRESH_TOKEN)
  }
}

// ═══ VERIFICATION ══════════════════════════════════════════════════════════

const verifyAccount = async (payload: IVerifyAccountPayload): Promise<IAuthResponse> => {
  const email = AuthHelper.sanitizeEmail(payload.email)
  const user = await User.findOne({ email, status: { $ne: USER_STATUS.DELETED } }).select('+authentication')
  if (!user) throw new ApiError(StatusCodes.NOT_FOUND, AUTH_MESSAGES.ACCOUNT_NOT_FOUND)
  if (user.status === USER_STATUS.RESTRICTED) throw new ApiError(StatusCodes.FORBIDDEN, AUTH_MESSAGES.ACCOUNT_RESTRICTED)

  const session = await mongoose.startSession()
  try {
    session.startTransaction()
    await VerificationService.verifyOtp(email, payload.type as VERIFICATION_TYPE, payload.oneTimeCode, session)

    if (payload.type === VERIFICATION_TYPE.ACCOUNT_ACTIVATION) {
      user.verified = true
      await user.save({ session })
      await VerificationService.deleteVerification(email, VERIFICATION_TYPE.ACCOUNT_ACTIVATION, session)
      const tokens = AuthHelper.createTokenPair(user._id, user.role, user.name, user.email)
      await session.commitTransaction()
      return AuthHelper.buildAuthResponse(StatusCodes.OK, AUTH_MESSAGES.VERIFY_SUCCESS(user.name!), {
        role: user.role,
        ...tokens
      })
    }

    if (payload.type === VERIFICATION_TYPE.RESET_PASSWORD) {
      const resetToken = cryptoToken()
      await Token.create([{ token: resetToken, user: user._id, expiresAt: new Date(Date.now() + 15 * 60 * 1000) }], { session })
      await VerificationService.deleteVerification(email, VERIFICATION_TYPE.RESET_PASSWORD, session)
      await session.commitTransaction()
      return AuthHelper.buildAuthResponse(StatusCodes.OK, AUTH_MESSAGES.OTP_VERIFIED_RESET, { token: resetToken })
    }

    throw new ApiError(StatusCodes.INTERNAL_SERVER_ERROR, 'Unrecognized verification type.')
  } catch (error) {
    await session.abortTransaction()
    throw error
  } finally {
    await session.endSession()
  }
}

const resendOtp = async (email: string, type: string) => {
  const sanitizedEmail = AuthHelper.sanitizeEmail(email)
  const user = await User.findOne({ email: sanitizedEmail, status: { $ne: USER_STATUS.DELETED } }).lean()
  if (!user) throw new ApiError(StatusCodes.NOT_FOUND, AUTH_MESSAGES.ACCOUNT_NOT_FOUND)
  if (user.status === USER_STATUS.RESTRICTED) throw new ApiError(StatusCodes.FORBIDDEN, AUTH_MESSAGES.ACCOUNT_RESTRICTED)

  await VerificationService.validateOtpRequest(sanitizedEmail, type as VERIFICATION_TYPE)
  const { otp } = await VerificationService.upsertVerification(sanitizedEmail, type as VERIFICATION_TYPE)

  const emailData = emailTemplate.resendOtp({ email: sanitizedEmail, name: user.name || '', otp, type: type as VERIFICATION_TYPE })
  emailHelper.sendEmail(emailData).catch(err => errorLogger.error('OTP resend failed:', err))

  return AUTH_MESSAGES.OTP_SENT
}

// ═══ PASSWORD MANAGEMENT ═══════════════════════════════════════════════════

const forgetPassword = async (email: string) => {
  const sanitizedEmail = AuthHelper.sanitizeEmail(email)
  const user = await User.findOne({ email: sanitizedEmail, status: { $ne: USER_STATUS.DELETED } }).select('+authentication').lean()
  if (!user) throw new ApiError(StatusCodes.NOT_FOUND, AUTH_MESSAGES.ACCOUNT_NOT_FOUND)
  if (user.status === USER_STATUS.RESTRICTED) throw new ApiError(StatusCodes.FORBIDDEN, AUTH_MESSAGES.ACCOUNT_RESTRICTED)

  AuthHelper.assertNotLocked(user.authentication?.isRestricted, user.authentication?.restrictionLeftAt)
  await VerificationService.validateOtpRequest(sanitizedEmail, VERIFICATION_TYPE.RESET_PASSWORD)
  const { otp } = await VerificationService.upsertVerification(sanitizedEmail, VERIFICATION_TYPE.RESET_PASSWORD)

  const resetEmail = emailTemplate.resetPassword({ name: user.name || '', email: sanitizedEmail, otp })
  emailHelper.sendEmail(resetEmail).catch(err => errorLogger.error('Reset email failed:', err))

  return AUTH_MESSAGES.OTP_SENT
}

const resetPassword = async (resetToken: string, payload: IAuthResetPassword) => {
  const session = await mongoose.startSession()
  try {
    session.startTransaction()
    const isTokenExist = await Token.findOne({ token: resetToken }).session(session)
    if (!isTokenExist || new Date() > isTokenExist.expiresAt) {
      if (isTokenExist) await Token.deleteOne({ _id: isTokenExist._id }).session(session)
      await session.commitTransaction()
      throw new ApiError(StatusCodes.BAD_REQUEST, AUTH_MESSAGES.SESSION_INVALID)
    }

    const user = await User.findById(isTokenExist.user).select('+password +authentication').session(session)
    if (!user || user.status === USER_STATUS.RESTRICTED) throw new ApiError(StatusCodes.FORBIDDEN, AUTH_MESSAGES.ACCOUNT_RESTRICTED)

    user.password = payload.newPassword
    user.authentication.passwordChangedAt = new Date()
    user.authentication.wrongLoginAttempts = 0
    user.authentication.isRestricted = false
    user.authentication.restrictionLeftAt = null
    await user.save({ session })

    await AuthCache.invalidateAuthCache(user._id.toString())
    await Token.deleteOne({ _id: isTokenExist._id }).session(session)
    await session.commitTransaction()
    return { message: AUTH_MESSAGES.PASSWORD_RESET_SUCCESS }
  } catch (error) {
    await session.abortTransaction()
    throw error
  } finally {
    await session.endSession()
  }
}

const changePassword = async (userData: JwtPayload, payload: IChangePassword) => {
  const user = await User.findById(userData.authId).select('+password +authentication')
  if (!user) throw new ApiError(StatusCodes.NOT_FOUND, AUTH_MESSAGES.ACCOUNT_NOT_FOUND)
  if (user.status === USER_STATUS.RESTRICTED) throw new ApiError(StatusCodes.FORBIDDEN, AUTH_MESSAGES.ACCOUNT_RESTRICTED)

  const { isRestricted, restrictionLeftAt, wrongLoginAttempts = 0 } = user.authentication || {}
  AuthHelper.assertNotLocked(isRestricted, restrictionLeftAt)

  const isMatch = await AuthHelper.isPasswordMatched(payload.currentPassword, user.password)
  if (!isMatch) {
    await AuthHelper.handleFailedPasswordAttempt(user._id, wrongLoginAttempts)
    throw new ApiError(StatusCodes.BAD_REQUEST, AUTH_MESSAGES.OLD_PASSWORD_INCORRECT)
  }

  if (payload.currentPassword === payload.newPassword) {
    throw new ApiError(StatusCodes.BAD_REQUEST, AUTH_MESSAGES.PASSWORD_SAME_AS_OLD)
  }

  user.password = payload.newPassword
  user.authentication.passwordChangedAt = new Date()
  user.authentication.wrongLoginAttempts = 0
  user.authentication.isRestricted = false
  user.authentication.restrictionLeftAt = null
  await user.save()
  await AuthCache.invalidateAuthCache(user._id.toString())

  return { message: AUTH_MESSAGES.PASSWORD_CHANGED_SUCCESS }
}

// ═══ ACCOUNT MANAGEMENT ════════════════════════════════════════════════════

const deleteAccount = async (userData: JwtPayload, password: string) => {
  const user = await User.findById(userData.authId).select('+password +authentication')
  if (!user || user.status === USER_STATUS.DELETED) throw new ApiError(StatusCodes.NOT_FOUND, AUTH_MESSAGES.ACCOUNT_NOT_FOUND)

  const { isRestricted, restrictionLeftAt, wrongLoginAttempts = 0 } = user.authentication || {}
  AuthHelper.assertNotLocked(isRestricted, restrictionLeftAt)

  const isMatch = await AuthHelper.isPasswordMatched(password, user.password)
  if (!isMatch) {
    await AuthHelper.handleFailedPasswordAttempt(user._id, wrongLoginAttempts)
    throw new ApiError(StatusCodes.UNAUTHORIZED, AUTH_MESSAGES.OLD_PASSWORD_INCORRECT)
  }

  await User.findByIdAndUpdate(user._id, {
    $set: {
      status: USER_STATUS.DELETED,
      email: `${user.email}_deleted_${Date.now()}`,
      verified: false,
      'authentication.wrongLoginAttempts': 0,
      'authentication.isRestricted': false,
      'authentication.restrictionLeftAt': null,
    },
    $unset: { fcmToken: 1 }
  })

  await AuthCache.invalidateAuthCache(userData.authId)

  return AUTH_MESSAGES.ACCOUNT_DELETED_SUCCESS
}

export const AuthServices = {
  signup,
  login,
  socialLogin,
  handleGoogleLogin,
  refreshToken,
  verifyAccount,
  resendOtp,
  forgetPassword,
  resetPassword,
  changePassword,
  deleteAccount
}
