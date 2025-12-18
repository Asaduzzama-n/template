import { StatusCodes } from 'http-status-codes'
import { User } from '../../user/user.model'
import { AuthHelper } from '../auth.helper'
import ApiError from '../../../../errors/ApiError'
import { USER_ROLES, USER_STATUS } from '../../../../enum/user'
import config from '../../../../config'
import { Token } from '../../token/token.model'
import { IAuthResponse, IResetPassword } from '../auth.interface'
import { emailTemplate } from '../../../../shared/emailTemplate'
import cryptoToken, { generateOtp, compareOtp } from '../../../../utils/crypto'
import bcrypt from 'bcrypt'
import { ILoginData } from '../../../../interfaces/auth'
import { AuthCommonServices, authResponse } from '../common'
import { jwtHelper } from '../../../../helpers/jwtHelper'
import { JwtPayload } from 'jsonwebtoken'
import { IUser } from '../../user/user.interface'
import { emailHelper } from '../../../../helpers/emailHelper'
import { redisHelper } from '../../../../helpers/redisHelper'
import { AuthRateLimitKeys } from '../../../../enum/redis.keys'

const OTP_EXPIRY_MINUTES = 5
const MAX_OTP_REQUESTS = 5
const RATE_LIMIT_WINDOW_SECONDS = 15 * 60 // 15 minutes
const COOLDOWN_SECONDS = 60 // 1 minute between requests

const createUser = async (payload: IUser) => {
  payload.email = payload.email?.toLowerCase().trim()
  const isUserExist = await User.findOne({
    email: payload.email,
    status: { $nin: [USER_STATUS.DELETED] },
  })

  if (isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      `An account with this email already exist, please login or try with another email.`,
    )
  }

  const otp = await generateOtp()
  const otpExpiresIn = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000)

  const authentication = {
    email: payload.email,
    oneTimeCode: otp.hashedOtp,
    expiresAt: otpExpiresIn,
    latestRequestAt: new Date(),
    requestCount: 1,
    authType: 'createAccount',
  }

  //send email or sms with otp
  const createAccount = emailTemplate.createAccount({
    name: payload.name!,
    email: payload.email!.toLowerCase().trim(),
    otp: otp.otp,
  })

  const user = await User.create({
    ...payload,
    password: payload.password,
    authentication,
  })

  if (!user) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Failed to create user.')
  }
  emailHelper.sendEmail(createAccount)

  return `${config.node_env === 'development' ? `${payload.email}, ${otp}` : 'An otp has been sent to your email, please check.'}`
}

const customLogin = async (payload: ILoginData): Promise<IAuthResponse> => {
  const { email, phone } = payload
  const query = email ? { email: email.toLowerCase().trim() } : { phone: phone }

  const isUserExist = await User.findOne({
    ...query,
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] },
  })
    .select('+password +authentication')
    .lean()
  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      `No account found with this ${email ? 'email' : 'phone'}`,
    )
  }

  const result = await AuthCommonServices.handleLoginLogic(payload, isUserExist)

  return result
}

const adminLogin = async (payload: ILoginData): Promise<IAuthResponse> => {
  const { email, phone, password } = payload

  if (!email && !phone) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Email or phone is required')
  }

  const query = email ? { email: email.trim().toLowerCase() } : { phone }

  const admin = await User.findOne({
    ...query,
    role: USER_ROLES.ADMIN,
    status: USER_STATUS.ACTIVE,
  }).select('+password')

  if (!admin) {
    throw new ApiError(StatusCodes.UNAUTHORIZED, 'Invalid credentials')
  }

  const isPasswordMatch = await AuthHelper.isPasswordMatched(
    password,
    admin.password!,
  )

  if (!isPasswordMatch) {
    // Optional: increment admin login attempts here
    throw new ApiError(StatusCodes.UNAUTHORIZED, 'Invalid credentials')
  }

  // Optional: update lastLoginAt, device info, IP
  await User.findByIdAndUpdate(admin._id, {
    $set: { lastLoginAt: new Date() },
  })

  const tokens = AuthHelper.createToken(
    admin._id,
    admin.role,
    admin.name!,
    admin.email!,
  )

  return authResponse(
    StatusCodes.OK,
    `Welcome back ${admin.name}`,
    admin.role,
    tokens.accessToken,
    tokens.refreshToken,
  )
}

const forgetPassword = async (email?: string, phone?: string) => {
  if (!email && !phone) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Email or phone is required')
  }

  const query = email ? { email: email.toLowerCase().trim() } : { phone }

  const user = await User.findOne({
    ...query,
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] },
  }).select('+authentication')

  if (!user) {
    return {
      message: 'If an account exists, a password reset code has been sent.',
    }
  }

  const identifier = email || phone!

  // Redis-based rate limiting: check cooldown first
  await redisHelper.checkCooldown(AuthRateLimitKeys.PASSWORD_RESET, identifier, COOLDOWN_SECONDS)

  // Redis-based rate limiting: increment and check max attempts
  await redisHelper.incrementRateLimit(
    AuthRateLimitKeys.PASSWORD_RESET,
    identifier,
    RATE_LIMIT_WINDOW_SECONDS,
    MAX_OTP_REQUESTS,
  )

  // Set cooldown for next request
  await redisHelper.setCooldown(AuthRateLimitKeys.PASSWORD_RESET, identifier, COOLDOWN_SECONDS)

  const otp = await generateOtp()

  await User.findByIdAndUpdate(user._id, {
    $set: {
      'authentication.oneTimeCode': otp.hashedOtp,
      'authentication.expiresAt': new Date(
        Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000,
      ),
      'authentication.authType': 'resetPassword',
      'authentication.resetPassword': true,
    },
  })

  if (email) {
    const template = emailTemplate.resetPassword({
      name: user.name!,
      email: user.email!,
      otp: otp.otp,
    })
    await emailHelper.sendEmail(template)
  }

  return {
    message: 'If an account exists, a password reset code has been sent.',
    ...(config.node_env === 'development' && { otp }),
  }
}

const resetPassword = async (resetToken: string, payload: IResetPassword) => {
  const { newPassword, confirmPassword } = payload

  if (!newPassword || !confirmPassword) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Password is required')
  }

  if (newPassword !== confirmPassword) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Passwords do not match')
  }

  // Optional: password strength check
  if (newPassword.length < 8) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Password must be at least 8 characters long',
    )
  }

  const tokenDoc = await Token.findOne({
    token: resetToken,
    expireAt: { $gt: new Date() },
  })

  if (!tokenDoc) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Invalid or expired reset token',
    )
  }

  const isTokenValid = await bcrypt.compare(resetToken, tokenDoc.token)

  if (!isTokenValid) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Invalid or expired reset token',
    )
  }

  const user = await User.findById(tokenDoc.user).select('+authentication')

  if (!user || !user.authentication?.resetPassword) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Invalid password reset request',
    )
  }

  const hashedPassword = await bcrypt.hash(
    newPassword,
    Number(config.bcrypt_salt_rounds),
  )

  await User.findByIdAndUpdate(user._id, {
    $set: {
      password: hashedPassword,
      'authentication.resetPassword': false,
      'authentication.oneTimeCode': null,
      'authentication.expiresAt': null,
      'authentication.latestRequestAt': null,
      'authentication.requestCount': 0,
      'authentication.authType': null,
      'authentication.wrongLoginAttempts': 0,
      'authentication.restrictionLeftAt': null,
      status: USER_STATUS.ACTIVE,
    },
  })

  await Token.findByIdAndDelete(tokenDoc._id)

  return {
    message: 'Password reset successful. Please login with your new password.',
  }
}

const verifyAccount = async (
  email: string,
  onetimeCode: string,
): Promise<IAuthResponse> => {
  //verify fo new user
  if (!onetimeCode) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'OTP is required.')
  }
  const isUserExist = await User.findOne({
    email: email.toLowerCase().trim(),
    status: { $nin: [USER_STATUS.DELETED] },
  })
    .select('+password +authentication')
    .lean()

  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      `No account found with this ${email}, please register first.`,
    )
  }

  const { authentication } = isUserExist

  //check the otp
  const isOtpValid = await compareOtp(onetimeCode, authentication?.oneTimeCode!)
  if (!isOtpValid) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'You provided a wrong OTP, please try again.',
    )
  }

  const currentDate = new Date()
  if (authentication?.expiresAt! < currentDate) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'OTP has already expired, please request a new one.',
    )
  }

  //either newly created user or existing user
  if (!isUserExist.verified) {
    await User.findByIdAndUpdate(
      isUserExist._id,
      {
        $set: {
          verified: true,
          authentication: {
            oneTimeCode: '',
            expiresAt: null,
            latestRequestAt: null,
            requestCount: 0,
            authType: '',
            resetPassword: true,
          },
        },
      },
      { new: true },
    )

    const tokens = AuthHelper.createToken(
      isUserExist._id,
      isUserExist.role,
      isUserExist.name,
      isUserExist.email,
    )
    return authResponse(
      StatusCodes.OK,
      `Welcome ${isUserExist.name} to our platform.`,
      isUserExist.role,
      tokens.accessToken,
      tokens.refreshToken,
    )
  } else {
    await User.findByIdAndUpdate(
      isUserExist._id,
      {
        $set: {
          authentication: {
            oneTimeCode: '',
            expiresAt: null,
            latestRequestAt: null,
            requestCount: 0,
            authType: '',
            resetPassword: true,
          },
        },
      },
      { new: true },
    )

    const token = await Token.create({
      token: cryptoToken(),
      user: isUserExist._id,
      expireAt: new Date(Date.now() + 5 * 60 * 1000), // 15 minutes
    })

    if (!token) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        'Something went wrong, please try again. or contact support.',
      )
    }

    return authResponse(
      StatusCodes.OK,
      'OTP verified successfully, please reset your password.',
      undefined,
      undefined,
      undefined,
      token.token,
    )
  }
}

const getRefreshToken = async (token: string) => {
  try {
    const decodedToken = jwtHelper.verifyToken(
      token,
      config.jwt.jwt_refresh_secret as string,
    )

    const { userId, role } = decodedToken

    const tokens = AuthHelper.createToken(
      userId,
      role,
      decodedToken.name,
      decodedToken.email,
    )

    return {
      accessToken: tokens.accessToken,
    }
  } catch (error) {
    if (error instanceof Error && error.name === 'TokenExpiredError') {
      throw new ApiError(StatusCodes.UNAUTHORIZED, 'Refresh Token has expired')
    }
    throw new ApiError(StatusCodes.FORBIDDEN, 'Invalid Refresh Token')
  }
}

const socialLogin = async (
  appId: string,
  deviceToken: string,
): Promise<IAuthResponse> => {
  const isUserExist = await User.findOne({
    appId,
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] },
  })
  if (!isUserExist) {
    const createdUser = await User.create({
      appId,
      deviceToken,
      status: USER_STATUS.ACTIVE,
    })
    if (!createdUser)
      throw new ApiError(StatusCodes.BAD_REQUEST, 'Failed to create user.')
    const tokens = AuthHelper.createToken(
      createdUser._id,
      createdUser.role,
      createdUser.name,
      createdUser.email,
    )
    return authResponse(
      StatusCodes.OK,
      `Welcome ${createdUser.name} to our platform.`,
      createdUser.role,
      tokens.accessToken,
      tokens.refreshToken,
    )
  } else {
    await User.findByIdAndUpdate(isUserExist._id, {
      $set: {
        deviceToken,
      },
    })

    const tokens = AuthHelper.createToken(
      isUserExist._id,
      isUserExist.role,
      isUserExist.name,
      isUserExist.email,
    )
    //send token to client
    return authResponse(
      StatusCodes.OK,
      `Welcome back ${isUserExist.name}`,
      isUserExist.role,
      tokens.accessToken,
      tokens.refreshToken,
    )
  }
}

const deleteAccount = async (user: JwtPayload, password: string) => {
  const { authId } = user
  const isUserExist = await User.findById(authId).select('+password')
  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Failed to delete account. Please try again.',
    )
  }

  if (isUserExist.status === USER_STATUS.DELETED) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Requested user is already deleted.',
    )
  }

  const isPasswordMatched = await bcrypt.compare(password, isUserExist.password)

  if (!isPasswordMatched) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Please provide a valid password to delete your account.',
    )
  }

  const deletedData = await User.findByIdAndUpdate(authId, {
    $set: { status: USER_STATUS.DELETED },
  })

  return {
    status: StatusCodes.OK,
    message: 'Account deleted successfully.',
    deletedData,
  }
}

const resendOtp = async (
  email: string,
  authType: 'createAccount' | 'resetPassword',
) => {
  const normalizedEmail = email.toLowerCase().trim()
  const isUserExist = await User.findOne({
    email: normalizedEmail,
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] },
  }).select('+authentication')

  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      `No account found with this ${email}, please try again.`,
    )
  }

  // Redis-based rate limiting
  await redisHelper.checkCooldown(AuthRateLimitKeys.OTP_RESEND, normalizedEmail, COOLDOWN_SECONDS)
  await redisHelper.incrementRateLimit(
    AuthRateLimitKeys.OTP_RESEND,
    normalizedEmail,
    RATE_LIMIT_WINDOW_SECONDS,
    MAX_OTP_REQUESTS,
  )
  await redisHelper.setCooldown(AuthRateLimitKeys.OTP_RESEND, normalizedEmail, COOLDOWN_SECONDS)

  const otp = await generateOtp()

  await User.findByIdAndUpdate(
    isUserExist._id,
    {
      $set: {
        'authentication.oneTimeCode': otp.hashedOtp,
        'authentication.expiresAt': new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000),
      },
    },
    { new: true },
  )

  // Send OTP email
  const forgetPasswordEmailTemplate = emailTemplate.resendOtp({
    email: normalizedEmail,
    name: isUserExist.name as string,
    otp: otp.otp,
    type: authType,
  })
  emailHelper.sendEmail(forgetPasswordEmailTemplate)

  return 'OTP sent successfully.'
}

const changePassword = async (
  user: JwtPayload,
  currentPassword: string,
  newPassword: string,
) => {
  // Find the user with password field
  const isUserExist = await User.findById(user.authId)
    .select('+password')
    .lean()

  if (!isUserExist) {
    throw new ApiError(StatusCodes.NOT_FOUND, 'User not found')
  }

  // Check if current password matches
  const isPasswordMatch = await AuthHelper.isPasswordMatched(
    currentPassword,
    isUserExist.password as string,
  )

  if (!isPasswordMatch) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Current password is incorrect')
  }

  // Hash the new password
  const hashedPassword = await bcrypt.hash(
    newPassword,
    Number(config.bcrypt_salt_rounds),
  )

  // Update the password
  await User.findByIdAndUpdate(
    user.authId,
    { password: hashedPassword },
    { new: true },
  )

  return { message: 'Password changed successfully' }
}

export const CustomAuthServices = {
  adminLogin,
  forgetPassword,
  resetPassword,
  verifyAccount,
  customLogin,
  getRefreshToken,
  socialLogin,
  deleteAccount,
  resendOtp,
  changePassword,
  createUser,
}
