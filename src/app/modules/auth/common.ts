import { StatusCodes } from 'http-status-codes'
import { ILoginData, ISocialLoginData } from '../../../interfaces/auth'
import ApiError from '../../../errors/ApiError'

import { User } from '../user/user.model'
import { AuthHelper } from './auth.helper'
import { generateOtp } from '../../../utils/crypto'
import { IAuthResponse } from './auth.interface'
import { IUser } from '../user/user.interface'
import { emailTemplate } from '../../../shared/emailTemplate'
import { emailHelper } from '../../../helpers/emailHelper'
import { Verification } from '../verification/verification.model'
import { VERIFICATION_TYPE } from '../verification/verification.interface'
import config from '../../../config'

/**
 * Handle Custom Login Logic (Email/Password)
 */
const handleCustomLoginLogic = async (
  payload: ILoginData,
  user: IUser,
): Promise<IAuthResponse> => {
  const {
    _id,
    email,
    name,
    role,
    verified,
    authentication,
    password: hashedPassword,
  } = user

  const {
    isRestricted,
    restrictionLeftAt,
    wrongLoginAttempts = 0,
  } = authentication || {}

  // 1. Initial Lockout Check
  if (isRestricted && restrictionLeftAt && new Date() < restrictionLeftAt) {
    const remaining = Math.ceil(
      (restrictionLeftAt.getTime() - Date.now()) / 60000,
    )
    throw new ApiError(
      StatusCodes.TOO_MANY_REQUESTS,
      `Account temporarily locked. Try again in ${remaining} minutes.`,
    )
  }

  // 2. Password Matching
  const isMatch = await User.isPasswordMatched(payload.password, hashedPassword)

  if (!isMatch) {
    const attempts = wrongLoginAttempts + 1
    const shouldLock = attempts >= Number(config.security.max_wrong_attempts)

    const updateQuery: any = {
      $inc: { 'authentication.wrongLoginAttempts': 1 },
      $set: { 'authentication.isRestricted': shouldLock },
    }

    if (shouldLock) {
      const lockUntil = new Date(
        Date.now() + Number(config.security.restriction_minutes) * 60 * 1000,
      )

      if (config.security.lock_out_strategy === 'EXTEND') {
        updateQuery.$min = { 'authentication.restrictionLeftAt': lockUntil }
      } else {
        updateQuery.$set['authentication.restrictionLeftAt'] = lockUntil
      }
    }

    await User.findByIdAndUpdate(_id, updateQuery)

    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Invalid credentials, please try again with valid one.',
    )
  }

  // 3. Verification Check
  if (!verified) {
    const existingOTP = await Verification.findOne({
      identifier: email,
      type: VERIFICATION_TYPE.ACCOUNT_ACTIVATION,
    })

    if (existingOTP) {
      if (existingOTP.latestRequest) {
        const secondsSinceLast = (Date.now() - existingOTP.latestRequest.getTime()) / 1000
        if (secondsSinceLast < Number(config.otp.request_cooldown_seconds)) {
          const waitTime = Math.ceil(Number(config.otp.request_cooldown_seconds) - secondsSinceLast)
          throw new ApiError(StatusCodes.TOO_MANY_REQUESTS, `Please wait ${waitTime} seconds.`)
        }
      }

      if (existingOTP.requestCount >= Number(config.otp.max_request_allowed || 5)) {
        throw new ApiError(
          StatusCodes.TOO_MANY_REQUESTS,
          'Maximum OTP limit reached. Please try again in 15 minutes.',
        )
      }
    }

    const { otp, expiresIn, hashedOtp } = await generateOtp()

    await Verification.findOneAndUpdate(
      { identifier: email, type: VERIFICATION_TYPE.ACCOUNT_ACTIVATION },
      {
        $set: {
          otpHash: hashedOtp,
          otpExpiresAt: expiresIn,
          latestRequest: new Date(),
          attempts: 0,
          expiresAt: new Date(Date.now() + 15 * 60 * 1000),
        },
        $inc: { requestCount: 1 },
      },
      { upsert: true, new: true },
    )

    emailHelper.sendEmail(emailTemplate.createAccount({ email, otp, name }))

    return authResponse(StatusCodes.FORBIDDEN, 'Account unverified. OTP sent.')
  }

  // 4. Success - Reset Security Counters
  await User.findByIdAndUpdate(_id, {
    $set: {
      'authentication.wrongLoginAttempts': 0,
      'authentication.isRestricted': false,
      'authentication.restrictionLeftAt': null,
      ...(payload.fcmToken && { fcmToken: payload.fcmToken }),
    },
  })

  const tokens = AuthHelper.createToken(_id, role, name, email)

  return authResponse(StatusCodes.OK, `Welcome back ${name}`, {
    role,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
  })
}

/**
 * Handle Social Login Logic (appId based)
 */
const handleSocialLoginLogic = async (
  payload: ISocialLoginData,
  user: IUser,
): Promise<IAuthResponse> => {
  const { _id, name, role, email } = user

  // Social login skips password checks and verification checks as we assume the provider verified them
  // We simply update the status if needed and return tokens

  await User.findByIdAndUpdate(_id, {
    $set: {
      verified: true, // Social accounts are trusted
      'authentication.wrongLoginAttempts': 0,
      'authentication.isRestricted': false,
      'authentication.restrictionLeftAt': null,
      ...(payload.fcmToken && { fcmToken: payload.fcmToken }),
    },
  })

  const tokens = AuthHelper.createToken(_id, role, name, email)

  return authResponse(StatusCodes.OK, `Welcome ${name}`, {
    role,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
  })
}

export const AuthCommonServices = {
  handleCustomLoginLogic,
  handleSocialLoginLogic,
}

export const authResponse = (
  status: number,
  message: string,
  options: {
    role?: string
    accessToken?: string
    refreshToken?: string
    token?: string
  } = {},
): IAuthResponse => {
  return {
    status,
    message,
    ...options,
  }
}

export const getSanitizeEmail = (email: string): string => {
  return email.toLowerCase().trim()
}
