import { StatusCodes } from 'http-status-codes'
import { ILoginData } from '../../../interfaces/auth'
import ApiError from '../../../errors/ApiError'
import { USER_STATUS } from '../../../enum/user'
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

const handleLoginLogic = async (
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
    const shouldLock = attempts >= Number(config.max_wrong_attempts)

    const updateQuery: any = {
      $inc: { 'authentication.wrongLoginAttempts': 1 },
      $set: { 'authentication.isRestricted': shouldLock },
    }

    if (shouldLock) {
      const lockUntil = new Date(
        Date.now() + Number(config.restriction_minutes) * 60 * 1000,
      )

      // Strategy Toggle: STRICT_EARLIEST (min) vs EXTEND (set)
      if (config.lock_out_strategy === 'EXTEND') {
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

  // 3. Verification Check (Using UPSERT for Verification model)
  if (!verified) {
    const existingOTP = await Verification.findOne({
      identifier: email,
      type: VERIFICATION_TYPE.ACCOUNT_ACTIVATION,
    })

   if (existingOTP) {
    // A. Check Cooldown (Time-based)
    if (existingOTP.latestRequest) {
      const secondsSinceLast = (Date.now() - existingOTP.latestRequest.getTime()) / 1000;
      if (secondsSinceLast < Number(config.otp_request_cooldown_seconds)) {
        const waitTime = Math.ceil(Number(config.otp_request_cooldown_seconds) - secondsSinceLast);
        throw new ApiError(StatusCodes.TOO_MANY_REQUESTS, `Please wait ${waitTime} seconds.`);
      }
    }

    // B. Check Request Limit (Volume-based) - NEW
    if (existingOTP.requestCount >= Number(config.max_otp_request_allowed || 5)) {
      throw new ApiError(
        StatusCodes.TOO_MANY_REQUESTS,
        'Maximum OTP limit reached. Please try again in 15 minutes.',
      );
    }
  }

    const { otp, expiresIn, hashedOtp } = await generateOtp()

    // Upsert ensures we don't crash on duplicate identity keys
    await Verification.findOneAndUpdate(
      { identifier: email, type: VERIFICATION_TYPE.ACCOUNT_ACTIVATION },
      {
        $set: {
          otpHash: hashedOtp,
          otpExpiresAt: expiresIn,
          latestRequest: new Date(),
          attempts: 0, // IMPORTANT: Reset failed OTP attempts when a new one is sent
          // Reset the TTL timer to 15 mins from NOW
          expiresAt: new Date(Date.now() + 15 * 60 * 1000),
        },
      },
      { upsert: true, new: true },
    )

    // Offload to helper (consider using a queue here for true production scale)
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

  // Best Practice: Return options as an object to keep code readable
  return authResponse(StatusCodes.OK, `Welcome back ${name}`, {
    role,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
  })
}

export const AuthCommonServices = {
  handleLoginLogic,
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



export const getSanitizeEmail = (email:string):string =>{
  return email.toLowerCase().trim()
}