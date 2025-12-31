import { StatusCodes } from 'http-status-codes'
import { ILoginData } from '../../../interfaces/auth'
import ApiError from '../../../errors/ApiError'
import { User } from '../user/user.model'
import { AuthHelper } from './auth.helper'
import { IAuthResponse } from './auth.interface'
import { IUser } from '../user/user.interface'
import { emailTemplate } from '../../../shared/emailTemplate'
import { emailHelper } from '../../../helpers/emailHelper'
import { VERIFICATION_TYPE } from '../verification/verification.interface'
import config from '../../../config'
import { VerificationService } from '../verification/verification.service'



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


  checkAccountLockout(isRestricted, restrictionLeftAt)


  const isMatch = await User.isPasswordMatched(payload.password, hashedPassword)

  if (!isMatch) {
    await handleFailedLogin(_id, wrongLoginAttempts)
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Invalid credentials, please try again with valid one.',
    )
  }

  if (!verified) {
    return await handleUnverifiedAccount(email!, name!)
  }
  await resetSecurityCounters(_id, payload.fcmToken)

  const tokens = AuthHelper.createToken(_id, role, name, email)

  return authResponse(StatusCodes.OK, `Welcome back ${name}`, {
    role,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
  })
}


const checkAccountLockout = (
  isRestricted?: boolean,
  restrictionLeftAt?: Date | null,
): void => {
  if (isRestricted && restrictionLeftAt && new Date() < restrictionLeftAt) {
    const remaining = Math.ceil(
      (restrictionLeftAt.getTime() - Date.now()) / 60000,
    )
    throw new ApiError(
      StatusCodes.TOO_MANY_REQUESTS,
      `Account temporarily locked. Try again in ${remaining} minutes.`,
    )
  }
}


const handleFailedLogin = async (
  userId: any,
  currentAttempts: number,
): Promise<void> => {
  const attempts = currentAttempts + 1
  const shouldLock = attempts >= Number(config.max_wrong_attempts)

  const updateQuery: any = {
    $inc: { 'authentication.wrongLoginAttempts': 1 },
    $set: { 'authentication.isRestricted': shouldLock },
  }

  if (shouldLock) {
    const lockUntil = new Date(
      Date.now() + Number(config.restriction_minutes) * 60 * 1000,
    )

    // STRICT_EARLIEST: Keep earliest lockout time | EXTEND: Update to new lockout time
    if (config.lock_out_strategy === 'STRICT_EARLIEST') {
      updateQuery.$min = { 'authentication.restrictionLeftAt': lockUntil }
    } else {
      updateQuery.$set['authentication.restrictionLeftAt'] = lockUntil
    }
  }

  await User.findByIdAndUpdate(userId, updateQuery)
}

const handleUnverifiedAccount = async (
  email: string,
  name: string,
): Promise<IAuthResponse> => {

  await VerificationService.validateOtpRequest(
    email,
    VERIFICATION_TYPE.ACCOUNT_ACTIVATION,
  )


  const { otp } = await VerificationService.upsertVerification(
    email,
    VERIFICATION_TYPE.ACCOUNT_ACTIVATION,
  )


  emailHelper.sendEmail(emailTemplate.createAccount({ email, otp, name }))

  return authResponse(StatusCodes.FORBIDDEN, 'Account unverified. OTP sent.')
}

const resetSecurityCounters = async (
  userId: any,
  fcmToken?: string,
): Promise<void> => {
  await User.findByIdAndUpdate(userId, {
    $set: {
      'authentication.wrongLoginAttempts': 0,
      'authentication.isRestricted': false,
      'authentication.restrictionLeftAt': null,
      ...(fcmToken && { fcmToken }),
    },
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

export const getSanitizeEmail = (email: string): string => {
  return email.toLowerCase().trim()
}
