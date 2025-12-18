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

const MAX_WRONG_ATTEMPTS = 5
const RESTRICTION_MINUTES = 10
const OTP_EXPIRY_MINUTES = 5

const handleLoginLogic = async (
  payload: ILoginData,
  user: IUser,
): Promise<IAuthResponse> => {
  const { password: hashedPassword, authentication, status, verified } = user

  const { wrongLoginAttempts = 0, restrictionLeftAt } = authentication || {}


  if (
    status === USER_STATUS.RESTRICTED &&
    restrictionLeftAt &&
    new Date() < restrictionLeftAt
  ) {
    const remainingMinutes = Math.ceil(
      (restrictionLeftAt.getTime() - Date.now()) / 60000,
    )

    throw new ApiError(
      StatusCodes.TOO_MANY_REQUESTS,
      `Too many failed attempts. Try again in ${remainingMinutes} minutes.`,
    )
  }


  const isPasswordMatched = await User.isPasswordMatched(
    payload.password,
    hashedPassword,
  )

  if (!isPasswordMatched) {
    const attempts = wrongLoginAttempts + 1
    const isRestricted = attempts >= MAX_WRONG_ATTEMPTS

    await User.findByIdAndUpdate(user._id, {
      $set: {
        status: isRestricted ? USER_STATUS.RESTRICTED : user.status,
        'authentication.restrictionLeftAt': isRestricted
          ? new Date(Date.now() + RESTRICTION_MINUTES * 60 * 1000)
          : null,
      },
      $inc: {
        'authentication.wrongLoginAttempts': 1,
      },
    })

    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Incorrect password, please try again.',
    )
  }


  if (!verified) {
    const otp = await generateOtp()
    const otpExpiresIn = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000)

    await User.findByIdAndUpdate(user._id, {
      $set: {
        'authentication.oneTimeCode': otp,
        'authentication.expiresAt': otpExpiresIn,
        'authentication.latestRequestAt': new Date(),
        'authentication.authType': 'loginVerification',
      },
    })

    const otpTemplate = emailTemplate.createAccount({
      name: user.name!,
      email: user.email!,
      otp: otp.otp,
    })

    await emailHelper.sendEmail(otpTemplate)

    return authResponse(
      StatusCodes.UNAUTHORIZED,
      `An OTP has been sent to your email. Please verify to continue.`,
    )
  }

  await User.findByIdAndUpdate(
    user._id,
    {
      $set: {
        status: USER_STATUS.ACTIVE,
        'authentication.wrongLoginAttempts': 0,
        'authentication.restrictionLeftAt': null,
        ...(payload.deviceToken && { deviceToken: payload.deviceToken }),
      },
    },
    { new: true },
  )


  const tokens = AuthHelper.createToken(
    user._id,
    user.role,
    user.name,
    user.email,
  )

  return authResponse(
    StatusCodes.OK,
    `Welcome back ${user.name}`,
    user.role,
    tokens.accessToken,
    tokens.refreshToken,
  )
}

export const AuthCommonServices = {
  handleLoginLogic,
}

export const authResponse = (
  status: number,
  message: string,
  role?: string,
  accessToken?: string,
  refreshToken?: string,
  token?: string,
): IAuthResponse => {
  return {
    status,
    message,
    ...(role && { role }),
    ...(accessToken && { accessToken }),
    ...(refreshToken && { refreshToken }),
    ...(token && { token }),
  }
}
