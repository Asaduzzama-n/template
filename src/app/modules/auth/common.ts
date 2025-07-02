import { StatusCodes } from 'http-status-codes'
import { ILoginData } from '../../../interfaces/auth'
import ApiError from '../../../errors/ApiError'
import { USER_STATUS } from '../../../enum/user'
import { User } from '../user/user.model'
import { AuthHelper } from './auth.helper'
import { generateOtp } from '../../../utils/crypto'

const handleLoginLogic = async (payload: ILoginData, isUserExist: any) => {
  const { authentication, verified, status, password } = isUserExist

  const { restrictionLeftAt, wrongLoginAttempts } = authentication



  if (!verified) {
    //send otp to user
    
    const otp = generateOtp()
    const otpExpiresIn = new Date(Date.now() + 5 * 60 * 1000)

    const authentication = {
      email: payload.email,
      oneTimeCode: otp,
      expiresAt: otpExpiresIn,
      latestRequestAt: new Date(),
      authType: 'createAccount',
    }

    await User.findByIdAndUpdate(isUserExist._id, {
      $set: {
        authentication,
      },
    })

    return {
      status: StatusCodes.PROXY_AUTHENTICATION_REQUIRED,
      message: 'Your email is not verified, please verify your email and try again.',
    }
  }

  if (status === USER_STATUS.DELETED) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'No account found with this email',
    )
  }

  if (status === USER_STATUS.RESTRICTED) {
    if (restrictionLeftAt && new Date() < restrictionLeftAt) {
      const remainingMinutes = Math.ceil(
        (restrictionLeftAt.getTime() - Date.now()) / 60000,
      )
      throw new ApiError(
        StatusCodes.TOO_MANY_REQUESTS,
        `You are restricted to login for ${remainingMinutes} minutes`,
      )
    }

    // Handle restriction expiration
    await User.findByIdAndUpdate(isUserExist._id, {
      $set: {
        authentication: { restrictionLeftAt: null, wrongLoginAttempts: 0 },
        status: USER_STATUS.ACTIVE,
      },
    })
  }

  const isPasswordMatched = await User.isPasswordMatched(
    payload.password,
    password,
  )

  if (!isPasswordMatched) {
    isUserExist.authentication.wrongLoginAttempts = wrongLoginAttempts + 1

    if (isUserExist.authentication.wrongLoginAttempts >= 5) {
      isUserExist.status = USER_STATUS.RESTRICTED
      isUserExist.authentication.restrictionLeftAt = new Date(
        Date.now() + 10 * 60 * 1000,
      ) // restriction for 10 minutes
    }

    await User.findByIdAndUpdate(isUserExist._id, {
      $set: {
        status: isUserExist.status,
        authentication: {
          restrictionLeftAt: isUserExist.authentication.restrictionLeftAt,
          wrongLoginAttempts: isUserExist.authentication.wrongLoginAttempts,
        },
      },
    })

    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Incorrect password, please try again.',
    )
  }

  await User.findByIdAndUpdate(
    isUserExist._id,
    {
      $set: {
        deviceToken: payload.deviceToken,
        authentication: {
          restrictionLeftAt: null,
          wrongLoginAttempts: 0,
        },
      },
    },
    { new: true },
  )

  const tokens = AuthHelper.createToken(isUserExist._id, isUserExist.role, isUserExist.name, isUserExist.email)
  return {
    status: StatusCodes.OK,
    message: `Welcome back ${isUserExist.name}`,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    role: isUserExist.role,
  }
}

export const AuthCommonServices = {
  handleLoginLogic,
}
