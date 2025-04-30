import { StatusCodes } from 'http-status-codes'
import { User } from '../../user/user.model'
import { AuthHelper } from '../auth.helper'
import ApiError from '../../../../errors/ApiError'
import { USER_STATUS } from '../../../../enum/user'
import config from '../../../../config'
import { Token } from '../../token/token.model'
import { IResetPassword } from '../auth.interface'
import { emailHelper } from '../../../../helpers/emailHelper'
import { emailTemplate } from '../../../../shared/emailTemplate'
import { generateOtp } from '../../../../utils/crypto'
import bcrypt from 'bcrypt'
import { ILoginData } from '../../../../interfaces/auth'
import { AuthCommonServices } from '../common'
import { jwtHelper } from '../../../../helpers/jwtHelper'
import { JwtPayload } from 'jsonwebtoken'

const customLogin = async (payload: ILoginData) => {
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

const forgetPassword = async (email?: string, phone?: string) => {
  const query = email ? { email: email } : { phone: phone }
  const isUserExist = await User.findOne({
    ...query,
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] },
  })

  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'No account found with this email or phone',
    )
  }

  const otp = generateOtp()
  const authentication = {
    oneTimeCode: otp,
    resetPassword: true,
    latestRequestAt: new Date(),
    requestCount: 1,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
    authType: 'resetPassword',
  }

  //send otp to user
  if (email) {
    const forgetPasswordEmailTemplate = emailTemplate.resetPassword({
      name: isUserExist.name as string,
      email: isUserExist.email as string,
      otp,
    })
    emailHelper.sendEmail(forgetPasswordEmailTemplate)
  }

  if (phone) {
    //implement this feature using twilio/aws sns
  }

  await User.findByIdAndUpdate(isUserExist._id, { $set: { authentication } })
  return { message: 'OTP sent successfully' }
}

const resetPassword = async (resetToken: string, payload: IResetPassword) => {
  const { newPassword, confirmPassword } = payload
  if (newPassword !== confirmPassword) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Passwords do not match')
  }

  const isTokenExist = await Token.findOne({ token: resetToken }).lean()
  if (!isTokenExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      "You don't have authorization to reset your password",
    )
  }

  const isUserExist = await User.findById(isTokenExist.user)
    .select('+authentication')
    .lean()
  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Something went wrong, please try again.',
    )
  }

  const { authentication } = isUserExist
  if (!authentication?.resetPassword) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'You don\'t have permission to change the password. Please click again to "Forgot Password"',
    )
  }

  const isTokenValid = authentication?.expiresAt! > new Date()
  if (!isTokenValid) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Your reset token has expired, please try again.',
    )
  }

  const hashPassword = bcrypt.hash(
    newPassword,
    config.bcrypt_salt_rounds as string,
  )
  const updatedUserData = {
    password: hashPassword,
    authentication: {
      resetPassword: false,
    },
  }

  await User.findByIdAndUpdate(
    isUserExist._id,
    { $set: updatedUserData },
    { new: true },
  )

  return { message: 'Password reset successfully' }
}

const verifyAccount = async (
  onetimeCode: string,
  email?: string,
  phone?: string,
) => {
  //verify fo new user

  if (!onetimeCode) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'OTP is required')
  }

  const query = email ? { email: email } : { phone: phone }

  const isUserExist = await User.findOne({
    ...query,
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] },
  })
    .select('+authentication')
    .lean()
  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'No account found with this email or phone',
    )
  }

  const { authentication } = isUserExist
  if (authentication?.oneTimeCode !== onetimeCode) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'You provided wrong OTP, please try again.',
    )
  }

  const currentDate = new Date()
  if (authentication?.expiresAt! < currentDate) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'OTP has expired, please try again.',
    )
  }

  const returnable = {
    message: '',
    token: '',
  }
  if (!isUserExist.verified) {
    await User.findByIdAndUpdate(
      isUserExist._id,
      { $set: { verified: true } },
      { new: true },
    )
    returnable.message = 'Account verified successfully'
  } else {
    const authentication = {
      oneTimeCode: null,
      resetPassword: true,
    }
    await User.findByIdAndUpdate(
      isUserExist._id,
      { $set: { authentication } },
      { new: true },
    )

    const resetToken = AuthHelper.createToken(isUserExist._id, isUserExist.role)
    returnable.token = resetToken.accessToken
    returnable.message =
      'OTP verified successfully, please reset your password.'
  }
  return returnable
}

const getRefreshToken = async (token: string) => {
  try {
    const decodedToken = jwtHelper.verifyToken(
      token,
      config.jwt.jwt_refresh_secret as string,
    )

    const { userId, role } = decodedToken

    const tokens = AuthHelper.createToken(userId, role)

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

const socialLogin = async (appId: string, deviceToken: string) => {
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
    const tokens = AuthHelper.createToken(createdUser._id, createdUser.role)
    return tokens.accessToken
  } else {
    await User.findByIdAndUpdate(isUserExist._id, {
      $set: {
        deviceToken,
      },
    })

    const tokens = AuthHelper.createToken(isUserExist._id, isUserExist.role)
    //send token to client
    return tokens.accessToken
  }
}

const resendOtpToPhoneOrEmail = async (
  type: 'verify' | 'reset',
  email?: string,
  phone?: string,
) => {
  const query = email ? { email: email } : { phone: phone }
  const isUserExist = await User.findOne({
    ...query,
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] },
  }).select('+authentication')
  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      `No account found with this ${email ? 'email' : 'phone'}`,
    )
  }

  //check the request count
  const { authentication } = isUserExist
  if (authentication?.requestCount! >= 5) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'You have exceeded the maximum number of requests. Please try again later.',
    )
  }
  const otp = generateOtp()
  const updatedAuthentication = {
    oneTimeCode: otp,
    latestRequestAt: new Date(),
    requestCount: authentication?.requestCount! + 1,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
  }

  //send otp to user
  if (email) {
    const forgetPasswordEmailTemplate = emailTemplate.resendOtp({
      email: isUserExist.email as string,
      name: isUserExist.name as string,
      otp,
      type,
    })
    emailHelper.sendEmail(forgetPasswordEmailTemplate)

    await User.findByIdAndUpdate(
      isUserExist._id,
      {
        $set: { authentication: updatedAuthentication },
      },
      { new: true },
    )
  }

  if (phone) {
    //implement this feature using twilio/aws sns

    await User.findByIdAndUpdate(
      isUserExist._id,
      {
        $set: { authentication: updatedAuthentication },
      },
      { new: true },
    )
  }
}

const deleteAccount = async (user: JwtPayload) => {
  const { authId } = user
  const isUserExist = await User.findById(authId)

  if (!isUserExist) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Requested user not found.')
  }

  if (isUserExist.status === USER_STATUS.DELETED) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Requested user is already deleted.',
    )
  }

  const deletedData = await User.findByIdAndUpdate(authId, {
    $set: { status: USER_STATUS.DELETED },
  })

  return 'Account deleted successfully.'
}

const resendOtp = async (email?: string, phone?: string) => {
  const query = email ? { email: email } : { phone: phone }
  const isUserExist = await User.findOne({
    ...query,
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] },
  }).select('+authentication')

  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      `No account found with this ${email ? 'email' : 'phone'}`,
    )
  }
  const otp = generateOtp()
  const authentication = {
    oneTimeCode: otp,
    latestRequestAt: new Date(),
    requestCount: isUserExist.authentication?.requestCount! + 1,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
  }

  await User.findByIdAndUpdate(isUserExist._id, {
    $set: { authentication },
  })

  if (isUserExist.authentication.requestCount! >= 4) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'You have exceeded the maximum number of requests. Please try again later.',
    )
  }
  //send otp to user
  if (email) {
    const forgetPasswordEmailTemplate = emailTemplate.resendOtp({
      email: isUserExist.email as string,
      name: isUserExist.name as string,
      otp,
      type: 'verify',
    })
    emailHelper.sendEmail(forgetPasswordEmailTemplate)
  }

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
    throw new ApiError(
      StatusCodes.UNAUTHORIZED,
      'Current password is incorrect',
    )
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
  forgetPassword,
  resetPassword,
  verifyAccount,
  customLogin,
  getRefreshToken,
  socialLogin,
  resendOtpToPhoneOrEmail,
  deleteAccount,
  resendOtp,
  changePassword,
}
