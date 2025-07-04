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
import cryptoToken, { generateOtp } from '../../../../utils/crypto'
import bcrypt from 'bcrypt'
import { ILoginData } from '../../../../interfaces/auth'
import { AuthCommonServices } from '../common'
import { jwtHelper } from '../../../../helpers/jwtHelper'
import { JwtPayload } from 'jsonwebtoken'
import { IUser } from '../../user/user.interface'


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

  const otp = generateOtp()
  const otpExpiresIn = new Date(Date.now() + 5 * 60 * 1000)

  const authentication = {
    email: payload.email,
    oneTimeCode: otp,
    expiresAt: otpExpiresIn,
    latestRequestAt: new Date(),
    requestCount: 1,
    authType: 'createAccount',
  }

  //send email or sms with otp
  const createAccount = emailTemplate.createAccount({
    name: payload.name!,
    email: payload.email!.toLowerCase().trim(),
    otp,
  })


  const user = await User.create({
    ...payload,
    password: payload.password,
    authentication,
  })

  if(!user){
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Failed to create user.')
  }
  emailHelper.sendEmail(createAccount)

  return "Account created successfully."
}

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
  const query = email ? { email: email.toLocaleLowerCase().trim() } : { phone: phone }
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



  if (phone) {
    //implement this feature using twilio/aws sns
  }

  const authentication ={
    email: isUserExist.email,
    resetPassword: true,
    oneTimeCode: otp,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    latestRequestAt: new Date(),
    requestCount: 1,
    authType: 'resetPassword',
  }
  
  await User.findByIdAndUpdate(
    isUserExist._id,
    {
      $set: { 'authentication': authentication },
    },
    { new: true },
  )
  

    // //send otp to user
  if (email) {
    const forgetPasswordEmailTemplate = emailTemplate.resetPassword({
      name: isUserExist.name as string,
      email: isUserExist.email as string,
      otp,
    })
    emailHelper.sendEmail(forgetPasswordEmailTemplate)
  }

  return "OTP sent successfully."
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
      "You don't have authorization to reset your password, please verify your account first.",
    )
  }

  const isUserExist = await User.findById(isTokenExist.user)
    .select('+authentication')
    .lean()


  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Something went wrong, please try again. or contact support.',
    )
  }

  const { authentication } = isUserExist
  if (!authentication?.resetPassword) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'You don\'t have permission to change the password. Please click again to "Forgot Password"',
    )
  }

  const isTokenValid = isTokenExist?.expireAt > new Date()
  if (!isTokenValid) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Your reset token has expired, please try again.',
    )
  }

  const hashPassword = await bcrypt.hash(
    newPassword,
    Number(config.bcrypt_salt_rounds),
  )
  const updatedUserData = {
    password: hashPassword,
    authentication: {
      resetPassword: false,
      otp: '',
      expiresAt: null,
      latestRequestAt: null,
      requestCount: 0,
      authType: '',
    },
  }

  await User.findByIdAndUpdate(
    isUserExist._id,
    { $set: updatedUserData },
    { new: true },
  )

  return { message: 'Password reset successfully' }
}

const verifyAccount = async (email:string, onetimeCode: string) => {
  //verify fo new user
  if (!onetimeCode) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'OTP is required.')
  }
  const isUserExist = await User.findOne({
    email: email.toLowerCase().trim(),
    status: { $nin: [USER_STATUS.DELETED] },
  }).select('+password +authentication')
  .lean()

  if(!isUserExist){
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      `No account found with this ${email}, please register first.`,
    )
  }

  const { authentication } = isUserExist

  //check the otp
  if (authentication?.oneTimeCode !== onetimeCode) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Invalid OTP, please try again.')
  }

  const currentDate = new Date()
  if (authentication?.expiresAt! < currentDate) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'OTP has expired, please try again.',
    )
  }


  //either newly created user or existing user
  if (!isUserExist.verified) {
    await User.findByIdAndUpdate(
      isUserExist._id,
      { $set: { verified: true } },
      { new: true },
    )

   return {
    status: StatusCodes.OK,
    message: `Welcome ${isUserExist.name} to our platform.`,
    token: AuthHelper.createToken(
      isUserExist._id,
      isUserExist.role,
      isUserExist.name,
      isUserExist.email,
    ),
    role: isUserExist.role,
   }
  }else{

    await User.findByIdAndUpdate(
      isUserExist._id,
      { $set: { authentication: { oneTimeCode: '', expiresAt: null, latestRequestAt: null, requestCount: 0, authType: '', resetPassword: true } } },
      { new: true },
    )

    const token = await Token.create({
      token: cryptoToken(),
      user: isUserExist._id,
      expireAt: new Date(Date.now() + 5 * 60 * 1000), // 15 minutes
    })

    if(!token){
      throw new ApiError(StatusCodes.BAD_REQUEST, 'Something went wrong, please try again. or contact support.')
    }
    return {
      status: StatusCodes.OK,
      message: 'OTP verified successfully, please reset your password.',
      token: token.token,
      role: isUserExist.role,
    }
  }

}

const getRefreshToken = async (token: string) => {
  try {
    const decodedToken = jwtHelper.verifyToken(
      token,
      config.jwt.jwt_refresh_secret as string,
    )

    const { userId, role } = decodedToken

    const tokens = AuthHelper.createToken(userId, role, decodedToken.name, decodedToken.email)

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
    const tokens = AuthHelper.createToken(createdUser._id, createdUser.role, createdUser.name, createdUser.email)
    return {
      status: StatusCodes.OK,
      message: `Welcome back ${createdUser.name}`,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      role: createdUser.role,
    }
  } else {
    await User.findByIdAndUpdate(isUserExist._id, {
      $set: {
        deviceToken,
      },
    })

    const tokens = AuthHelper.createToken(isUserExist._id, isUserExist.role, isUserExist.name, isUserExist.email)
    //send token to client
    return {
      status: StatusCodes.OK,
      message: `Welcome back ${isUserExist.name}`,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      role: isUserExist.role,
    }
  }
}

const resendOtpToPhoneOrEmail = async (
  authType: 'resetPassword' | 'createAccount',
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
      type:authType,
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

const deleteAccount = async (user: JwtPayload, password:string) => {
  const { authId } = user
  const isUserExist = await User.findById(authId).select('+password')
  if (!isUserExist) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Failed to delete account. Please try again.')
  }



  if (isUserExist.status === USER_STATUS.DELETED) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Requested user is already deleted.',
    )
  }

  const isPasswordMatched = await bcrypt.compare(
    password,
    isUserExist.password,
  )

  if (!isPasswordMatched) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Please provide a valid password to delete your account.')
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

const resendOtp = async (email:string, authType:'createAccount' | 'resetPassword') => {

  const isUserExist = await User.findOne({
    email: email.toLowerCase().trim(),
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] },
  }).select('+authentication')
  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      `No account found with this ${email}, please try again.`,
    )
  }

  const { authentication } = isUserExist

  const otp = generateOtp()
  const authenticationPayload = {
    oneTimeCode: otp,
    latestRequestAt: new Date(),
    requestCount: authentication?.requestCount! + 1,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
  }

  await User.findByIdAndUpdate(
    isUserExist._id,
    {
      $set: { authentication: authenticationPayload },
    },
    { new: true },
  )

  if (authenticationPayload.requestCount! >= 5) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'You have exceeded the maximum number of requests. Please try again later.',
    )
  }

  //send otp to user
  if (email) {
    const forgetPasswordEmailTemplate = emailTemplate.resendOtp({
      email: email as string,
      name: isUserExist.name as string,
      otp,
      type: authType,
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
      StatusCodes.BAD_REQUEST,
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
  createUser,
}
