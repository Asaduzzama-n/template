import { Request, Response } from 'express'
import catchAsync from '../../../../shared/catchAsync'
import { CustomAuthServices } from './custom.auth.service'
import sendResponse from '../../../../shared/sendResponse'
import { StatusCodes } from 'http-status-codes'
import config from '../../../../config'
import { IAuthResponse } from '../auth.interface'

const customLogin = catchAsync(async (req: Request, res: Response) => {
  console.log(req.body)
  const result = await CustomAuthServices.customLogin(req.body)

  const { refreshToken, status, message, accessToken, role } = result

  if (refreshToken) {
    res.cookie('refreshToken', refreshToken, {
      secure: config.node_env === 'production',
      httpOnly: true,
      sameSite: 'strict',
    })
  }

  sendResponse<Pick<IAuthResponse, 'accessToken' | 'role'>>(res, {
    statusCode: status,
    success: true,
    message: message,
    data: { accessToken, role },
  })
})

const adminLogin = catchAsync(async (req: Request, res: Response) => {
  const { ...loginData } = req.body

  const result = await CustomAuthServices.adminLogin(loginData)
  const { status, message, accessToken, refreshToken, role } = result

  sendResponse(res, {
    statusCode: status,
    success: true,
    message: message,
    data: { accessToken, refreshToken, role },
  })
})

const forgetPassword = catchAsync(async (req: Request, res: Response) => {
  const { email } = req.body
  const result = await CustomAuthServices.forgetPassword(email)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: `An OTP has been sent to your given email. Please verify your email.`,
    data: result,
  })
})

const resetPassword = catchAsync(async (req: Request, res: Response) => {
  const token = req.headers.authorization
  const { ...resetData } = req.body
  const result = await CustomAuthServices.resetPassword(token!, resetData)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Password reset successfully, please login now.',
    data: result,
  })
})

const verifyAccount = catchAsync(async (req: Request, res: Response) => {
  const { oneTimeCode, type, email } = req.body

  const result = await CustomAuthServices.verifyAccount(
    email,
    oneTimeCode,
    type,
  )
  const { status, message, accessToken, refreshToken, role, token } = result

  if (refreshToken) {
    res.cookie('refreshToken', refreshToken, {
      secure: config.node_env === 'production',
      httpOnly: true,
      sameSite: 'strict',
    })
  }
  sendResponse<Pick<IAuthResponse, 'accessToken' | 'role' | 'token'>>(res, {
    statusCode: status,
    success: true,
    message: message,
    data: { accessToken, role, token },
  })
})

const getRefreshToken = catchAsync(async (req: Request, res: Response) => {
  const { refreshToken } = req.cookies
  const result = await CustomAuthServices.getRefreshToken(refreshToken)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Token refreshed successfully',
    data: result,
  })
})

const resendOtp = catchAsync(async (req: Request, res: Response) => {
  const { email, phone, type } = req.body
  console.log(req.body)
  const result = await CustomAuthServices.resendOtp(email, type)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: `An OTP has been sent to your email. Please verify your email.`,
    data: result
  })
})

const changePassword = catchAsync(async (req: Request, res: Response) => {

  const result = await CustomAuthServices.changePassword(req.user!, req.body)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Password changed successfully',
    data: result,
  })
})

const createUser = catchAsync(async (req: Request, res: Response) => {
  const { ...userData } = req.body
  const result = await CustomAuthServices.createUser(userData)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'User created successfully',
    data: result,
  })
})
const deleteAccount = catchAsync(async (req: Request, res: Response) => {
  const user = req.user
  const { password } = req.body
  const result = await CustomAuthServices.deleteAccount(user!, password)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Account deleted successfully',
    data: result,
  })
})

const socialLogin = catchAsync(async (req: Request, res: Response) => {
  const { appId, fcmToken } = req.body
  const result = await CustomAuthServices.socialLogin(appId, fcmToken)
  const { status, message, accessToken, refreshToken, role } = result
  sendResponse(res, {
    statusCode: status,
    success: true,
    message: message,
    data: { accessToken, refreshToken, role },
  })
})
export const CustomAuthController = {
  forgetPassword,
  resetPassword,
  verifyAccount,
  customLogin,
  getRefreshToken,
  resendOtp,
  changePassword,
  createUser,
  deleteAccount,
  adminLogin,
  socialLogin,
}
