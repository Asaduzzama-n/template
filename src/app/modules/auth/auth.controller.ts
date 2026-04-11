import { Request, Response } from 'express'
import { StatusCodes } from 'http-status-codes'
import catchAsync from '../../../shared/catchAsync'
import sendResponse from '../../../shared/sendResponse'
import config from '../../../config'
import { AuthServices } from './auth.service'
import { IAuthResponse } from './auth.interface'

const setRefreshTokenCookie = (res: Response, refreshToken: string) => {
  res.cookie('refreshToken', refreshToken, {
    secure: config.node_env === 'production',
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 180 * 24 * 60 * 60 * 1000, // 180 days matching JWT expire
  })
}

const signup = catchAsync(async (req: Request, res: Response) => {
  const result = await AuthServices.signup(req.body)
  sendResponse(res, {
    statusCode: StatusCodes.CREATED,
    success: true,
    message: result,
    data: null,
  })
})

const login = catchAsync(async (req: Request, res: Response) => {
  const result = await AuthServices.login(req.body)
  const { accessToken, refreshToken, role, message } = result

  if (refreshToken) setRefreshTokenCookie(res, refreshToken)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message,
    data: { accessToken, role },
  })
})

const adminLogin = catchAsync(async (req: Request, res: Response) => {
  const result = await AuthServices.login(req.body, 'admin')
  const { accessToken, refreshToken, role, message } = result

  if (refreshToken) setRefreshTokenCookie(res, refreshToken)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message,
    data: { accessToken, role },
  })
})

const socialLogin = catchAsync(async (req: Request, res: Response) => {
  const result = await AuthServices.socialLogin(req.body)
  const { accessToken, refreshToken, role, message } = result

  if (refreshToken) setRefreshTokenCookie(res, refreshToken)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message,
    data: { accessToken, role },
  })
})

const googleAuthCallback = catchAsync(async (req: Request, res: Response) => {
  const result = await AuthServices.handleGoogleLogin(req.user as any)
  const { accessToken, refreshToken, role, message } = result

  if (refreshToken) setRefreshTokenCookie(res, refreshToken)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message,
    data: { accessToken, role },
  })
})

const verifyAccount = catchAsync(async (req: Request, res: Response) => {
  const result = await AuthServices.verifyAccount(req.body)
  const { accessToken, refreshToken, role, token, message } = result

  if (refreshToken) setRefreshTokenCookie(res, refreshToken)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message,
    data: { accessToken, role, token },
  })
})

const refreshToken = catchAsync(async (req: Request, res: Response) => {
  const { refreshToken } = req.cookies
  const result = await AuthServices.refreshToken(refreshToken)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Token refreshed successfully',
    data: result,
  })
})

const forgetPassword = catchAsync(async (req: Request, res: Response) => {
  const { email } = req.body
  const result = await AuthServices.forgetPassword(email)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: result,
    data: null,
  })
})

const resetPassword = catchAsync(async (req: Request, res: Response) => {
  const token = req.headers.authorization
  const result = await AuthServices.resetPassword(token!, req.body)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: result.message,
    data: null,
  })
})

const changePassword = catchAsync(async (req: Request, res: Response) => {
  const result = await AuthServices.changePassword(req.user!, req.body)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: result.message,
    data: null,
  })
})

const resendOtp = catchAsync(async (req: Request, res: Response) => {
  const { email, type } = req.body
  const result = await AuthServices.resendOtp(email, type)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: result,
    data: null,
  })
})

const deleteAccount = catchAsync(async (req: Request, res: Response) => {
  const result = await AuthServices.deleteAccount(req.user!, req.body.password)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: result,
    data: null,
  })
})

export const AuthControllers = {
  signup,
  login,
  adminLogin,
  socialLogin,
  googleAuthCallback,
  verifyAccount,
  refreshToken,
  forgetPassword,
  resetPassword,
  changePassword,
  resendOtp,
  deleteAccount,
}
