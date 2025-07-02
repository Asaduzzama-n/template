import { Request, Response } from 'express'
import catchAsync from '../../../../shared/catchAsync'
import sendResponse from '../../../../shared/sendResponse'
import { IUser } from '../../user/user.interface'
import { StatusCodes } from 'http-status-codes'
import { ILoginResponse } from '../../../../interfaces/response'
import { PassportAuthServices } from './passport.auth.service'
import { AuthCommonServices } from '../common'

const login = catchAsync(async (req: Request, res: Response) => {
  const user = req.user
  const { deviceToken, password } = req.body

  const result = await AuthCommonServices.handleLoginLogic(
    { deviceToken: deviceToken, password: password },
    user as IUser,
  )

  sendResponse<ILoginResponse>(res, {
    statusCode: result.status,
    success: true,
    message: result.message,
    data: result,
  })
})

const googleAuthCallback = catchAsync(async (req: Request, res: Response) => {
  const result = await PassportAuthServices.handleGoogleLogin(
    req.user as IUser & { profile: any },
  )
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Login successful',
    data: result,
  })
})

export const PassportAuthController = {
  login,
  googleAuthCallback,
}
