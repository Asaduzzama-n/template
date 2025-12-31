import { Request, Response } from 'express'
import catchAsync from '../../../../shared/catchAsync'
import sendResponse from '../../../../shared/sendResponse'
import { IUser } from '../../user/user.interface'
import { PassportAuthServices } from './passport.auth.service'

const googleAuthCallback = catchAsync(async (req: Request, res: Response) => {
  const result = await PassportAuthServices.handleGoogleLogin(
    req.user as IUser & { profile: any },
  )
  const { status, message, accessToken, refreshToken, role } = result
  sendResponse(res, {
    statusCode: status,
    success: true,
    message: message,
    data: { accessToken, refreshToken, role },
  })
})

export const PassportAuthController = {
  googleAuthCallback,
}
