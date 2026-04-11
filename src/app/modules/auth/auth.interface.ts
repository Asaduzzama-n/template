import { Types } from 'mongoose'

export type IAuthResponse = {
  status: number
  message: string
  role?: string
  accessToken?: string
  refreshToken?: string
  token?: string // for reset tokens
}

export type IVerifyAccountPayload = {
  email: string
  oneTimeCode: string
  type: string // from VERIFICATION_TYPE
}

export type ISocialLoginPayload = {
  appId: string
  fcmToken: string
}

export type ITokenResponse = {
  accessToken: string
  refreshToken?: string
}