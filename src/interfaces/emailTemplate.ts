import { VERIFICATION_TYPE } from "../app/modules/verification/verification.interface"

export type ICreateAccount = {
  email: string
  otp: string
  name?: string
}

export type IResetPassword = {
  name: string
  email: string
  otp: string
}


export type IEmailOrPhoneVerification = {
  name: string
  email?: string
  phone?: string
  type: VERIFICATION_TYPE.ACCOUNT_ACTIVATION | VERIFICATION_TYPE.RESET_PASSWORD
}