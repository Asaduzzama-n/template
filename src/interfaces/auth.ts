export type IVerifyEmail = {
  email: string
  oneTimeCode: number
}

export type ILoginData = {
  email: string
  password: string
  fcmToken?: string
}

export type ISocialLoginData = {
  appId: string
  fcmToken?: string
}

export type IAuthResetPassword = {
  newPassword: string
  confirmPassword: string
}

export type IChangePassword = {
  currentPassword: string
  newPassword: string
  confirmPassword: string
}
