import { Model, Types } from 'mongoose'

export type IOtp = {
  _id: Types.ObjectId
  email: string
  phone: string
  restrictionLeftAt: Date
  resetPassword: boolean
  wrongLoginAttempts: number
  passwordChangedAt: Date
  oneTimeCode: string
  latestRequestAt?: Date
  expiresAt?: Date
  requestCount?: number
  authType?: 'createAccount' | 'resetPassword'
  createdAt: Date
  updatedAt: Date
}

export type OtpModel = Model<IOtp>
