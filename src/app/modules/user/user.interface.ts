import { Model, Types } from 'mongoose'

type IAuthentication = {
  restrictionLeftAt: Date | null
  resetPassword: boolean
  wrongLoginAttempts: number
  passwordChangedAt?: Date
  oneTimeCode: string
  latestRequestAt: Date
  expiresAt?: Date
  requestCount?: number
  authType?: 'createAccount' | 'resetPassword'
}


export type Point = {
  type: 'Point'
  coordinates: [number, number] // [longitude, latitude]
}

export type IUser = {
  _id: Types.ObjectId
  name?: string
  email?: string
  profile?: string
  phone?: string
  status: string
  verified: boolean
  address?: string
  location: Point
  password: string
  role: string
  appId?: string
  deviceToken?: string

  authentication: IAuthentication
  createdAt: Date
  updatedAt: Date
}

export type UserModel = {
  isPasswordMatched: (
    givenPassword: string,
    savedPassword: string,
  ) => Promise<boolean>
} & Model<IUser>
