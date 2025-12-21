import { HydratedDocument, Model, Types } from 'mongoose'

type IAuthentication = {
  isRestricted: boolean
  restrictionLeftAt: Date | null
  wrongLoginAttempts: number | 0
  passwordChangedAt?: Date | null
}

export type Point = {
  type: 'Point'
  coordinates: [number, number] // [longitude, latitude]
}

export interface IUser {
  _id: Types.ObjectId
  name?: string
  email: string
  profile?: string
  phone?: string
  status: string
  verified: boolean
  address?: string
  location: Point
  password: string
  role: string
  appId?: string
  fcmToken?: string
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

export type UserDocument = HydratedDocument<IUser>
