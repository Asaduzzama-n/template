import { Secret } from 'jsonwebtoken'
import { jwtHelper } from '../../../helpers/jwtHelper'
import config from '../../../config'
import { Types } from 'mongoose'
import bcrypt from 'bcrypt'

const createToken = (
  authId: Types.ObjectId,
  role: string,
  name?: string,
  email?: string,
  profile?: string,
  fcmToken?: string,
) => {
  const accessToken = jwtHelper.createToken(
    { authId, role, name, email, profile, fcmToken },
    config.jwt.jwt_secret as Secret,
    config.jwt.jwt_expire_in as string,
  )
  const refreshToken = jwtHelper.createToken(
    { authId, role, name, email, fcmToken },
    config.jwt.jwt_refresh_secret as Secret,
    config.jwt.jwt_refresh_expire_in as string,
  )

  return { accessToken, refreshToken }
}

const tempAccessToken = (
  authId: Types.ObjectId,
  role: string,
  name?: string,
  email?: string,
  profile?: string,
  fcmToken?: string,
) => {
  const accessToken = jwtHelper.createToken(
    { authId, role, name, email, profile, fcmToken },
    'asjdhashd#$uaas98',
    config.jwt.jwt_expire_in as string,
  )

  return { accessToken }
}

const isPasswordMatched = async (
  plainTextPassword: string,
  hashedPassword: string,
) => {
  return await bcrypt.compare(plainTextPassword, hashedPassword)
}

const isTokenInvalidated = (
  passwordChangedAt: Date,
  tokenIssuedAt: number,
): boolean => {
  // Convert Mongoose Date (ms) to Unix Timestamp (seconds)
  const passwordChangedTime = Math.floor(passwordChangedAt.getTime() / 1000)
  return passwordChangedTime > tokenIssuedAt
}

export const AuthHelper = { createToken, isPasswordMatched, isTokenInvalidated }
