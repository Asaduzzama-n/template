import jwt, { JwtPayload, Secret } from 'jsonwebtoken'
import { StringValue } from 'ms'

const createToken = (
  payload: object,
  secret: Secret,
  expireTime: string | number | StringValue,
) => {
  return jwt.sign(payload, secret, { expiresIn: expireTime as any })
}



const verifyToken = (token: string, secret: Secret) => {
  return jwt.verify(token, secret) as JwtPayload
}

export const jwtHelper = { createToken, verifyToken }
