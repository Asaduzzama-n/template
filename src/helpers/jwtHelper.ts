import jwt, { JwtPayload, Secret, SignOptions } from 'jsonwebtoken'

const createToken = (
  payload: JwtPayload | object,
  secret: Secret,
  expiresIn: SignOptions['expiresIn'],
): string => {
  return jwt.sign(payload, secret, { expiresIn })
}

const verifyToken = (token: string, secret: Secret): JwtPayload => {
  return jwt.verify(token, secret) as JwtPayload
}

export const jwtHelper = { createToken, verifyToken }
