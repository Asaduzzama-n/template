import jwt, { JwtPayload, Secret, SignOptions } from 'jsonwebtoken'

// ─── Token Creation ───────────────────────────────────────────────────────────
const createToken = (
  payload: object,
  secret: Secret,
  expireTime: string | number,
): string => {
  const options: SignOptions = {
    expiresIn: expireTime as SignOptions['expiresIn'],
    algorithm: 'HS256', // explicit — never rely on library default
  }
  return jwt.sign(payload, secret, options)
}

// ─── Token Verification ───────────────────────────────────────────────────────
/**
 * Verifies a JWT and returns its decoded payload.
 * Throws `TokenExpiredError` or `JsonWebTokenError` on failure —
 * callers should discriminate by `error.name`.
 */
const verifyToken = (token: string, secret: Secret): JwtPayload => {
  return jwt.verify(token, secret, { algorithms: ['HS256'] }) as JwtPayload
}

// ─── Token Decoding (no verification) ────────────────────────────────────────
/**
 * Decodes a token WITHOUT verifying the signature.
 * Useful for reading expiry time or user info from an expired token.
 * NEVER use this for authentication decisions.
 */
const decodeToken = (token: string): JwtPayload | null => {
  return jwt.decode(token) as JwtPayload | null
}

export const jwtHelper = { createToken, verifyToken, decodeToken }
