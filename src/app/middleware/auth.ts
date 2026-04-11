import { NextFunction, Request, Response } from 'express'
import { StatusCodes } from 'http-status-codes'
import { Secret } from 'jsonwebtoken'
import config from '../../config'
import { jwtHelper } from '../../helpers/jwtHelper'
import ApiError from '../../errors/ApiError'
import { USER_ROLES } from '../../enum/user'

// ─── Auth Middleware Factory ──────────────────────────────────────────────────
/**
 * Factory that returns an auth middleware using the given JWT secret.
 * Eliminates duplicated logic between `auth` and `tempAuth`.
 */
const makeAuth =
  (secret: Secret) =>
  (...roles: string[]) =>
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const tokenWithBearer = req.headers.authorization

      // ── No token ──────────────────────────────────────────────────────────
      if (!tokenWithBearer) {
        // Allow guest-accessible routes through
        if (roles.includes(USER_ROLES.GUEST)) {
          req.user = { role: USER_ROLES.GUEST }
          return next()
        }
        // 401 Unauthorized — not 404!
        throw new ApiError(
          StatusCodes.UNAUTHORIZED,
          'Authentication required. Please provide a valid token.',
        )
      }

      // ── Extract token ─────────────────────────────────────────────────────
      if (!tokenWithBearer.startsWith('Bearer ')) {
        throw new ApiError(
          StatusCodes.UNAUTHORIZED,
          'Malformed authorization header. Expected format: Bearer <token>',
        )
      }

      const token = tokenWithBearer.split(' ')[1]

      try {
        const verifyUser = jwtHelper.verifyToken(token, secret)

        // Attach user to request
        req.user = verifyUser

        // Role guard
        if (roles.length && !roles.includes(verifyUser.role)) {
          throw new ApiError(
            StatusCodes.FORBIDDEN,
            "You don't have permission to access this resource.",
          )
        }

        next()
      } catch (error) {
        if (error instanceof ApiError) throw error

        if (error instanceof Error) {
          if (error.name === 'TokenExpiredError') {
            throw new ApiError(
              StatusCodes.UNAUTHORIZED,
              'Access token has expired. Please refresh your session.',
            )
          }
          if (error.name === 'JsonWebTokenError') {
            throw new ApiError(StatusCodes.UNAUTHORIZED, 'Invalid access token.')
          }
        }

        throw new ApiError(StatusCodes.UNAUTHORIZED, 'Token verification failed.')
      }
    } catch (error) {
      next(error)
    }
  }

// ─── Standard Auth (uses primary JWT secret) ─────────────────────────────────
const auth = makeAuth(config.jwt.jwt_secret as Secret)
export default auth

// ─── Temp Auth (uses short-lived temp JWT secret for pre-verification flows) ──
//
// Used for temporary user verification before account creation is complete.
// e.g. the OTP verification step that returns a temp token to proceed.
export const tempAuth = makeAuth(config.jwt.temp_jwt_secret as Secret)
