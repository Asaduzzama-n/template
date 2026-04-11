import { NextFunction, Request, Response } from 'express'
import { Secret } from 'jsonwebtoken'
import { StatusCodes } from 'http-status-codes'
import config from '../../config'
import { jwtHelper } from '../../helpers/jwtHelper'
import ApiError from '../../errors/ApiError'
import { USER_ROLES, USER_STATUS } from '../../enum/user'
import { User } from '../modules/user/user.model'
import { AuthCache } from '../modules/auth/auth.cache'
import { AuthHelper } from '../modules/auth/auth.helper'

// ─── Auth Middleware Factory ──────────────────────────────────────────────────
/**
 * Factory that returns an auth middleware using the given JWT secret.
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
        const { authId, iat } = verifyUser

        // ── Security Check (Instant Revocation) ─────────────────────────────
        // 1. Check Redis Cache First (O(1) - Fast)
        let securityData = await AuthCache.getAuthCache(authId)

        // 2. Fallback to DB if cache miss
        if (!securityData) {
          const user = await User.findById(authId)
            .select('+authentication')
            .lean()
          if (!user) {
            throw new ApiError(
              StatusCodes.UNAUTHORIZED,
              'Account no longer exists.',
            )
          }

          securityData = {
            status: user.status,
            passwordChangedAt:
              user.authentication?.passwordChangedAt?.toISOString() || null,
          }
          // Populate cache for 1 hour
          await AuthCache.setAuthCache(authId, securityData)
        }

        // 3. Status Invalidation
        if (securityData.status === USER_STATUS.DELETED) {
          throw new ApiError(
            StatusCodes.FORBIDDEN,
            'This account has been deleted.',
          )
        }
        if (securityData.status === USER_STATUS.RESTRICTED) {
          throw new ApiError(
            StatusCodes.FORBIDDEN,
            'Your access has been restricted.',
          )
        }

        // 4. Password Change Invalidation
        if (securityData.passwordChangedAt && iat) {
          const changedAt = new Date(securityData.passwordChangedAt)
          if (AuthHelper.isTokenInvalidated(changedAt, iat)) {
            throw new ApiError(
              StatusCodes.UNAUTHORIZED,
              'Session expired due to password change. Please login again.',
            )
          }
        }

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
            throw new ApiError(
              StatusCodes.UNAUTHORIZED,
              'Invalid access token.',
            )
          }
        }

        throw new ApiError(
          StatusCodes.UNAUTHORIZED,
          'Token verification failed.',
        )
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
