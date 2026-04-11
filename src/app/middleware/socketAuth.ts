import { StatusCodes } from 'http-status-codes'
import ApiError from '../../errors/ApiError'
import { ErrorResponse, SocketWithUser } from '../../interfaces/socket'
import { ExtendedError } from 'socket.io'
import { jwtHelper } from '../../helpers/jwtHelper'
import { Socket } from 'socket.io'
import colors from 'colors'
import { logger, errorLogger } from '../../shared/logger'
import config from '../../config'
import { Secret } from 'jsonwebtoken'
import { ZodSchema } from 'zod'
import handleZodError from '../../errors/handleZodError'

// ─── Token Extraction ──────────────────────────────────────────────────────────
/**
 * Extracts a raw JWT from a socket handshake token value.
 * Accepts: "Bearer <token>", or a raw token string.
 * Rejects: JSON blobs (previously accepted, now a security risk).
 */
const extractToken = (token: string | string[]): string => {
  const raw = Array.isArray(token) ? token[0] : token
  if (typeof raw !== 'string') {
    throw new ApiError(StatusCodes.UNAUTHORIZED, 'Invalid token format')
  }
  // Handle standard Bearer prefix
  if (raw.startsWith('Bearer ')) {
    return raw.slice(7)
  }
  // Return raw token (already a JWT)
  return raw
}

// ─── Error Helpers ────────────────────────────────────────────────────────────
const getErrorName = (statusCode: number): string => {
  switch (statusCode) {
    case StatusCodes.BAD_REQUEST:
      return 'Bad Request'
    case StatusCodes.UNAUTHORIZED:
      return 'Unauthorized'
    case StatusCodes.FORBIDDEN:
      return 'Forbidden'
    case StatusCodes.NOT_FOUND:
      return 'Not Found'
    default:
      return 'Internal Server Error'
  }
}

const createErrorResponse = (
  statusCode: number,
  message: string,
  errorMessages?: Record<string, unknown>[],
): ErrorResponse => ({
  statusCode,
  error: getErrorName(statusCode),
  message,
  ...(errorMessages && { errorMessages }),
})

const handleSocketError = (socket: SocketWithUser, error: unknown): void => {
  if (error instanceof ApiError) {
    socket.emit(
      'socket_error',
      createErrorResponse(error.statusCode, error.message),
    )
  } else {
    socket.emit(
      'socket_error',
      createErrorResponse(
        StatusCodes.INTERNAL_SERVER_ERROR,
        'An internal error occurred',
      ),
    )
  }
  const message = error instanceof Error ? error.message : String(error)
  errorLogger.error(colors.red(`Socket error: ${message}`))
}

// ─── Connection Auth Middleware ────────────────────────────────────────────────
/**
 * Used in `io.use(...)` — runs once per connection handshake.
 * Verifies the JWT and attaches `socket.user`.
 */
const socketAuth =
  (...roles: string[]) =>
  (socket: SocketWithUser, next: (err?: ExtendedError) => void) => {
    try {
      const rawToken =
        socket.handshake.auth.token ||
        socket.handshake.query.token ||
        socket.handshake.headers.authorization

      if (!rawToken) {
        throw new ApiError(
          StatusCodes.UNAUTHORIZED,
          'Authentication token is required',
        )
      }

      const jwtToken = extractToken(rawToken as string | string[])
      const verifiedUser = jwtHelper.verifyToken(
        jwtToken,
        config.jwt.jwt_secret as Secret,
      )

      socket.user = {
        authId: verifiedUser.authId,
        name: verifiedUser.name,
        email: verifiedUser.email,
        role: verifiedUser.role,
        ...verifiedUser,
      }

      if (roles.length && !roles.includes(verifiedUser.role)) {
        errorLogger.error(
          colors.red(
            `Socket auth denied: role '${verifiedUser.role}' not in [${roles.join(', ')}]`,
          ),
        )
        return next(
          new ApiError(
            StatusCodes.FORBIDDEN,
            "You don't have permission to connect to this socket",
          ) as ExtendedError,
        )
      }

      logger.info(
        colors.green(`Socket authenticated for user: ${verifiedUser.authId}`),
      )
      next()
    } catch (error) {
      if (error instanceof ApiError) {
        socket.emit('socket_error', createErrorResponse(error.statusCode, error.message))
        return next(error as ExtendedError)
      }
      if (error instanceof Error) {
        if (error.name === 'TokenExpiredError') {
          const apiError = new ApiError(StatusCodes.UNAUTHORIZED, 'Access token has expired')
          socket.emit('socket_error', createErrorResponse(apiError.statusCode, apiError.message))
          return next(apiError as ExtendedError)
        }
        if (error.name === 'JsonWebTokenError') {
          const apiError = new ApiError(StatusCodes.UNAUTHORIZED, 'Invalid access token')
          socket.emit('socket_error', createErrorResponse(apiError.statusCode, apiError.message))
          return next(apiError as ExtendedError)
        }
      }
      next(error as ExtendedError)
    }
  }

// ─── Per-Event Auth (for event handlers that need fresh auth check) ────────────
/**
 * Re-verifies the token from the socket handshake for a specific event handler.
 * Returns the verified user payload or null (after emitting socket_error).
 */
const handleSocketRequest = (
  socket: Socket,
  ...roles: string[]
): ReturnType<typeof jwtHelper.verifyToken> | null => {
  try {
    const rawToken =
      socket.handshake.auth.token ||
      socket.handshake.query.token ||
      socket.handshake.headers.authorization

    const jwtToken = extractToken(rawToken as string | string[])
    const verifiedUser = jwtHelper.verifyToken(
      jwtToken,
      config.jwt.jwt_secret as Secret,
    )

    if (roles.length && !roles.includes(verifiedUser.role)) {
      socket.emit(
        'socket_error',
        createErrorResponse(
          StatusCodes.FORBIDDEN,
          "You don't have permission for this socket event",
        ),
      )
      return null
    }

    return verifiedUser
  } catch (error) {
    handleSocketError(socket as SocketWithUser, error)
    return null
  }
}

// ─── Event Data Validation ────────────────────────────────────────────────────
/**
 * Validates socket event data against a Zod schema.
 * Returns parsed data or null (after emitting socket_error).
 */
const validateEventData = <T>(
  socket: Socket,
  schema: ZodSchema,
  data: unknown,
): T | null => {
  try {
    return schema.parse(data) as T
  } catch (error: any) {
    const zodError = handleZodError(error)
    socket.emit('socket_error', {
      statusCode: zodError.statusCode,
      error: getErrorName(zodError.statusCode),
      message: zodError.message,
      errorMessages: zodError.errorMessages,
    })
    return null
  }
}

export const socketMiddleware = {
  socketAuth,
  validateEventData,
  handleSocketRequest,
}