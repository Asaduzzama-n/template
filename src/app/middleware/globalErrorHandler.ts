/* eslint-disable @typescript-eslint/no-unused-vars */
import { ErrorRequestHandler, NextFunction, Request, Response } from 'express'
import config from '../../config'
import { IGenericErrorMessage } from '../../interfaces/error'
import handleZodError from '../../errors/handleZodError'
import handleValidationError from '../../errors/handleValidationError'
import { ZodError } from 'zod'
import handleCastError from '../../errors/handleCastError'
import ApiError from '../../errors/ApiError'
import { errorLogger } from '../../shared/logger'

const globalErrorHandler: ErrorRequestHandler = (
  error,
  req: Request,
  res: Response,
  _next: NextFunction,
) => {
  // Always log the error server-side
  if (config.node_env === 'development') {
    errorLogger.error('Global Error Handler:', error)
  }

  let statusCode = 500
  let message = 'Something went wrong!'
  let errorMessages: IGenericErrorMessage[] = []

  // ── Mongoose Validation Error ──────────────────────────────────────────────
  //    Note: Mongoose throws 'ValidationError' (capital V)
  if (error?.name === 'ValidationError') {
    const simplifiedError = handleValidationError(error)
    statusCode = simplifiedError.statusCode
    message = simplifiedError.errorMessages[0]?.message ?? message
    errorMessages = simplifiedError.errorMessages

  // ── Zod Validation Error ────────────────────────────────────────────────────
  } else if (error instanceof ZodError) {
    const simplifiedError = handleZodError(error)
    statusCode = simplifiedError.statusCode
    message = simplifiedError.errorMessages[0]?.message ?? message
    errorMessages = simplifiedError.errorMessages

  // ── Mongoose Cast Error (invalid ObjectId etc.) ─────────────────────────────
  } else if (error?.name === 'CastError') {
    const simplifiedError = handleCastError(error)
    statusCode = simplifiedError.statusCode
    message = simplifiedError.message
    errorMessages = simplifiedError.errorMessages

  // ── MongoDB Duplicate Key Error ─────────────────────────────────────────────
  } else if (error?.code === 11000) {
    statusCode = 409
    const field = Object.keys(error.keyPattern || error.keyValue || {})[0] ?? 'field'
    message = `A record with this ${field} already exists.`
    errorMessages = [{ path: field, message }]

  // ── Application-level API Error ─────────────────────────────────────────────
  } else if (error instanceof ApiError) {
    statusCode = error.statusCode
    message = error.message
    errorMessages = error.message ? [{ path: '', message: error.message }] : []

  // ── Generic JavaScript Error ────────────────────────────────────────────────
  } else if (error instanceof Error) {
    message = error.message
    errorMessages = error.message ? [{ path: '', message: error.message }] : []
  }

  res.status(statusCode).json({
    success: false,
    message,
    errorMessages,
    // Stack trace only in non-production (already logged server-side above)
    stack: config.node_env === 'production' ? undefined : error?.stack,
  })
}

export default globalErrorHandler
