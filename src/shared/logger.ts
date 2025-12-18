import path from 'path'
import { createLogger, format, transports, Logger } from 'winston'
import DailyRotateFile from 'winston-daily-rotate-file'
import fs from 'fs'
import config from '../config'

// Ensure log directories exist
const createLogDirs = () => {
  const dirs = ['logs/winston/combined', 'logs/winston/errors']
  dirs.forEach(dir => {
    const fullPath = path.join(process.cwd(), dir)
    if (!fs.existsSync(fullPath)) {
      fs.mkdirSync(fullPath, { recursive: true })
    }
  })
}

createLogDirs()

/**
 * Environment-based log level
 * - development: debug (verbose)
 * - production: info (standard)
 * - test: error (minimal)
 */
const getLogLevel = (): string => {
  const envLevel = process.env.LOG_LEVEL
  if (envLevel) return envLevel.toLowerCase()

  switch (config.node_env) {
    case 'development':
      return 'debug'
    case 'test':
      return 'error'
    default:
      return 'info'
  }
}

/**
 * Redact sensitive fields from log data
 */
const redactSensitiveData = format((info) => {
  const sensitiveFields = ['password', 'token', 'accessToken', 'refreshToken', 'authorization', 'cookie', 'secret']

  const redact = (obj: any): any => {
    if (!obj || typeof obj !== 'object') return obj

    const result = Array.isArray(obj) ? [...obj] : { ...obj }

    for (const key of Object.keys(result)) {
      if (sensitiveFields.some(field => key.toLowerCase().includes(field))) {
        result[key] = '[REDACTED]'
      } else if (typeof result[key] === 'object') {
        result[key] = redact(result[key])
      }
    }

    return result
  }

  return redact(info)
})

/**
 * Error stack formatter - ensures stack traces are properly captured
 */
const errorStackFormat = format((info) => {
  if (info instanceof Error) {
    return {
      ...info,
      message: info.message,
      stack: info.stack,
      name: info.name,
    }
  }

  if (info.error instanceof Error) {
    info.error = {
      message: info.error.message,
      stack: info.error.stack,
      name: info.error.name,
    }
  }

  return info
})

/**
 * JSON format for production - parseable by log aggregators (ELK, CloudWatch, etc.)
 */
const jsonFormat = format.combine(
  format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
  errorStackFormat(),
  redactSensitiveData(),
  format.errors({ stack: true }),
  format.json()
)

/**
 * Pretty format for development - human readable with colors
 */
const prettyFormat = format.combine(
  format.timestamp({ format: 'HH:mm:ss' }),
  errorStackFormat(),
  redactSensitiveData(),
  format.colorize({ all: true }),
  format.printf(({ timestamp, level, message, correlationId, ...meta }) => {
    const metaStr = Object.keys(meta).length ? `\n${JSON.stringify(meta, null, 2)}` : ''
    const corrId = correlationId ? `[${correlationId}] ` : ''
    return `${timestamp} ${level}: ${corrId}${message}${metaStr}`
  })
)

/**
 * Get appropriate format based on environment
 */
const getFormat = () => {
  return config.node_env === 'production' ? jsonFormat : prettyFormat
}

/**
 * File transport for combined logs (all levels)
 */
const combinedFileTransport = new DailyRotateFile({
  filename: path.join(process.cwd(), 'logs', 'winston', 'combined', 'app-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  zippedArchive: true,
  maxSize: '20m',
  maxFiles: '14d',
  format: jsonFormat, // Always JSON in files for parsing
})

/**
 * File transport for error logs only
 */
const errorFileTransport = new DailyRotateFile({
  filename: path.join(process.cwd(), 'logs', 'winston', 'errors', 'error-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  zippedArchive: true,
  maxSize: '20m',
  maxFiles: '30d',
  level: 'error',
  format: jsonFormat,
})

/**
 * Console transport with environment-appropriate formatting
 */
const consoleTransport = new transports.Console({
  format: getFormat(),
})

/**
 * Main application logger
 * 
 * Usage:
 * - logger.info('Message')
 * - logger.info('Message', { userId: '123', action: 'login' })
 * - logger.error('Error occurred', { error: err })
 * - logger.debug('Debug info', { data: someObject })
 */
const logger: Logger = createLogger({
  level: getLogLevel(),
  defaultMeta: {
    service: 'express-craft',
    environment: config.node_env,
  },
  transports: [
    consoleTransport,
    combinedFileTransport,
    errorFileTransport,
  ],
  exitOnError: false,
})

/**
 * Error logger - convenience export for backward compatibility
 * In the new system, use logger.error() instead
 */
const errorLogger = {
  error: (message: string, meta?: object) => {
    logger.error(message, meta)
  },
}

/**
 * Create a child logger with additional context
 * Useful for request-scoped logging with correlation IDs
 * 
 * @param meta - Additional metadata to include in all logs
 */
const createChildLogger = (meta: object): Logger => {
  return logger.child(meta)
}

/**
 * Log with correlation ID for request tracing
 * 
 * @param correlationId - Unique ID for the request
 */
const withCorrelationId = (correlationId: string): Logger => {
  return logger.child({ correlationId })
}

export {
  logger,
  errorLogger,
  createChildLogger,
  withCorrelationId,
}
