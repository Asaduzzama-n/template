import path from 'path'
import fs from 'fs'
import { createLogger, format, transports } from 'winston'
import DailyRotateFile from 'winston-daily-rotate-file'
import config from '../config'

const { combine, timestamp, label, printf, colorize, errors, json } = format

// Ensure log directories exist
const logDir = path.join(process.cwd(), 'logs/winston')
const successDir = path.join(logDir, 'successes')
const errorDir = path.join(logDir, 'errors')

if (!fs.existsSync(successDir)) fs.mkdirSync(successDir, { recursive: true })
if (!fs.existsSync(errorDir)) fs.mkdirSync(errorDir, { recursive: true })

// Custom console format for development
const devFormat = printf(({ level, message, label, timestamp, stack }) => {
  return `${timestamp} [${label}] ${level}: ${stack || message}`
})

// Base configuration
const baseLabel = config.app.platform_name || 'API-SERVICE'
const isProduction = config.app.node_env === 'production'

/**
 * Production-ready Logger
 * Supports:
 * - JSON logging in production for ELK/CloudWatch
 * - Colorized logging in development
 * - Automatic stack trace capture for Error objects
 * - Separate log rotation for info and error levels
 */
const logger = createLogger({
  level: isProduction ? 'info' : 'debug',
  format: combine(
    label({ label: baseLabel }),
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    errors({ stack: true }),
    isProduction ? json() : combine(colorize(), devFormat),
  ),
  transports: [
    // Console transport
    new transports.Console(),

    // Success log rotation
    new DailyRotateFile({
      level: 'info',
      filename: path.join(successDir, 'success-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d',
    }),

    // Error log rotation
    new DailyRotateFile({
      level: 'error',
      filename: path.join(errorDir, 'error-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d',
    }),
  ],
  // Handle uncaught exceptions and unhandled rejections
  exceptionHandlers: [
    new transports.Console(),
    new DailyRotateFile({
      filename: path.join(errorDir, 'exceptions-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d',
    }),
  ],
  rejectionHandlers: [
    new transports.Console(),
    new DailyRotateFile({
      filename: path.join(errorDir, 'rejections-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d',
    }),
  ],
})

// Maintain backward compatibility with existing exports
const errorLogger = logger

export { logger, errorLogger }

