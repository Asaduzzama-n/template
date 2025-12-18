import { Request, Response, NextFunction } from 'express'
import { v4 as uuidv4 } from 'uuid'
import { logger, withCorrelationId } from '../../shared/logger'

// Extend Express Request to include correlation ID and logger
declare global {
    namespace Express {
        interface Request {
            correlationId?: string
            log?: ReturnType<typeof withCorrelationId>
        }
    }
}

/**
 * Request Logger Middleware
 * 
 * Adds correlation ID to each request for distributed tracing.
 * Logs request start and completion with duration.
 * Attaches a child logger to the request for consistent logging.
 */
export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
    // Generate or use existing correlation ID
    const correlationId = (req.headers['x-correlation-id'] as string) ||
        (req.headers['x-request-id'] as string) ||
        uuidv4()

    // Attach to request
    req.correlationId = correlationId
    req.log = withCorrelationId(correlationId)

    // Add correlation ID to response headers
    res.setHeader('X-Correlation-ID', correlationId)

    // Start timer
    const startTime = process.hrtime.bigint()

    // Log request start
    req.log.info('Request started', {
        method: req.method,
        url: req.originalUrl,
        ip: req.ip || req.socket.remoteAddress,
        userAgent: req.get('user-agent'),
    })

    // Log on response finish
    res.on('finish', () => {
        const endTime = process.hrtime.bigint()
        const durationMs = Number(endTime - startTime) / 1_000_000

        const logData = {
            method: req.method,
            url: req.originalUrl,
            statusCode: res.statusCode,
            durationMs: Math.round(durationMs * 100) / 100,
            contentLength: res.get('content-length'),
        }

        // Log based on status code
        if (res.statusCode >= 500) {
            req.log!.error('Request failed', logData)
        } else if (res.statusCode >= 400) {
            req.log!.warn('Request client error', logData)
        } else {
            req.log!.info('Request completed', logData)
        }
    })

    next()
}

/**
 * Error logging middleware - should be placed after routes
 * Logs unhandled errors with full stack traces
 */
export const errorRequestLogger = (err: Error, req: Request, res: Response, next: NextFunction) => {
    const log = req.log || logger

    log.error('Unhandled error', {
        error: {
            message: err.message,
            name: err.name,
            stack: err.stack,
        },
        method: req.method,
        url: req.originalUrl,
        body: req.body,
        params: req.params,
        query: req.query,
    })

    next(err)
}
