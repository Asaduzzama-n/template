import { Request, Response, NextFunction } from 'express'
import { getRedisClient } from '../../adapters/redisAdapter'
import { logger } from '../../shared/logger'
import { StatusCodes } from 'http-status-codes'
import config from '../../config'
import { JwtPayload } from 'jsonwebtoken'

/**
 * Rate limiter configuration interface
 */
interface IRateLimiterConfig {
    windowMs: number      // Time window in milliseconds
    maxRequests: number   // Max requests per window
    keyPrefix?: string    // Redis key prefix
    skipPaths?: string[]  // Paths to skip rate limiting
    keyGenerator?: (req: Request) => string  // Custom key generator
    handler?: (req: Request, res: Response) => void  // Custom response handler
}

/**
 * Default configuration from environment
 */
const defaultConfig: IRateLimiterConfig = {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
    keyPrefix: 'ratelimit:global',
    skipPaths: ['/health', '/ready', '/metrics'],
}

/**
 * Default key generator - uses IP address
 */
const defaultKeyGenerator = (req: Request): string => {
    const forwarded = req.headers['x-forwarded-for']
    const ip = typeof forwarded === 'string'
        ? forwarded.split(',')[0].trim()
        : req.ip || req.socket.remoteAddress || 'unknown'
    return ip
}

/**
 * Default rate limit exceeded handler
 */
const defaultHandler = (req: Request, res: Response): void => {
    res.status(StatusCodes.TOO_MANY_REQUESTS).json({
        success: false,
        message: 'Too many requests, please try again later.',
        retryAfter: res.getHeader('Retry-After'),
    })
}

/**
 * Sliding window rate limiter using Redis
 * 
 * Uses a sliding window algorithm for smooth limiting:
 * - More accurate than fixed window
 * - Prevents burst traffic at window boundaries
 * 
 * @param options - Rate limiter configuration
 */
export const rateLimiter = (options: Partial<IRateLimiterConfig> = {}) => {
    const config: IRateLimiterConfig = { ...defaultConfig, ...options }
    const { windowMs, maxRequests, keyPrefix, skipPaths, keyGenerator, handler } = config

    const windowSeconds = Math.ceil(windowMs / 1000)
    const generateKey = keyGenerator || defaultKeyGenerator
    const handleLimit = handler || defaultHandler

    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        // Skip rate limiting for specified paths
        if (skipPaths?.some(path => req.path.startsWith(path))) {
            return next()
        }

        try {
            const redis = getRedisClient()
            const identifier = generateKey(req)
            const key = `${keyPrefix}:${identifier}`
            const now = Date.now()

            // Use Redis pipeline for atomic operations
            const pipeline = redis.pipeline()

            // Remove old entries outside the window
            pipeline.zremrangebyscore(key, 0, now - windowMs)

            // Add current request
            pipeline.zadd(key, now, `${now}-${Math.random()}`)

            // Count requests in window
            pipeline.zcard(key)

            // Set TTL on the key
            pipeline.expire(key, windowSeconds)

            const results = await pipeline.exec()

            if (!results) {
                logger.warn('Rate limiter pipeline returned null')
                return next()
            }

            const requestCount = results[2]?.[1] as number || 0

            // Set rate limit headers
            res.setHeader('X-RateLimit-Limit', maxRequests)
            res.setHeader('X-RateLimit-Remaining', Math.max(0, maxRequests - requestCount))
            res.setHeader('X-RateLimit-Reset', Math.ceil((now + windowMs) / 1000))

            if (requestCount > maxRequests) {
                const retryAfter = Math.ceil(windowMs / 1000)
                res.setHeader('Retry-After', retryAfter)

                logger.warn('Rate limit exceeded', {
                    ip: identifier,
                    path: req.path,
                    requestCount,
                    limit: maxRequests,
                })

                return handleLimit(req, res)
            }

            next()
        } catch (error: any) {
            // On Redis error, allow the request (fail open)
            logger.error('Rate limiter error', { error: error.message })
            next()
        }
    }
}

/**
 * Stricter rate limiter for auth endpoints
 */
export const authRateLimiter = rateLimiter({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    maxRequests: 30,           // 30 attempts per 15 min
    keyPrefix: 'ratelimit:auth',
})

/**
 * Rate limiter for API endpoints
 */
export const apiRateLimiter = rateLimiter({
    windowMs: 60 * 1000,       // 1 minute
    maxRequests: 100,          // 100 requests per minute
    keyPrefix: 'ratelimit:api',
})

/**
 * Stricter rate limiter for sensitive operations
 */
export const strictRateLimiter = rateLimiter({
    windowMs: 60 * 60 * 1000,  // 1 hour
    maxRequests: 10,           // 10 attempts per hour
    keyPrefix: 'ratelimit:strict',
})

/**
 * Per-user rate limiter (uses user ID from JWT)
 */
export const userRateLimiter = rateLimiter({
    windowMs: 60 * 1000,
    maxRequests: 200,
    keyPrefix: 'ratelimit:user',
    keyGenerator: (req: Request) => {
        // Use user ID if authenticated, otherwise fall back to IP
        const userId = (req.user as JwtPayload)?.authId
        if (userId) return userId

        const forwarded = req.headers['x-forwarded-for']
        return typeof forwarded === 'string'
            ? forwarded.split(',')[0].trim()
            : req.ip || 'unknown'
    },
})
