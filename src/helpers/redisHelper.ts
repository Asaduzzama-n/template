import { getRedisClient } from '../adapters/redisAdapter'
import { logger, errorLogger } from '../shared/logger'
import ApiError from '../errors/ApiError'
import { StatusCodes } from 'http-status-codes'

/**
 * Rate limit key builder.
 * @param prefix - The type of rate limit (e.g., 'otp', 'password-reset')
 * @param identifier - Unique identifier (e.g., email or user ID)
 */
const buildRateLimitKey = (prefix: string, identifier: string): string => {
    return `auth:ratelimit:${prefix}:${identifier.toLowerCase()}`
}

/**
 * Cooldown key builder.
 * @param prefix - The type of cooldown
 * @param identifier - Unique identifier
 */
const buildCooldownKey = (prefix: string, identifier: string): string => {
    return `auth:cooldown:${prefix}:${identifier.toLowerCase()}`
}

/**
 * Increment rate limit counter and check against max attempts.
 * Uses Redis INCR which is atomic.
 *
 * @param prefix - Rate limit type prefix
 * @param identifier - User identifier (email, phone, userId)
 * @param ttlSeconds - TTL for the rate limit window
 * @param maxAttempts - Maximum allowed attempts within the window
 * @throws ApiError if rate limit exceeded
 * @returns Current attempt count
 */
const incrementRateLimit = async (
    prefix: string,
    identifier: string,
    ttlSeconds: number,
    maxAttempts: number,
): Promise<number> => {
    const redis = getRedisClient()
    const key = buildRateLimitKey(prefix, identifier)

    // Atomically increment and get the new value
    const currentCount = await redis.incr(key)

    // Set TTL only on the first increment (when count becomes 1)
    if (currentCount === 1) {
        await redis.expire(key, ttlSeconds)
    }

    if (currentCount > maxAttempts) {
        // Get remaining TTL for user-friendly message
        const ttl = await redis.ttl(key)
        throw new ApiError(
            StatusCodes.TOO_MANY_REQUESTS,
            `Too many requests. Please try again in ${Math.ceil(ttl / 60)} minute(s).`,
        )
    }

    return currentCount
}

/**
 * Check if a cooldown is active for the given identifier.
 *
 * @param prefix - Cooldown type prefix
 * @param identifier - User identifier
 * @param cooldownSeconds - Cooldown duration to check
 * @throws ApiError if cooldown is active
 */
const checkCooldown = async (
    prefix: string,
    identifier: string,
    cooldownSeconds: number,
): Promise<void> => {
    const redis = getRedisClient()
    const key = buildCooldownKey(prefix, identifier)
    const exists = await redis.exists(key)

    if (exists) {
        const ttl = await redis.ttl(key)
        throw new ApiError(
            StatusCodes.TOO_MANY_REQUESTS,
            `Please wait ${ttl} second(s) before requesting again.`,
        )
    }
}

/**
 * Set a cooldown marker for the given identifier.
 *
 * @param prefix - Cooldown type prefix
 * @param identifier - User identifier
 * @param cooldownSeconds - Duration of the cooldown
 */
const setCooldown = async (
    prefix: string,
    identifier: string,
    cooldownSeconds: number,
): Promise<void> => {
    const redis = getRedisClient()
    const key = buildCooldownKey(prefix, identifier)
    await redis.setex(key, cooldownSeconds, '1')
}

/**
 * Reset (delete) the rate limit counter for a given identifier.
 * Call this after successful verification to allow fresh attempts.
 *
 * @param prefix - Rate limit type prefix
 * @param identifier - User identifier
 */
const resetRateLimit = async (prefix: string, identifier: string): Promise<void> => {
    const redis = getRedisClient()
    const key = buildRateLimitKey(prefix, identifier)
    await redis.del(key)
}

/**
 * Reset (delete) the cooldown marker for a given identifier.
 *
 * @param prefix - Cooldown type prefix
 * @param identifier - User identifier
 */
const resetCooldown = async (prefix: string, identifier: string): Promise<void> => {
    const redis = getRedisClient()
    const key = buildCooldownKey(prefix, identifier)
    await redis.del(key)
}

/**
 * Get current rate limit count (for debugging/logging).
 *
 * @param prefix - Rate limit type prefix
 * @param identifier - User identifier
 * @returns Current count or 0 if not set
 */
const getRateLimitCount = async (prefix: string, identifier: string): Promise<number> => {
    const redis = getRedisClient()
    const key = buildRateLimitKey(prefix, identifier)
    const count = await redis.get(key)
    return count ? parseInt(count, 10) : 0
}

export const redisHelper = {
    buildRateLimitKey,
    buildCooldownKey,
    incrementRateLimit,
    checkCooldown,
    setCooldown,
    resetRateLimit,
    resetCooldown,
    getRateLimitCount,
}
