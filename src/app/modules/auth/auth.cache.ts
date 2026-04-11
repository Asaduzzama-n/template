import { redisClient } from '../../../config/redis'
import { errorLogger } from '../../../shared/logger'

const AUTH_CACHE_KEY_PREFIX = 'auth:v1:user:'
const CACHE_TTL_SECONDS = 3600 // 1 hour

export interface IAuthCacheData {
  status: string
  passwordChangedAt?: string | null // ISO string
}

/**
 * Retrieves user security metadata from Redis.
 */
const getAuthCache = async (userId: string): Promise<IAuthCacheData | null> => {
  try {
    const data = await redisClient.get(`${AUTH_CACHE_KEY_PREFIX}${userId}`)
    return data ? JSON.parse(data) : null
  } catch (err) {
    errorLogger.error('Redis Auth Cache Get Error:', err)
    return null // Graceful fallback
  }
}

/**
 * Stores user security metadata in Redis for 1 hour.
 */
const setAuthCache = async (userId: string, data: IAuthCacheData): Promise<void> => {
  try {
    await redisClient.setex(
      `${AUTH_CACHE_KEY_PREFIX}${userId}`,
      CACHE_TTL_SECONDS,
      JSON.stringify(data),
    )
  } catch (err) {
    errorLogger.error('Redis Auth Cache Set Error:', err)
  }
}

/**
 * Force-invalidates the user cache (used on password change/ban).
 */
const invalidateAuthCache = async (userId: string): Promise<void> => {
  try {
    await redisClient.del(`${AUTH_CACHE_KEY_PREFIX}${userId}`)
  } catch (err) {
    errorLogger.error('Redis Auth Cache Delete Error:', err)
  }
}

export const AuthCache = {
  getAuthCache,
  setAuthCache,
  invalidateAuthCache,
}
