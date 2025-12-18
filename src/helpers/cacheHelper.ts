import { getRedisClient } from '../adapters/redisAdapter'
import { logger } from '../shared/logger'
import config from '../config'

/**
 * Cache key prefixes
 */
export const CACHE_PREFIXES = {
    QUERY: 'cache:query:',
    STATS: 'cache:stats',
} as const

/**
 * Default TTL values (in seconds)
 */
export const CACHE_TTL = {
    SHORT: 60,           // 1 minute
    MEDIUM: 5 * 60,      // 5 minutes
    LONG: 30 * 60,       // 30 minutes
    VERY_LONG: 60 * 60,  // 1 hour
} as const

/**
 * Cache statistics stored in Redis
 */
interface ICacheStats {
    hits: number
    misses: number
    lastReset: string
}

/**
 * Pagination parameters for cache key generation
 */
interface IPaginationParams {
    page?: number
    limit?: number
    sortBy?: string
    sortOrder?: string
}

/**
 * Build a cache key for paginated queries
 * 
 * @param prefix - Entity type prefix (e.g., 'users', 'reviews')
 * @param identifier - Unique identifier (e.g., userId)
 * @param pagination - Pagination parameters
 * @param filters - Additional filter parameters
 */
export const buildCacheKey = (
    prefix: string,
    identifier?: string,
    pagination?: IPaginationParams,
    filters?: Record<string, any>
): string => {
    const parts = [CACHE_PREFIXES.QUERY, prefix]

    if (identifier) {
        parts.push(identifier)
    }

    if (pagination) {
        const { page = 1, limit = 10, sortBy = 'createdAt', sortOrder = 'desc' } = pagination
        parts.push(`p${page}`, `l${limit}`, `s${sortBy}`, `o${sortOrder}`)
    }

    if (filters && Object.keys(filters).length > 0) {
        // Sort keys for consistent cache keys
        const sortedFilters = Object.keys(filters)
            .sort()
            .map(key => `${key}:${filters[key]}`)
            .join('_')
        parts.push(sortedFilters)
    }

    return parts.join(':')
}

/**
 * Get cached data with automatic deserialization
 * 
 * @param key - Cache key
 * @returns Cached data or null if not found
 */
export const getCache = async <T>(key: string): Promise<T | null> => {
    try {
        const redis = getRedisClient()
        const data = await redis.get(key)

        if (data) {
            await incrementStats('hits')
            logger.debug('Cache hit', { key })
            return JSON.parse(data) as T
        }

        await incrementStats('misses')
        logger.debug('Cache miss', { key })
        return null
    } catch (error: any) {
        logger.error('Cache get error', { key, error: error.message })
        return null
    }
}

/**
 * Set cache data with automatic serialization
 * 
 * @param key - Cache key
 * @param data - Data to cache
 * @param ttlSeconds - Time to live in seconds
 */
export const setCache = async <T>(
    key: string,
    data: T,
    ttlSeconds: number = CACHE_TTL.MEDIUM
): Promise<void> => {
    try {
        const redis = getRedisClient()
        await redis.setex(key, ttlSeconds, JSON.stringify(data))
        logger.debug('Cache set', { key, ttl: ttlSeconds })
    } catch (error: any) {
        logger.error('Cache set error', { key, error: error.message })
    }
}

/**
 * Delete cache by key
 * 
 * @param key - Cache key
 */
export const deleteCache = async (key: string): Promise<void> => {
    try {
        const redis = getRedisClient()
        await redis.del(key)
        logger.debug('Cache deleted', { key })
    } catch (error: any) {
        logger.error('Cache delete error', { key, error: error.message })
    }
}

/**
 * Delete all cache keys matching a pattern
 * Useful for invalidating all pages of a paginated query
 * 
 * @param pattern - Pattern to match (e.g., 'cache:query:reviews:123*')
 */
export const invalidateCachePattern = async (pattern: string): Promise<number> => {
    try {
        const redis = getRedisClient()
        let cursor = '0'
        let deletedCount = 0
        const keysToDelete: string[] = []

        // Scan for matching keys
        do {
            const result = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 100)
            cursor = result[0]
            keysToDelete.push(...result[1])
        } while (cursor !== '0')

        // Delete in batches
        if (keysToDelete.length > 0) {
            deletedCount = await redis.del(...keysToDelete)
            logger.debug('Cache pattern invalidated', { pattern, count: deletedCount })
        }

        return deletedCount
    } catch (error: any) {
        logger.error('Cache pattern invalidation error', { pattern, error: error.message })
        return 0
    }
}

/**
 * Increment cache statistics
 */
const incrementStats = async (field: 'hits' | 'misses'): Promise<void> => {
    try {
        const redis = getRedisClient()
        await redis.hincrby(CACHE_PREFIXES.STATS, field, 1)
    } catch (error: any) {
        // Silent fail for stats - don't break caching for stats errors
    }
}

/**
 * Get cache statistics
 */
export const getCacheStats = async (): Promise<ICacheStats> => {
    try {
        const redis = getRedisClient()
        const stats = await redis.hgetall(CACHE_PREFIXES.STATS)

        return {
            hits: parseInt(stats.hits || '0', 10),
            misses: parseInt(stats.misses || '0', 10),
            lastReset: stats.lastReset || new Date().toISOString(),
        }
    } catch (error: any) {
        logger.error('Cache stats error', { error: error.message })
        return { hits: 0, misses: 0, lastReset: new Date().toISOString() }
    }
}

/**
 * Reset cache statistics
 */
export const resetCacheStats = async (): Promise<void> => {
    try {
        const redis = getRedisClient()
        await redis.hset(CACHE_PREFIXES.STATS, {
            hits: '0',
            misses: '0',
            lastReset: new Date().toISOString(),
        })
        logger.info('Cache stats reset')
    } catch (error: any) {
        logger.error('Cache stats reset error', { error: error.message })
    }
}

/**
 * Get all cache keys (for monitoring)
 */
export const getAllCacheKeys = async (): Promise<string[]> => {
    try {
        const redis = getRedisClient()
        let cursor = '0'
        const keys: string[] = []

        do {
            const result = await redis.scan(cursor, 'MATCH', `${CACHE_PREFIXES.QUERY}*`, 'COUNT', 100)
            cursor = result[0]
            keys.push(...result[1])
        } while (cursor !== '0')

        return keys
    } catch (error: any) {
        logger.error('Get all cache keys error', { error: error.message })
        return []
    }
}

/**
 * Clear all query cache
 */
export const clearAllCache = async (): Promise<number> => {
    return invalidateCachePattern(`${CACHE_PREFIXES.QUERY}*`)
}

/**
 * Cache wrapper for async functions with pagination support
 * 
 * @param cacheKey - Cache key
 * @param ttlSeconds - Time to live
 * @param fetchFn - Function to fetch data if not cached
 */
export const withCache = async <T>(
    cacheKey: string,
    ttlSeconds: number,
    fetchFn: () => Promise<T>
): Promise<T> => {
    // Try to get from cache
    const cached = await getCache<T>(cacheKey)
    if (cached !== null) {
        return cached
    }

    // Fetch fresh data
    const data = await fetchFn()

    // Store in cache
    await setCache(cacheKey, data, ttlSeconds)

    return data
}

export const cacheHelper = {
    buildCacheKey,
    getCache,
    setCache,
    deleteCache,
    invalidateCachePattern,
    getCacheStats,
    resetCacheStats,
    getAllCacheKeys,
    clearAllCache,
    withCache,
    CACHE_TTL,
    CACHE_PREFIXES,
}
