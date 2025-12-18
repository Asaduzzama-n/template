import { Request, Response } from 'express'
import { StatusCodes } from 'http-status-codes'
import catchAsync from '../../../shared/catchAsync'
import sendResponse from '../../../shared/sendResponse'
import {
    getCacheStats,
    resetCacheStats,
    getAllCacheKeys,
    clearAllCache
} from '../../../helpers/cacheHelper'
import { redisAdapter } from '../../../adapters/redisAdapter'

/**
 * Get cache statistics
 */
const getStats = catchAsync(async (req: Request, res: Response) => {
    const stats = await getCacheStats()
    const totalRequests = stats.hits + stats.misses
    const hitRate = totalRequests > 0
        ? ((stats.hits / totalRequests) * 100).toFixed(2)
        : '0.00'

    sendResponse(res, {
        statusCode: StatusCodes.OK,
        success: true,
        message: 'Cache statistics retrieved successfully',
        data: {
            totalHits: stats.hits,
            totalMisses: stats.misses,
            totalRequests,
            hitRate: `${hitRate}%`,
            lastReset: stats.lastReset,
        },
    })
})

/**
 * Reset cache statistics
 */
const resetStats = catchAsync(async (req: Request, res: Response) => {
    await resetCacheStats()

    sendResponse(res, {
        statusCode: StatusCodes.OK,
        success: true,
        message: 'Cache statistics reset successfully',
        data: null,
    })
})

/**
 * Get all cached keys (for debugging)
 */
const getCachedKeys = catchAsync(async (req: Request, res: Response) => {
    const keys = await getAllCacheKeys()

    sendResponse(res, {
        statusCode: StatusCodes.OK,
        success: true,
        message: 'Cached keys retrieved successfully',
        data: {
            count: keys.length,
            keys,
        },
    })
})

/**
 * Clear all cache
 */
const clearCache = catchAsync(async (req: Request, res: Response) => {
    const deletedCount = await clearAllCache()

    sendResponse(res, {
        statusCode: StatusCodes.OK,
        success: true,
        message: `Cleared ${deletedCount} cached entries`,
        data: {
            deletedCount,
        },
    })
})

/**
 * Redis health check
 */
const redisHealth = catchAsync(async (req: Request, res: Response) => {
    const isHealthy = await redisAdapter.healthCheck()

    sendResponse(res, {
        statusCode: isHealthy ? StatusCodes.OK : StatusCodes.SERVICE_UNAVAILABLE,
        success: isHealthy,
        message: isHealthy ? 'Redis is healthy' : 'Redis is unavailable',
        data: {
            connected: redisAdapter.isConnected,
            healthy: isHealthy,
        },
    })
})

export const CacheController = {
    getStats,
    resetStats,
    getCachedKeys,
    clearCache,
    redisHealth,
}
