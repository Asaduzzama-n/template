import { getRedisClient } from '../adapters/redisAdapter'
import { logger, errorLogger } from '../shared/logger'

/**
 * Redis key prefixes for socket mappings
 */
const SOCKET_KEYS = {
    USER_SOCKETS: 'socket:user:', // Maps userId -> Set of socketIds
    SOCKET_USER: 'socket:id:',   // Maps socketId -> userId
}

/**
 * TTL for socket mappings (auto-cleanup for stale connections)
 */
const SOCKET_TTL = 24 * 60 * 60 // 24 hours

/**
 * Store user's socket connection in Redis
 * Supports multiple sockets per user (multiple tabs/devices)
 * 
 * @param userId - User ID
 * @param socketId - Socket connection ID
 */
export const setUserSocket = async (userId: string, socketId: string): Promise<void> => {
    try {
        const redis = getRedisClient()
        const userKey = `${SOCKET_KEYS.USER_SOCKETS}${userId}`
        const socketKey = `${SOCKET_KEYS.SOCKET_USER}${socketId}`

        // Add socket to user's set
        await redis.sadd(userKey, socketId)
        await redis.expire(userKey, SOCKET_TTL)

        // Map socket to user for reverse lookup
        await redis.setex(socketKey, SOCKET_TTL, userId)

        logger.debug('Socket connection stored', { userId, socketId })
    } catch (error: any) {
        errorLogger.error('Failed to store socket connection', {
            userId,
            socketId,
            error: error.message,
        })
    }
}

/**
 * Remove user's socket connection from Redis
 * 
 * @param userId - User ID
 * @param socketId - Socket connection ID
 */
export const removeUserSocket = async (userId: string, socketId: string): Promise<void> => {
    try {
        const redis = getRedisClient()
        const userKey = `${SOCKET_KEYS.USER_SOCKETS}${userId}`
        const socketKey = `${SOCKET_KEYS.SOCKET_USER}${socketId}`

        // Remove socket from user's set
        await redis.srem(userKey, socketId)

        // Remove socket-to-user mapping
        await redis.del(socketKey)

        // Clean up empty sets
        const remaining = await redis.scard(userKey)
        if (remaining === 0) {
            await redis.del(userKey)
        }

        logger.debug('Socket connection removed', { userId, socketId })
    } catch (error: any) {
        errorLogger.error('Failed to remove socket connection', {
            userId,
            socketId,
            error: error.message,
        })
    }
}

/**
 * Get all socket IDs for a user
 * Returns array of socket IDs for emitting to all user's connections
 * 
 * @param userId - User ID
 * @returns Array of socket IDs
 */
export const getUserSockets = async (userId: string): Promise<string[]> => {
    try {
        const redis = getRedisClient()
        const userKey = `${SOCKET_KEYS.USER_SOCKETS}${userId}`

        const sockets = await redis.smembers(userKey)
        return sockets
    } catch (error: any) {
        errorLogger.error('Failed to get user sockets', {
            userId,
            error: error.message,
        })
        return []
    }
}

/**
 * Get user ID from socket ID
 * 
 * @param socketId - Socket connection ID
 * @returns User ID or null
 */
export const getUserFromSocket = async (socketId: string): Promise<string | null> => {
    try {
        const redis = getRedisClient()
        const socketKey = `${SOCKET_KEYS.SOCKET_USER}${socketId}`

        return await redis.get(socketKey)
    } catch (error: any) {
        errorLogger.error('Failed to get user from socket', {
            socketId,
            error: error.message,
        })
        return null
    }
}

/**
 * Check if user is online (has any active sockets)
 * 
 * @param userId - User ID
 * @returns Boolean indicating online status
 */
export const isUserOnline = async (userId: string): Promise<boolean> => {
    try {
        const redis = getRedisClient()
        const userKey = `${SOCKET_KEYS.USER_SOCKETS}${userId}`

        const count = await redis.scard(userKey)
        return count > 0
    } catch (error: any) {
        errorLogger.error('Failed to check user online status', {
            userId,
            error: error.message,
        })
        return false
    }
}

/**
 * Get all online users
 * Note: Use with caution for large user bases
 * 
 * @returns Array of online user IDs
 */
export const getOnlineUsers = async (): Promise<string[]> => {
    try {
        const redis = getRedisClient()

        // Scan for all user socket keys
        const keys: string[] = []
        let cursor = '0'

        do {
            const result = await redis.scan(
                cursor,
                'MATCH',
                `${SOCKET_KEYS.USER_SOCKETS}*`,
                'COUNT',
                100
            )
            cursor = result[0]
            keys.push(...result[1])
        } while (cursor !== '0')

        // Extract user IDs from keys
        const userIds = keys.map(key => key.replace(SOCKET_KEYS.USER_SOCKETS, ''))
        return userIds
    } catch (error: any) {
        errorLogger.error('Failed to get online users', {
            error: error.message,
        })
        return []
    }
}

/**
 * Clean up all sockets for a user (e.g., on logout)
 * 
 * @param userId - User ID
 */
export const clearUserSockets = async (userId: string): Promise<void> => {
    try {
        const redis = getRedisClient()
        const userKey = `${SOCKET_KEYS.USER_SOCKETS}${userId}`

        // Get all socket IDs
        const socketIds = await redis.smembers(userKey)

        // Delete socket-to-user mappings
        if (socketIds.length > 0) {
            const socketKeys = socketIds.map(id => `${SOCKET_KEYS.SOCKET_USER}${id}`)
            await redis.del(...socketKeys)
        }

        // Delete user's socket set
        await redis.del(userKey)

        logger.debug('Cleared all sockets for user', { userId, count: socketIds.length })
    } catch (error: any) {
        errorLogger.error('Failed to clear user sockets', {
            userId,
            error: error.message,
        })
    }
}

export const socketRedis = {
    setUserSocket,
    removeUserSocket,
    getUserSockets,
    getUserFromSocket,
    isUserOnline,
    getOnlineUsers,
    clearUserSockets,
}
