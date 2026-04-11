import { StatusCodes } from 'http-status-codes'
import { User } from '../user/user.model'
import { Verification } from '../verification/verification.model'
import { USER_STATUS } from '../../../enum/user'
import { redisClient } from '../../../config/redis'
import { logger } from '../../../shared/logger'

/**
 * Permanently removes users who have been soft-deleted for longer than the threshold.
 */
const purgeOldDeletedUsers = async (daysThreshold: number = 30) => {
  const cutoffDate = new Date(Date.now() - daysThreshold * 24 * 60 * 60 * 1000)

  const result = await User.deleteMany({
    status: USER_STATUS.DELETED,
    updatedAt: { $lt: cutoffDate },
  })

  logger.info(`♻️  Maintenance: Purged ${result.deletedCount} old deleted user records.`)
  return result.deletedCount
}

/**
 * Iteratively deletes all Redis keys matching the auth cache pattern.
 * Uses SCAN instead of KEYS to avoid blocking the Redis event loop.
 */
const clearAuthCache = async () => {
  const pattern = 'auth:v1:user:*'
  let cursor = '0'
  let deletedTotal = 0

  do {
    const [nextCursor, keys] = await redisClient.scan(cursor, 'MATCH', pattern, 'COUNT', 100)
    cursor = nextCursor

    if (keys.length > 0) {
      await redisClient.del(...keys)
      deletedTotal += keys.length
    }
  } while (cursor !== '0')

  logger.info(`♻️  Maintenance: Cleared ${deletedTotal} auth cache entries from Redis.`)
  return deletedTotal
}

/**
 * Retrieves a summary of system storage and entity counts.
 */
const getStorageStats = async () => {
  const [totalUsers, deletedUsers, pendingVerifications, redisInfo] = await Promise.all([
    User.countDocuments(),
    User.countDocuments({ status: USER_STATUS.DELETED }),
    Verification.countDocuments(),
    redisClient.info('memory'),
  ])

  // Parse used memory from Redis info string
  const usedMemoryMatch = redisInfo.match(/used_memory_human:([\d\w.]+)/)
  const usedMemory = usedMemoryMatch ? usedMemoryMatch[1] : 'unknown'

  return {
    users: {
      total: totalUsers,
      active: totalUsers - deletedUsers,
      softDeleted: deletedUsers,
    },
    verification: {
      pendingOtpSessions: pendingVerifications,
    },
    redis: {
      usedMemoryHuman: usedMemory,
    },
  }
}

export const MaintenanceService = {
  purgeOldDeletedUsers,
  clearAuthCache,
  getStorageStats,
}
