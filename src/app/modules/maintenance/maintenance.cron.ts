import { Queue, Worker } from 'bullmq'
import { redisClient } from '../../../config/redis'
import { MaintenanceService } from './maintenance.service'
import { errorLogger, logger } from '../../../shared/logger'

const MAINTENANCE_QUEUE_NAME = 'system-maintenance'

// ─── Queue Initialization ─────────────────────────────────────────────────────
export const maintenanceQueue = new Queue(MAINTENANCE_QUEUE_NAME, {
  connection: redisClient,
  defaultJobOptions: {
    removeOnComplete: true,
    removeOnFail: { count: 10 },
  },
})

// ─── Worker Definition ────────────────────────────────────────────────────────
const maintenanceWorker = new Worker(
  MAINTENANCE_QUEUE_NAME,
  async job => {
    switch (job.name) {
      case 'PURGE_OLD_USERS':
        logger.info('🕒 Job Started: PURGE_OLD_USERS')
        const purgedCount = await MaintenanceService.purgeOldDeletedUsers(30)
        logger.info(`🕒 Job Finished: PURGE_OLD_USERS. Removed ${purgedCount} records.`)
        break

      case 'REFRESH_AUTH_CACHE':
        logger.info('🕒 Job Started: REFRESH_AUTH_CACHE')
        const clearedCount = await MaintenanceService.clearAuthCache()
        logger.info(`🕒 Job Finished: REFRESH_AUTH_CACHE. Cleared ${clearedCount} entries.`)
        break

      default:
        logger.warn(`🕒 Unknown maintenance job type: ${job.name}`)
    }
  },
  {
    connection: redisClient,
    concurrency: 1, // Ensure sequential maintenance
  },
)

maintenanceWorker.on('failed', (job, err) => {
  errorLogger.error(`🕒 Maintenance job ${job?.id} (${job?.name}) failed:`, err.message)
})

// ─── Scheduler Logic ──────────────────────────────────────────────────────────
/**
 * Sets up repeatable jobs (Cron replacement).
 * Using BullMQ repeatable jobs ensures tasks run only once in a cluster.
 */
const initializeSchedule = async () => {
  try {
    // 1. Clear existing repeatable jobs to avoid duplicates on restart
    // Note: In some versions we use getRepeatableJobs() and removeRepeatableByKey()
    // For simplicity here, we use the upsert behavior of add() with jobId.
    
    // 2. Schedule Daily User Purge at Midnight (0 0 * * *)
    await maintenanceQueue.add(
      'PURGE_OLD_USERS',
      {},
      {
        repeat: { pattern: '0 0 * * *' },
        jobId: 'daily-user-purge', // Stable ID prevents duplicates
      },
    )

    // 3. Schedule Weekly Cache Refresh at 2am Sunday (0 2 * * 0)
    await maintenanceQueue.add(
      'REFRESH_AUTH_CACHE',
      {},
      {
        repeat: { pattern: '0 2 * * 0' },
        jobId: 'weekly-cache-refresh',
      },
    )

    logger.info('🕒 System maintenance schedule initialized (Daily Purge & Weekly Refresh)')
  } catch (err) {
    errorLogger.error('🕒 Failed to initialize maintenance schedule:', err)
  }
}

export const MaintenanceCron = {
  initializeSchedule,
}
