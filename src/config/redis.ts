import { Redis } from 'ioredis'
import config from './index'
import { errorLogger, logger } from '../shared/logger'

// ─── Redis Singleton ─────────────────────────────────────────────────────────
// A single Redis client for the application. A duplicate is used by the
// Socket.IO Redis adapter (pub/sub requires separate connections).
// BullMQ workers also use this client.

const createRedisClient = (): Redis => {
  const client = new Redis({
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password || undefined,
    // Required for BullMQ — disables the default max-retries-per-request limit
    maxRetriesPerRequest: null,
    // Reconnect with exponential back-off (max 10 s)
    retryStrategy: (times: number) => Math.min(times * 200, 10_000),
    lazyConnect: true,
    enableOfflineQueue: true,
  })

  client.on('connect', () => logger.info('🟢 Redis connected'))
  client.on('ready', () => logger.info('✅ Redis ready'))
  client.on('error', (err: Error) =>
    errorLogger.error('Redis error:', err.message),
  )
  client.on('close', () => logger.info('🔴 Redis connection closed'))
  client.on('reconnecting', () => logger.info('🔁 Redis reconnecting…'))

  return client
}

export const redisClient = createRedisClient()

/**
 * Call this once during server startup to establish the connection.
 * Throws if Redis cannot be reached (fast-fail in production).
 */
export const connectRedis = async (): Promise<void> => {
  await redisClient.connect()
}

/**
 * Returns a duplicate Redis client for use as a subscriber.
 * Required by the Socket.IO Redis adapter (needs separate pub/sub connections).
 */
export const createRedisDuplicate = (): Redis => redisClient.duplicate()
