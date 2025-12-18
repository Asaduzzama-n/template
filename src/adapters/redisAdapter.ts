import Redis, { Redis as RedisClient } from 'ioredis'
import config from '../config'
import { logger, errorLogger } from '../shared/logger'

/**
 * Redis connection options with production-ready defaults.
 */
const redisOptions = {
    maxRetriesPerRequest: 3,
    retryStrategy(times: number) {
        if (times > 10) {
            errorLogger.error('Redis max retries exceeded, giving up')
            return null // Stop retrying
        }
        const delay = Math.min(times * 100, 3000)
        logger.warn(`Redis connection retry attempt ${times}, waiting ${delay}ms`)
        return delay
    },
    reconnectOnError(err: Error) {
        const targetErrors = ['READONLY', 'ECONNRESET', 'ETIMEDOUT']
        return targetErrors.some(e => err.message.includes(e))
    },
    enableReadyCheck: true,
    lazyConnect: false, // Connect immediately for health checks
}

/**
 * Centralized Redis Adapter
 * 
 * Provides a single connection pool reused across:
 * - Rate limiting
 * - BullMQ job queues
 * - Socket.IO adapter
 * - Caching
 * 
 * Supports graceful shutdown and health monitoring.
 */
class RedisAdapter {
    private static instance: RedisAdapter
    private _client: RedisClient | null = null
    private _subscriber: RedisClient | null = null
    private _publisher: RedisClient | null = null
    private _isConnected: boolean = false
    private _isShuttingDown: boolean = false

    private constructor() { }

    /**
     * Get singleton instance
     */
    static getInstance(): RedisAdapter {
        if (!RedisAdapter.instance) {
            RedisAdapter.instance = new RedisAdapter()
        }
        return RedisAdapter.instance
    }

    /**
     * Initialize Redis connections
     */
    async initialize(): Promise<void> {
        if (this._client) {
            logger.warn('Redis already initialized')
            return
        }

        try {
            this._client = new Redis(config.redis.url, redisOptions)

            this._client.on('connect', () => {
                logger.info('📦 Redis client connected')
            })

            this._client.on('ready', () => {
                this._isConnected = true
                logger.info('✅ Redis client ready')
            })

            this._client.on('error', (err) => {
                this._isConnected = false
                errorLogger.error('Redis client error', { error: err.message })
            })

            this._client.on('close', () => {
                this._isConnected = false
                if (!this._isShuttingDown) {
                    logger.warn('Redis connection closed unexpectedly')
                }
            })

            // Wait for connection
            await this._client.ping()
            logger.info('🏓 Redis PING successful')
        } catch (error) {
            errorLogger.error('Failed to initialize Redis', { error })
            throw error
        }
    }

    /**
     * Get the main Redis client for general operations
     */
    get client(): RedisClient {
        if (!this._client) {
            throw new Error('Redis not initialized. Call initialize() first.')
        }
        return this._client
    }

    /**
     * Get a subscriber client for Pub/Sub (Socket.IO adapter)
     * Creates a duplicate connection for subscriptions
     */
    get subscriber(): RedisClient {
        if (!this._subscriber && this._client) {
            this._subscriber = this._client.duplicate()
            this._subscriber.on('error', (err) => {
                errorLogger.error('Redis subscriber error', { error: err.message })
            })
        }
        if (!this._subscriber) {
            throw new Error('Redis not initialized. Call initialize() first.')
        }
        return this._subscriber
    }

    /**
     * Get a publisher client for Pub/Sub (Socket.IO adapter)
     * Creates a duplicate connection for publishing
     */
    get publisher(): RedisClient {
        if (!this._publisher && this._client) {
            this._publisher = this._client.duplicate()
            this._publisher.on('error', (err) => {
                errorLogger.error('Redis publisher error', { error: err.message })
            })
        }
        if (!this._publisher) {
            throw new Error('Redis not initialized. Call initialize() first.')
        }
        return this._publisher
    }

    /**
     * Check if Redis is connected and healthy
     */
    get isConnected(): boolean {
        return this._isConnected
    }

    /**
     * Health check - returns true if Redis responds to PING
     */
    async healthCheck(): Promise<boolean> {
        if (!this._client) return false
        try {
            const result = await this._client.ping()
            return result === 'PONG'
        } catch {
            return false
        }
    }

    /**
     * Get Redis connection URL for BullMQ
     * BullMQ needs the connection config, not the client
     */
    getConnectionConfig() {
        return {
            connection: this._client,
        }
    }

    /**
     * Get raw connection URL for external use
     */
    getConnectionUrl(): string {
        return config.redis.url
    }

    /**
     * Graceful shutdown - close all connections
     */
    async shutdown(): Promise<void> {
        this._isShuttingDown = true
        logger.info('🔌 Shutting down Redis connections...')

        const closePromises: Promise<void>[] = []

        if (this._subscriber) {
            closePromises.push(
                this._subscriber.quit().then(() => {
                    logger.info('Redis subscriber closed')
                })
            )
        }

        if (this._publisher) {
            closePromises.push(
                this._publisher.quit().then(() => {
                    logger.info('Redis publisher closed')
                })
            )
        }

        if (this._client) {
            closePromises.push(
                this._client.quit().then(() => {
                    logger.info('Redis client closed')
                })
            )
        }

        await Promise.all(closePromises)

        this._client = null
        this._subscriber = null
        this._publisher = null
        this._isConnected = false

        logger.info('✅ All Redis connections closed')
    }
}

// Export singleton instance
export const redisAdapter = RedisAdapter.getInstance()

// Export convenience methods
export const getRedisClient = () => redisAdapter.client
export const getRedisSubscriber = () => redisAdapter.subscriber
export const getRedisPublisher = () => redisAdapter.publisher
