import Redis from 'ioredis'
import config from '../config'
import { logger } from '../shared/logger'
import colors from 'colors'

const redisConfig = {
    host: config.redis.url || '127.0.0.1',
    port: Number(config.redis.port) || 6379,
    password: config.redis.password || undefined,
    maxRetriesPerRequest: null,
}

const redis = new Redis(redisConfig)

redis.on('connect', () => {
    logger.info(colors.green('🚀 Redis connected successfully'))
})

redis.on('error', error => {
    logger.error(colors.red('🤢 Redis connection error:'), error)
})

const set = async (key: string, value: string, ttl?: number): Promise<void> => {
    if (ttl) {
        await redis.set(key, value, 'EX', ttl)
    } else {
        await redis.set(key, value)
    }
}

const get = async (key: string): Promise<string | null> => {
    return await redis.get(key)
}

const del = async (key: string): Promise<void> => {
    await redis.del(key)
}

const disconnect = async (): Promise<void> => {
    await redis.quit()
}

export const redisHelper = {
    set,
    get,
    del,
    disconnect,
    redis,
}
