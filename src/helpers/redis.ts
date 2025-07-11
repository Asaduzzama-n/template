import createClient from 'ioredis'

export const redisClient = new createClient()

redisClient.on('error', err => {
  console.error('Redis client error:', err)
})
