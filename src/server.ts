import colors from 'colors'
import mongoose from 'mongoose'
import { Server } from 'socket.io'
import { createAdapter } from '@socket.io/redis-adapter'
import app from './app'
import config from './config'

import { errorLogger, logger } from './shared/logger'
import { socketHelper } from './helpers/socketHelper'
import { UserServices } from './app/modules/user/user.service'
import { setSocketIO } from './helpers/socketInstances'
import { redisAdapter, getRedisPublisher, getRedisSubscriber } from './adapters/redisAdapter'
import { initializeQueues, shutdownQueues } from './queues'
import { closeEmailTransporter } from './queues/workers/emailWorker'

let server: any
let isShuttingDown = false

/**
 * Graceful shutdown handler
 */
const gracefulShutdown = async (signal: string) => {
  if (isShuttingDown) return
  isShuttingDown = true

  logger.info(`${signal} received. Starting graceful shutdown...`)

  // 1. Stop accepting new connections
  if (server) {
    server.close(() => {
      logger.info('HTTP server closed')
    })
  }

  // 2. Wait for active requests (give them 10 seconds)
  await new Promise(resolve => setTimeout(resolve, 5000))

  // 3. Close BullMQ workers and queues
  try {
    await shutdownQueues()
  } catch (error: any) {
    errorLogger.error('Error shutting down queues', { error: error.message })
  }

  // 4. Close email transporter
  closeEmailTransporter()

  // 5. Close Redis connections
  try {
    await redisAdapter.shutdown()
  } catch (error: any) {
    errorLogger.error('Error shutting down Redis', { error: error.message })
  }

  // 6. Close MongoDB connection
  try {
    await mongoose.connection.close()
    logger.info('MongoDB connection closed')
  } catch (error: any) {
    errorLogger.error('Error closing MongoDB', { error: error.message })
  }

  logger.info('✅ Graceful shutdown complete')
  process.exit(0)
}

/**
 * Main server initialization
 */
async function main() {
  try {
    // 1. Connect to MongoDB
    await mongoose.connect(config.database_url as string)
    logger.info('🗄️  MongoDB connected successfully')

    // 2. Initialize Redis
    await redisAdapter.initialize()

    // 3. Initialize BullMQ queues
    await initializeQueues()

    // 4. Start HTTP server
    const port = typeof config.port === 'number' ? config.port : Number(config.port)

    server = app.listen(port, config.ip_address as string, () => {
      logger.info(`🚀 Server running on http://${config.ip_address}:${port}`)
    })

    // 5. Initialize Socket.IO with Redis adapter
    const io = new Server(server, {
      pingTimeout: 60000,
      cors: {
        origin: '*',
        credentials: true,
      },
    })

    // Use Redis adapter for horizontal scaling
    const pubClient = getRedisPublisher()
    const subClient = getRedisSubscriber()
    io.adapter(createAdapter(pubClient, subClient))
    logger.info('📡 Socket.IO Redis adapter initialized')

    // 6. Initialize socket handlers
    socketHelper.socket(io)
    setSocketIO(io)

    // 7. Create admin user
    await UserServices.createAdmin()

    logger.info('✅ Server initialization complete')

  } catch (error: any) {
    errorLogger.error('🔥 Server initialization failed', {
      error: error.message,
      stack: error.stack,
    })
    process.exit(1)
  }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  errorLogger.error('💥 Uncaught Exception', {
    error: error.message,
    stack: error.stack,
  })
  process.exit(1)
})

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason: any) => {
  errorLogger.error('💥 Unhandled Rejection', {
    reason: reason?.message || reason,
    stack: reason?.stack,
  })
  // Don't exit, let the app try to continue
})

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
process.on('SIGINT', () => gracefulShutdown('SIGINT'))

// Start the server
main()
