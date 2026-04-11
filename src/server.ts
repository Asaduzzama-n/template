import colors from 'colors'
import http from 'http'
import mongoose from 'mongoose'
import { Server } from 'socket.io'
import { createAdapter } from '@socket.io/redis-adapter'
import app from './app'
import config from './config'
import { connectRedis, createRedisDuplicate, redisClient } from './config/redis'
import { errorLogger, logger } from './shared/logger'
import { socketHelper } from './helpers/socketHelper'
import { UserServices } from './app/modules/user/user.service'
import { setSocketIO } from './helpers/socketInstances'

// ─── Uncaught Exceptions (sync errors before event loop) ────────────────────
process.on('uncaughtException', error => {
  errorLogger.error('UncaughtException Detected:', error)
  process.exit(1)
})

let server: http.Server

async function main() {
  try {
    // 1. Connect Redis first (Socket.IO adapter needs it)
    await connectRedis()
    logger.info(colors.cyan('🔴 Redis connected successfully'))

    // 2. Connect MongoDB
    await mongoose.connect(config.database_url)
    logger.info(colors.green('🚀 Database connected successfully'))

    // 3. Start HTTP server
    server = http.createServer(app)
    server.listen(config.port, config.ip_address, () => {
      logger.info(
        colors.yellow(`♻️  Application listening on port: ${config.port}`),
      )
    })

    // 4. Setup Socket.IO with Redis adapter for horizontal scaling
    const io = new Server(server, {
      pingTimeout: 60_000,
      cors: {
        origin: config.node_env === 'development' ? '*' : config.allowed_origins,
        credentials: true,
      },
    })

    // Wire Redis pub/sub adapter (enables multi-process socket events)
    const subClient = createRedisDuplicate()
    await subClient.connect()
    io.adapter(createAdapter(redisClient, subClient))
    logger.info(colors.cyan('⚡ Socket.IO Redis adapter initialized'))

    // 5. Seed admin user (non-fatal — isolated error)
    try {
      await UserServices.createAdmin()
    } catch (err) {
      errorLogger.error('Admin seed failed (non-fatal):', err)
    }

    // 6. Register socket handlers
    socketHelper.socket(io)
    setSocketIO(io)
  } catch (error) {
    errorLogger.error(colors.red('🤢 Failed to start server:'), error)
    process.exit(1)
  }

  // ─── Unhandled Promise Rejections ─────────────────────────────────────────
  process.on('unhandledRejection', error => {
    errorLogger.error('UnhandledRejection Detected:', error)
    gracefulShutdown('unhandledRejection')
  })
}

// ─── Graceful Shutdown ────────────────────────────────────────────────────────
async function gracefulShutdown(signal: string): Promise<void> {
  logger.info(colors.yellow(`${signal} received — shutting down gracefully…`))

  // Give in-flight requests 10 s to finish
  if (server) {
    server.close(async () => {
      logger.info('HTTP server closed')

      try {
        await mongoose.disconnect()
        logger.info('MongoDB disconnected')
      } catch (err) {
        errorLogger.error('Error disconnecting MongoDB:', err)
      }

      try {
        await redisClient.quit()
        logger.info('Redis disconnected')
      } catch (err) {
        errorLogger.error('Error disconnecting Redis:', err)
      }

      logger.info('✅ Graceful shutdown complete')
      process.exit(0)
    })

    // Force exit if graceful shutdown takes too long
    setTimeout(() => {
      errorLogger.error('Graceful shutdown timed out — forcing exit')
      process.exit(1)
    }, 10_000)
  } else {
    process.exit(0)
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
process.on('SIGINT', () => gracefulShutdown('SIGINT'))

main()
