import colors from 'colors'
import { Server, Socket } from 'socket.io'
import { logger } from '../shared/logger'
import { USER_ROLES } from '../enum/user'
import { JwtPayload } from 'jsonwebtoken'
import { socketMiddleware } from '../app/middleware/socketAuth'
import { socketRedis } from './socketRedis'
import { getSocketIO } from './socketInstances'

// Define interface for socket with user data
export interface SocketWithUser extends Socket {
  user?: JwtPayload & {
    authId: string
    role: string
  }
}

/**
 * Initialize socket server with Redis-backed user tracking
 * 
 * @param io - Socket.IO server instance
 */
const socket = (io: Server) => {
  // Apply authentication middleware to all connections
  io.use(
    socketMiddleware.socketAuth(
      USER_ROLES.CUSTOMER,
      USER_ROLES.ADMIN,
      USER_ROLES.GUEST,
      USER_ROLES.USER,
    ),
  )

  io.on('connection', async (socket: SocketWithUser) => {
    if (socket.user) {
      const userId = socket.user.authId

      // Store socket mapping in Redis
      await socketRedis.setUserSocket(userId, socket.id)

      // Join user to their own room (for targeted emissions)
      socket.join(userId)

      logger.info(`⚡ User connected`, {
        userId,
        socketId: socket.id,
        role: socket.user.role,
      })

      // Register event handlers
      registerEventHandlers(socket)
    }
  })
}

/**
 * Register all socket event handlers
 */
const registerEventHandlers = (socket: SocketWithUser) => {
  const userId = socket.user?.authId

  // Handle disconnect
  socket.on('disconnect', async (reason) => {
    if (userId) {
      // Remove socket mapping from Redis
      await socketRedis.removeUserSocket(userId, socket.id)

      logger.info(`⚡ User disconnected`, {
        userId,
        socketId: socket.id,
        reason,
      })
    }
  })

  // Handle explicit logout (clear all sockets)
  socket.on('logout', async () => {
    if (userId) {
      await socketRedis.clearUserSockets(userId)
      logger.info(`User logged out from all devices`, { userId })
    }
  })

  // Handle errors
  socket.on('error', (error) => {
    logger.error('Socket error', {
      userId,
      socketId: socket.id,
      error: error.message,
    })
  })
}

/**
 * Emit event to a specific user (all their connected sockets)
 * 
 * @param userId - Target user ID
 * @param event - Event name
 * @param data - Event data
 */
export const emitToUser = async (
  userId: string,
  event: string,
  data: any
): Promise<boolean> => {
  const io = getSocketIO()
  if (!io) {
    logger.warn('Socket.IO not initialized, skipping emit', { event, userId })
    return false
  }

  try {
    // Emit to the user's room (all their sockets join their userId room)
    io.to(userId).emit(event, data)

    logger.debug('Emitted event to user', {
      userId,
      event,
    })

    return true
  } catch (error: any) {
    logger.error('Failed to emit to user', {
      userId,
      event,
      error: error.message,
    })
    return false
  }
}

/**
 * Emit event to multiple users
 * 
 * @param userIds - Array of user IDs
 * @param event - Event name
 * @param data - Event data
 */
export const emitToUsers = async (
  userIds: string[],
  event: string,
  data: any
): Promise<void> => {
  const io = getSocketIO()
  if (!io) {
    logger.warn('Socket.IO not initialized, skipping emit', { event })
    return
  }

  userIds.forEach(userId => {
    io.to(userId).emit(event, data)
  })

  logger.debug('Emitted event to users', {
    userCount: userIds.length,
    event,
  })
}

/**
 * Broadcast event to all connected users
 * 
 * @param event - Event name
 * @param data - Event data
 */
export const broadcast = (event: string, data: any): boolean => {
  const io = getSocketIO()
  if (!io) {
    logger.warn('Socket.IO not initialized, skipping broadcast', { event })
    return false
  }

  io.emit(event, data)

  logger.debug('Broadcast event', { event })
  return true
}

export const socketHelper = {
  socket,
  emitToUser,
  emitToUsers,
  broadcast,
}
