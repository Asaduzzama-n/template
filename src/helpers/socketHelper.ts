import colors from 'colors'
import { Server, Socket } from 'socket.io'
import { logger } from '../shared/logger'
import { redisClient } from '../config/redis'
import { USER_ROLES } from '../enum/user'
import { JwtPayload } from 'jsonwebtoken'
import { socketMiddleware } from '../app/middleware/socketAuth'

// ─── Socket user shape ────────────────────────────────────────────────────────
export interface SocketWithUser extends Socket {
  user?: JwtPayload & {
    authId: string
    role: string
    name?: string
    email?: string
  }
}

// ─── Redis key helpers ────────────────────────────────────────────────────────
const ONLINE_USERS_KEY = 'socket:online_users'

const markUserOnline = (authId: string, socketId: string) =>
  redisClient.hset(ONLINE_USERS_KEY, authId, socketId)

const markUserOffline = (authId: string) =>
  redisClient.hdel(ONLINE_USERS_KEY, authId)

export const getUserSocketId = (authId: string) =>
  redisClient.hget(ONLINE_USERS_KEY, authId)

export const isUserOnline = async (authId: string): Promise<boolean> => {
  const val = await redisClient.hexists(ONLINE_USERS_KEY, authId)
  return val === 1
}

// ─── Socket setup ─────────────────────────────────────────────────────────────
const socket = (io: Server) => {
  // Apply JWT auth middleware to all incoming connections
  io.use(
    socketMiddleware.socketAuth(
      USER_ROLES.CUSTOMER,
      USER_ROLES.ADMIN,
      USER_ROLES.GUEST,
      USER_ROLES.USER,
    ),
  )

  io.on('connection', async (socket: SocketWithUser) => {
    if (!socket.user) return

    const { authId } = socket.user

    // ── Track online status in Redis (survives multi-process) ─────────────────
    await markUserOnline(authId, socket.id)
    logger.info(colors.blue(`⚡ User ${authId} connected [${socket.id}]`))

    // ── Join personal room for targeted events ────────────────────────────────
    // Notifications, direct messages etc. are sent to `user:<authId>`
    socket.join(`user:${authId}`)
    logger.info(colors.blue(`📬 User ${authId} joined room user:${authId}`))

    registerEventHandlers(socket, io)
  })
}

// ─── Event Handlers ───────────────────────────────────────────────────────────
const registerEventHandlers = (socket: SocketWithUser, _io: Server) => {
  socket.on('disconnect', async () => {
    const authId = socket.user?.authId
    if (authId) {
      await markUserOffline(authId)
    }
    logger.info(
      colors.red(
        `User ${socket.user?.authId ?? 'Unknown'} disconnected [${socket.id}]`,
      ),
    )
  })
}

export const socketHelper = {
  socket,
  markUserOnline,
  markUserOffline,
  getUserSocketId,
  isUserOnline,
}
