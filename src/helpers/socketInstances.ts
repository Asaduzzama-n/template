import { Server } from 'socket.io'
import { logger, errorLogger } from '../shared/logger'

// ─── Socket.IO Instance Registry ─────────────────────────────────────────────
// Use getSocketIO() / setSocketIO() instead of importing the raw variable.
// This avoids circular dependency issues and is type-safe.

let socketIO: Server | null = null

export const setSocketIO = (io: Server): void => {
  socketIO = io
}

export const getSocketIO = (): Server | null => {
  return socketIO
}

// ─── Emit Helpers ─────────────────────────────────────────────────────────────

/**
 * Emit an event to a specific room or to all connected clients.
 * Returns `true` on success, `false` if Socket.IO is not yet initialized.
 */
export const emitEvent = (
  event: string,
  data: unknown,
  room?: string,
): boolean => {
  if (!socketIO) {
    logger.warn(`Socket.IO not initialized — skipping event: ${event}`)
    return false
  }

  try {
    if (room) {
      socketIO.to(room).emit(event, data)
    } else {
      socketIO.emit(event, data)
    }
    return true
  } catch (error) {
    errorLogger.error(`Socket emit failed for event '${event}':`, error)
    return false
  }
}

/**
 * Emit an event targeted to a specific user via their personal room.
 * Room name convention: `user:<authId>`
 */
export const emitToUser = (
  authId: string,
  event: string,
  data: unknown,
): boolean => {
  return emitEvent(event, data, `user:${authId}`)
}