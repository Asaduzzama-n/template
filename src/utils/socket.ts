/**
 * @deprecated
 * This module is deprecated and will be removed.
 *
 * Use `getSocketIO()` and `emitToUser()` from `@/helpers/socketInstances` instead.
 * Those functions provide type-safe access to the Socket.IO server instance
 * and targeted room-based event emission.
 *
 * Example:
 *   import { emitToUser } from '../helpers/socketInstances'
 *   emitToUser(userId, 'notification', payload)
 */
export { getSocketIO as socket } from '../helpers/socketInstances'
