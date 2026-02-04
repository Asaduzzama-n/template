import { Server } from 'socket.io';
import { logger, errorLogger } from '../shared/logger';

// Type-safe socket instance export

export let socketIO: Server | null = null;

export const setSocketIO = (io: Server) => {
  socketIO = io;
};

export const getSocketIO = (): Server | null => {
  return socketIO;
};


// Generic emit function
export const emitEvent = (
  event: string,
  data: unknown,
  room?: string
): boolean => {
  if (!socketIO) {
    logger.warn(`Socket.IO not initialized - Skipping event: ${event}`);
    return false;
  }

  try {
    if (room) {
      socketIO.to(room).emit(event, data);
    } else {
      socketIO.emit(event, data);
    }
    return true;
  } catch (error) {
    errorLogger.error(`Socket emit failed for event ${event}:`, error);
    return false;
  }
};