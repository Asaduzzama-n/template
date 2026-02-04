import { Types } from 'mongoose'
import { Notification } from '../app/modules/notifications/notifications.model'
import { logger } from '../shared/logger'
import { socket } from '../utils/socket'
import { sendPushNotification } from './pushnotificationHelper'

export const sendNotification = async (
  from: {
    authId: string,
    profile?: string,
    name?: string,
  },
  to: string,
  title: string,
  body: string,
  fcmToken?: string,
) => {
  try {
    const result = await Notification.create({
      from: from.authId,
      to,
      title,
      body,
      isRead: false,
    })

    if (!result) logger.warn('Notification not sent')

    const socketResponse = {
      _id: result._id,
      from: {
        _id: from.authId,
        name: from?.name,
        profile: from?.profile,
      },
      to,
      title,
      body,
      isRead: false,
      createdAt: result.createdAt,
      updatedAt: result.updatedAt,

    }


    if (socket) {
      socket.emit('notification', socketResponse)
    }

    if (fcmToken) {
      await sendPushNotification(fcmToken, title, body, { from: from.authId, to })
    }
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err))
    logger.error(`FROM NOTIFICATION HELPER: ${error.message}`)
  }
}
