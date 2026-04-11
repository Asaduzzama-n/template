import { Notification } from '../app/modules/notifications/notifications.model'
import { logger } from '../shared/logger'
import { emitToUser } from './socketInstances'
import { sendPushNotification } from './pushnotificationHelper'

type NotificationSender = {
  authId: string
  profile?: string
  name?: string
}

/**
 * Creates a DB notification record, delivers it in real-time via Socket.IO
 * to the specific recipient's room, and optionally sends an FCM push notification.
 *
 * Room convention: `user:<authId>` (see socketHelper.ts — joined on connect)
 */
export const sendNotification = async (
  from: NotificationSender,
  to: string,
  title: string,
  body: string,
  fcmToken?: string,
): Promise<void> => {
  try {
    // 1. Persist notification to DB
    const result = await Notification.create({
      from: from.authId,
      to,
      title,
      body,
      isRead: false,
    })

    if (!result) {
      logger.warn('Notification DB write returned no result')
      return
    }

    // 2. Real-time delivery — targeted ONLY to the recipient's room
    //    Previously used socket.emit (broadcast to ALL) — now fixed
    const socketPayload = {
      _id: result._id,
      from: {
        _id: from.authId,
        name: from.name,
        profile: from.profile,
      },
      to,
      title,
      body,
      isRead: false,
      createdAt: result.createdAt,
      updatedAt: result.updatedAt,
    }

    emitToUser(to, 'notification', socketPayload)

    // 3. Push notification (optional — only if FCM token provided)
    if (fcmToken) {
      await sendPushNotification(fcmToken, title, body, {
        from: from.authId,
        to,
      })
    }
  } catch (err) {
    logger.error('sendNotification failed:', err)
  }
}
