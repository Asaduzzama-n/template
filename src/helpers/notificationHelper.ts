import { Notification } from '../app/modules/notifications/notifications.model'
import { logger, errorLogger } from '../shared/logger'
import { sendPushNotification } from './pushnotificationHelper'
import { addJob, QUEUE_NAMES, JOB_TYPES } from '../queues'
import { INotificationJobData } from '../queues/workers/notificationWorker'
import { emitToUser } from './socketHelper'

/**
 * Send notification directly (synchronous)
 * Use this only when you need immediate notification
 * 
 * @deprecated Use queueNotification() for better performance
 */
export const sendNotification = async (
  from: {
    authId: string
    profile?: string
    name?: string
  },
  to: string,
  title: string,
  body: string,
  deviceToken?: string,
) => {
  try {
    const result = await Notification.create({
      from: from.authId,
      to,
      title,
      body,
      isRead: false,
    })

    if (!result) {
      logger.warn('Notification not created')
      return null
    }

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

    // Emit to user via socket
    await emitToUser(to, 'notification', socketResponse)

    // Send push notification if device token available
    if (deviceToken) {
      await sendPushNotification(deviceToken, title, body, { from: from.authId, to })
    }

    return result
  } catch (err: any) {
    errorLogger.error('Failed to send notification', {
      to,
      title,
      error: err.message,
    })
    return null
  }
}

/**
 * Queue notification for background processing (non-blocking)
 * This is the preferred method for sending notifications
 */
export const queueNotification = async (
  from: {
    authId: string
    profile?: string
    name?: string
  },
  to: string,
  title: string,
  body: string,
  deviceToken?: string,
  data?: Record<string, any>
): Promise<string> => {
  const jobData: INotificationJobData = {
    from,
    to,
    title,
    body,
    deviceToken,
    data,
  }

  const job = await addJob(
    QUEUE_NAMES.NOTIFICATION,
    JOB_TYPES.NOTIFICATION.SEND_NOTIFICATION,
    jobData
  )

  logger.debug('Notification queued', {
    jobId: job.id,
    to,
    title,
  })

  return job.id!
}

export const notificationHelper = {
  sendNotification,
  queueNotification,
}
