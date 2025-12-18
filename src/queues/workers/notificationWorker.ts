import { Job } from 'bullmq'
import { Notification } from '../../app/modules/notifications/notifications.model'
import { logger, errorLogger } from '../../shared/logger'
import { getSocketIO } from '../../helpers/socketInstances'
import { sendPushNotification } from '../../helpers/pushnotificationHelper'

/**
 * Notification job data interface
 */
export interface INotificationJobData {
    from: {
        authId: string
        name?: string
        profile?: string
    }
    to: string
    title: string
    body: string
    deviceToken?: string
    data?: Record<string, any>
}

/**
 * Bulk notification job data
 */
export interface IBulkNotificationJobData {
    from: {
        authId: string
        name?: string
        profile?: string
    }
    recipients: Array<{
        userId: string
        deviceToken?: string
    }>
    title: string
    body: string
    data?: Record<string, any>
}

/**
 * Process notification job
 */
export const processNotificationJob = async (
    job: Job<INotificationJobData | IBulkNotificationJobData>
): Promise<{ success: boolean; notificationId?: string }> => {
    const jobData = job.data

    // Check if bulk notification
    if ('recipients' in jobData) {
        return processBulkNotification(job as Job<IBulkNotificationJobData>)
    }

    return processSingleNotification(job as Job<INotificationJobData>)
}

/**
 * Process single notification
 */
const processSingleNotification = async (
    job: Job<INotificationJobData>
): Promise<{ success: boolean; notificationId: string }> => {
    const { from, to, title, body, deviceToken, data } = job.data

    logger.debug(`Processing notification job ${job.id}`, {
        jobId: job.id,
        to,
        title,
    })

    try {
        // Create notification in database
        const notification = await Notification.create({
            from: from.authId,
            to,
            title,
            body,
            isRead: false,
            data,
        })

        // Emit via Socket.IO
        const io = getSocketIO()
        if (io) {
            const socketResponse = {
                _id: notification._id,
                from: {
                    _id: from.authId,
                    name: from.name,
                    profile: from.profile,
                },
                to,
                title,
                body,
                isRead: false,
                createdAt: notification.createdAt,
                updatedAt: notification.updatedAt,
            }

            // Emit to user's room (userId-based room)
            io.to(to).emit('notification', socketResponse)
        }

        // Send push notification if device token is available
        if (deviceToken) {
            try {
                await sendPushNotification(deviceToken, title, body, {
                    from: from.authId,
                    to,
                    notificationId: notification._id.toString(),
                    ...data,
                })
            } catch (pushError: any) {
                // Log but don't fail the job for push notification errors
                logger.warn(`Push notification failed for job ${job.id}`, {
                    error: pushError.message,
                })
            }
        }

        logger.info(`Notification sent successfully`, {
            jobId: job.id,
            notificationId: notification._id.toString(),
            to,
        })

        return { success: true, notificationId: notification._id.toString() }
    } catch (error: any) {
        errorLogger.error(`Failed to send notification`, {
            jobId: job.id,
            to,
            error: error.message,
        })
        throw error
    }
}

/**
 * Process bulk notification
 */
const processBulkNotification = async (
    job: Job<IBulkNotificationJobData>
): Promise<{ success: boolean; notificationId?: string }> => {
    const { from, recipients, title, body, data } = job.data

    logger.debug(`Processing bulk notification job ${job.id}`, {
        jobId: job.id,
        recipientCount: recipients.length,
        title,
    })

    try {
        // Create notifications in bulk
        const notifications = recipients.map((recipient) => ({
            from: from.authId,
            to: recipient.userId,
            title,
            body,
            isRead: false,
            data,
        }))

        const created = await Notification.insertMany(notifications)

        // Emit via Socket.IO
        const io = getSocketIO()
        if (io) {
            recipients.forEach((recipient, index) => {
                const notification = created[index]
                const socketResponse = {
                    _id: notification._id,
                    from: {
                        _id: from.authId,
                        name: from.name,
                        profile: from.profile,
                    },
                    to: recipient.userId,
                    title,
                    body,
                    isRead: false,
                    createdAt: notification.createdAt,
                    updatedAt: notification.updatedAt,
                }
                io.to(recipient.userId).emit('notification', socketResponse)
            })
        }

        // Send push notifications
        const pushPromises = recipients
            .filter((r) => r.deviceToken)
            .map((recipient) =>
                sendPushNotification(recipient.deviceToken!, title, body, {
                    from: from.authId,
                    to: recipient.userId,
                    ...data,
                }).catch((err) => {
                    logger.warn(`Push notification failed for user ${recipient.userId}`, {
                        error: err.message,
                    })
                })
            )

        await Promise.allSettled(pushPromises)

        logger.info(`Bulk notification sent successfully`, {
            jobId: job.id,
            recipientCount: recipients.length,
        })

        return { success: true }
    } catch (error: any) {
        errorLogger.error(`Failed to send bulk notification`, {
            jobId: job.id,
            error: error.message,
        })
        throw error
    }
}
