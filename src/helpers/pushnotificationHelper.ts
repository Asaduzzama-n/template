import admin from 'firebase-admin'
import config from '../config'
import { logger, errorLogger } from '../shared/logger'
import { User } from '../app/modules/user/user.model'

type NotificationData = { [key: string]: string }

// ─── Lazy Firebase Initialization ────────────────────────────────────────────
// Previously initialized at module load time, crashing the app if env missing.
// Now deferred to first use with a guard.
let firebaseApp: admin.app.App | null = null

const getFirebaseApp = (): admin.app.App => {
  if (firebaseApp) return firebaseApp

  const base64 = config.firebase_service_account_base64
  if (!base64) {
    throw new Error(
      'Firebase is not configured. Set FIREBASE_SERVICE_ACCOUNT_BASE64 in your .env file.',
    )
  }

  try {
    const serviceAccountJson = Buffer.from(base64, 'base64').toString('utf8')
    const serviceAccount = JSON.parse(serviceAccountJson)
    firebaseApp = admin.initializeApp(
      {
        credential: admin.credential.cert(
          serviceAccount as admin.ServiceAccount,
        ),
      },
      // Named instance to avoid "already initialized" errors in hot-reload dev
      `firebase-${Date.now()}`,
    )
    logger.info('🔥 Firebase Admin initialized')
    return firebaseApp
  } catch (err) {
    throw new Error(
      `Failed to parse Firebase service account: ${(err as Error).message}`,
    )
  }
}

// ─── Send Push Notification ───────────────────────────────────────────────────
export const sendPushNotification = async (
  fcmToken: string,
  title: string,
  body: string,
  data: NotificationData,
  icon?: string,
): Promise<void> => {
  let app: admin.app.App

  try {
    app = getFirebaseApp()
  } catch (err) {
    // Firebase not configured — degrade gracefully (don't crash)
    errorLogger.error('Push notification skipped:', (err as Error).message)
    return
  }

  const message: admin.messaging.Message = {
    token: fcmToken,
    notification: { title, body },
    data,
    ...(icon && {
      android: {
        notification: { icon },
      },
    }),
    apns: {
      payload: {
        aps: { 'mutable-content': 1 },
      },
    },
  }

  try {
    const response = await app.messaging().send(message)
    logger.info('Push notification sent:', response)
  } catch (error: any) {
    // Stale token cleanup — device unregistered from FCM
    if (
      error?.code === 'messaging/registration-token-not-registered' ||
      error?.code === 'messaging/invalid-registration-token'
    ) {
      logger.warn(
        `Stale FCM token detected — removing from user record: ${fcmToken.slice(0, 20)}…`,
      )
      try {
        await User.findOneAndUpdate(
          { fcmToken },
          { $unset: { fcmToken: 1 } },
        )
      } catch (dbErr) {
        errorLogger.error('Failed to remove stale FCM token:', dbErr)
      }
      return
    }

    errorLogger.error('Push notification failed:', error?.message, error)
  }
}
