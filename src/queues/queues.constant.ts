/**
 * Queue name constants for BullMQ
 * Centralized to avoid typos and enable easy refactoring
 */
export const QUEUE_NAMES = {
    EMAIL: 'email-queue',
    NOTIFICATION: 'notification-queue',
    PUSH_NOTIFICATION: 'push-notification-queue',
} as const

/**
 * Job types for each queue
 */
export const JOB_TYPES = {
    EMAIL: {
        SEND_EMAIL: 'send-email',
        SEND_OTP: 'send-otp',
        SEND_WELCOME: 'send-welcome',
        SEND_PASSWORD_RESET: 'send-password-reset',
    },
    NOTIFICATION: {
        SEND_NOTIFICATION: 'send-notification',
        SEND_BULK_NOTIFICATION: 'send-bulk-notification',
    },
    PUSH: {
        SEND_PUSH: 'send-push',
        SEND_BULK_PUSH: 'send-bulk-push',
    },
} as const

/**
 * Default job options
 */
export const DEFAULT_JOB_OPTIONS = {
    attempts: 5,
    backoff: {
        type: 'exponential' as const,
        delay: 2000, // Start with 2 seconds
    },
    removeOnComplete: {
        count: 100, // Keep last 100 completed jobs
        age: 24 * 60 * 60, // Keep for 24 hours
    },
    removeOnFail: {
        count: 1000, // Keep last 1000 failed jobs for debugging
        age: 7 * 24 * 60 * 60, // Keep for 7 days
    },
}

/**
 * Queue-specific configurations
 */
export const QUEUE_CONFIG = {
    [QUEUE_NAMES.EMAIL]: {
        concurrency: 5, // Process 5 emails at a time
        limiter: {
            max: 100, // Max 100 jobs
            duration: 60000, // Per minute (rate limiting for email providers)
        },
    },
    [QUEUE_NAMES.NOTIFICATION]: {
        concurrency: 10,
    },
    [QUEUE_NAMES.PUSH_NOTIFICATION]: {
        concurrency: 20,
    },
}
