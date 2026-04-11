import nodemailer from 'nodemailer'
import config from '../config'
import { errorLogger, logger } from '../shared/logger'
import { ISendEmail } from '../interfaces/email'
import { Queue, Worker, QueueEvents } from 'bullmq'
import { redisClient } from '../config/redis'

// ─── Nodemailer Transporter ───────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: config.email.host,
  port: Number(config.email.port),
  secure: Number(config.email.port) === 465,
  auth: {
    user: config.email.user,
    pass: config.email.pass,
  },
  // Pool connections for efficiency
  pool: true,
  maxConnections: 5,
  maxMessages: 100,
})

// Verify SMTP connection on startup (non-fatal)
transporter.verify().then(() => {
  logger.info('📧 SMTP connection verified')
}).catch(err => {
  errorLogger.error('SMTP verification failed (check email config):', err.message)
})

// ─── BullMQ Email Queue ───────────────────────────────────────────────────────
const EMAIL_QUEUE_NAME = 'email-send'

export const emailQueue = new Queue(EMAIL_QUEUE_NAME, {
  connection: redisClient,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5_000 },
    removeOnComplete: { count: 100 },
    removeOnFail: { count: 200 },
  },
})

// ─── BullMQ Worker ────────────────────────────────────────────────────────────
const emailWorker = new Worker(
  EMAIL_QUEUE_NAME,
  async job => {
    const { to, subject, html } = job.data as ISendEmail
    await transporter.sendMail({
      from: `"${config.platform_name}" <${config.email.from}>`,
      to,
      subject,
      html,
    })
    logger.info(`📧 Email delivered to: ${to} (job ${job.id})`)
  },
  {
    connection: redisClient,
    concurrency: 5,
  },
)

emailWorker.on('failed', (job, err) => {
  errorLogger.error(
    `Email job ${job?.id} failed (attempt ${job?.attemptsMade}/${job?.opts.attempts}):`,
    err.message,
  )
})

emailWorker.on('error', err => {
  errorLogger.error('Email worker error:', err.message)
})

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Enqueues an email for resilient delivery via BullMQ.
 * Retries 3× with exponential backoff on transient SMTP failures.
 *
 * For use cases that require synchronous delivery (e.g. testing),
 * use `sendEmailDirect` instead.
 */
const sendEmail = async (values: ISendEmail): Promise<void> => {
  try {
    await emailQueue.add('send', values)
  } catch (err) {
    errorLogger.error('Failed to enqueue email:', err)
  }
}

/**
 * Sends an email directly (bypasses the queue).
 * Prefer `sendEmail` in production for resilience.
 */
const sendEmailDirect = async (values: ISendEmail): Promise<void> => {
  try {
    await transporter.sendMail({
      from: `"${config.platform_name}" <${config.email.from}>`,
      to: values.to,
      subject: values.subject,
      html: values.html,
    })
    logger.info('📧 Email sent directly to:', values.to)
  } catch (error) {
    errorLogger.error('Direct email failed:', error)
    throw error
  }
}

export const emailHelper = {
  sendEmail,
  sendEmailDirect,
}
