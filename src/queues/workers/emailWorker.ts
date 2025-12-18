import { Job } from 'bullmq'
import nodemailer from 'nodemailer'
import config from '../../config'
import { logger, errorLogger } from '../../shared/logger'
import { JOB_TYPES } from '../queues.constant'

/**
 * Email job data interface
 */
export interface IEmailJobData {
    to: string
    subject: string
    html: string
    from?: string
    replyTo?: string
    attachments?: Array<{
        filename: string
        content: Buffer | string
        contentType?: string
    }>
}

/**
 * Create nodemailer transporter
 */
const createTransporter = () => {
    return nodemailer.createTransport({
        host: config.email.host,
        port: Number(config.email.port),
        secure: Number(config.email.port) === 465,
        auth: {
            user: config.email.user,
            pass: config.email.pass,
        },
        pool: true, // Use connection pooling
        maxConnections: 5,
        maxMessages: 100,
    })
}

let transporter: nodemailer.Transporter | null = null

/**
 * Get or create transporter (singleton for connection pooling)
 */
const getTransporter = (): nodemailer.Transporter => {
    if (!transporter) {
        transporter = createTransporter()
    }
    return transporter
}

/**
 * Process email job
 */
export const processEmailJob = async (job: Job<IEmailJobData>): Promise<{ messageId: string }> => {
    const { to, subject, html, from, replyTo, attachments } = job.data

    logger.debug(`Processing email job ${job.id}`, {
        jobId: job.id,
        to,
        subject,
        attempt: job.attemptsMade + 1,
    })

    try {
        const mailer = getTransporter()

        const info = await mailer.sendMail({
            from: from || `"Express-Craft" <${config.email.from}>`,
            to,
            subject,
            html,
            replyTo,
            attachments,
        })

        logger.info(`Email sent successfully`, {
            jobId: job.id,
            to,
            subject,
            messageId: info.messageId,
        })

        return { messageId: info.messageId }
    } catch (error: any) {
        errorLogger.error(`Failed to send email`, {
            jobId: job.id,
            to,
            subject,
            attempt: job.attemptsMade + 1,
            error: error.message,
        })

        // Rethrow to trigger retry
        throw error
    }
}

/**
 * Close transporter connection (for graceful shutdown)
 */
export const closeEmailTransporter = (): void => {
    if (transporter) {
        transporter.close()
        transporter = null
        logger.info('Email transporter closed')
    }
}
