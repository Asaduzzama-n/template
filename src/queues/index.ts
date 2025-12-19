import { Queue, Worker, QueueEvents, Job } from 'bullmq'
import { redisAdapter } from '../adapters/redisAdapter'
import { logger, errorLogger } from '../shared/logger'
import { QUEUE_NAMES, QUEUE_CONFIG, DEFAULT_JOB_OPTIONS } from './queues.constant'
import { processEmailJob } from './workers/emailWorker'
import { processNotificationJob } from './workers/notificationWorker'

// Import workers


/**
 * Queue Registry - Stores all queue instances
 */
const queues: Map<string, Queue> = new Map()
const workers: Map<string, Worker> = new Map()
const queueEvents: Map<string, QueueEvents> = new Map()

/**
 * Create a queue with default configuration.
 * Uses the dedicated BullMQ Redis client with maxRetriesPerRequest: null.
 */
const createQueue = (name: string): Queue => {
    // Use the dedicated BullMQ client (has maxRetriesPerRequest: null)
    const connection = redisAdapter.bullmqClient

    const queue = new Queue(name, {
        connection,
        defaultJobOptions: DEFAULT_JOB_OPTIONS,
    })

    queues.set(name, queue)

    // Create queue events for monitoring
    const events = new QueueEvents(name, { connection })
    queueEvents.set(name, events)

    // Log queue events
    events.on('completed', ({ jobId }) => {
        logger.debug(`Job ${jobId} completed in queue ${name}`)
    })

    events.on('failed', ({ jobId, failedReason }) => {
        errorLogger.error(`Job ${jobId} failed in queue ${name}`, {
            queue: name,
            jobId,
            reason: failedReason,
        })
    })

    events.on('stalled', ({ jobId }) => {
        logger.warn(`Job ${jobId} stalled in queue ${name}`)
    })

    logger.info(`📬 Queue "${name}" created`)
    return queue
}

/**
 * Create a worker with given processor.
 * Uses the dedicated BullMQ Redis client with maxRetriesPerRequest: null.
 */
const createWorker = (
    name: string,
    processor: (job: Job) => Promise<any>,
    options?: { concurrency?: number; limiter?: { max: number; duration: number } }
): Worker => {
    // Use the dedicated BullMQ client (has maxRetriesPerRequest: null)
    const connection = redisAdapter.bullmqClient
    const config = QUEUE_CONFIG[name as keyof typeof QUEUE_CONFIG]

    const workerOptions: any = {
        connection,
        concurrency: options?.concurrency || (config as any)?.concurrency || 5,
    }

    // Add limiter if available
    const limiter = options?.limiter || (config as any)?.limiter
    if (limiter) {
        workerOptions.limiter = limiter
    }

    const worker = new Worker(name, processor, workerOptions)

    // Worker event handlers
    worker.on('completed', (job) => {
        logger.debug(`Worker completed job ${job.id} in queue ${name}`)
    })

    worker.on('failed', (job, err) => {
        errorLogger.error(`Worker failed job ${job?.id} in queue ${name}`, {
            queue: name,
            jobId: job?.id,
            error: err.message,
            stack: err.stack,
        })
    })

    worker.on('error', (err) => {
        errorLogger.error(`Worker error in queue ${name}`, {
            queue: name,
            error: err.message,
        })
    })

    workers.set(name, worker)
    logger.info(`👷 Worker for "${name}" created`)
    return worker
}

/**
 * Initialize all queues and workers
 */
export const initializeQueues = async (): Promise<void> => {
    logger.info('🚀 Initializing BullMQ queues...')

    // Create queues
    createQueue(QUEUE_NAMES.EMAIL)
    createQueue(QUEUE_NAMES.NOTIFICATION)
    createQueue(QUEUE_NAMES.PUSH_NOTIFICATION)

    // Create workers
    createWorker(QUEUE_NAMES.EMAIL, processEmailJob)
    createWorker(QUEUE_NAMES.NOTIFICATION, processNotificationJob)
    // Push notification worker will use the same notification worker for now

    logger.info('✅ All queues and workers initialized')
}

/**
 * Get a queue by name
 */
export const getQueue = (name: string): Queue => {
    const queue = queues.get(name)
    if (!queue) {
        throw new Error(`Queue "${name}" not found. Make sure to call initializeQueues() first.`)
    }
    return queue
}

/**
 * Add a job to a queue
 */
export const addJob = async <T>(
    queueName: string,
    jobName: string,
    data: T,
    options?: {
        priority?: number
        delay?: number
        attempts?: number
    }
): Promise<Job<T>> => {
    const queue = getQueue(queueName)

    const job = await queue.add(jobName, data, {
        priority: options?.priority,
        delay: options?.delay,
        attempts: options?.attempts,
    })

    logger.debug(`Job ${job.id} added to queue ${queueName}`, {
        queue: queueName,
        jobName,
        jobId: job.id,
    })

    return job
}

/**
 * Graceful shutdown of all queues and workers
 */
export const shutdownQueues = async (): Promise<void> => {
    logger.info('🔌 Shutting down BullMQ queues...')

    // Close workers first (stop processing)
    const workerPromises = Array.from(workers.values()).map(async (worker) => {
        await worker.close()
    })
    await Promise.all(workerPromises)
    logger.info('All workers closed')

    // Close queue events
    const eventPromises = Array.from(queueEvents.values()).map(async (events) => {
        await events.close()
    })
    await Promise.all(eventPromises)

    // Close queues
    const queuePromises = Array.from(queues.values()).map(async (queue) => {
        await queue.close()
    })
    await Promise.all(queuePromises)

    queues.clear()
    workers.clear()
    queueEvents.clear()

    logger.info('✅ All queues shut down')
}

// Export queue names for easy access
export { QUEUE_NAMES, JOB_TYPES } from './queues.constant'
