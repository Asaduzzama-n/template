import { Worker, Job } from 'bullmq';
import { sendNotification } from './notificationHelper';
import { logger } from '../shared/logger';

import { emailHelper } from './emailHelper';
import { redisClient } from './redis';




export const notificationWorker = new Worker(
  'notifications',
  async (job: Job) => {
    logger.info('Notification worker starting...','🎭');

    try {
      await sendNotification(job.data.from, job.data.to, job.data.title, job.data.body, job.data.deviceToken);
    } catch (err) {
      logger.error(err);
      throw err; // rethrow to trigger retry
    }
  },
  {
    connection:redisClient,
    autorun: true,
    
  }
);

export const emailWorker = new Worker(
  'emails',
  async (job: Job) => {
    logger.info('Email worker starting...','🎭');

    try {
      await emailHelper.sendEmail(job.data);
    } catch (err) {
      logger.error(err);
      throw err; // rethrow to trigger retry
    }
  },
  {
    connection:redisClient,
    autorun: true,
    
  }
);



notificationWorker.on('active', (job) => {
    console.log(`Job ${job.id} is now active`);
  });
  
  notificationWorker.on('completed', (job) => {
    console.log(`Job ${job.id} has been completed`);
  });
  
  notificationWorker.on('failed', (job, err) => {
    console.error(`Job ${job?.id} failed`, err);
  });
  
  emailWorker.on('active', (job) => {
    console.log(`Job ${job.id} is now active`);
  });
  
  emailWorker.on('completed', (job) => {
    console.log(`Job ${job.id} has been completed`);
  });
  
  emailWorker.on('failed', (job, err) => {
    console.error(`Job ${job?.id} failed`, err);
  });
  