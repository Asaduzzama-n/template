import { Queue } from "bullmq";
import { redisClient } from "./redis";



export const notificationQueue = new Queue('notifications', {
  connection: redisClient
})

export const emailQueue = new Queue('emails', {
  connection: redisClient
})

