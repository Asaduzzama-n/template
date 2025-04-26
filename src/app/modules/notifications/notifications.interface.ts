import { Model, Types } from 'mongoose'

export type INotification = {
  _id: Types.ObjectId
  receiver: Types.ObjectId
  sender: Types.ObjectId
  title: string
  body: string
  isRead: boolean
  createdAt: Date
  updatedAt: Date
}

export type NotificationModel = Model<INotification>
