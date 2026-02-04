import express from 'express'
import auth from '../../middleware/auth'
import { USER_ROLES } from '../../../enum/user'
import { NotificationController } from './notifications.controller'
import validateRequest from '../../middleware/validateRequest'
import { NotificationValidations } from './notifications.validation'

const router = express.Router()

router.get(
  '/',
  auth(USER_ROLES.USER, USER_ROLES.ADMIN),
  NotificationController.getMyNotifications,
)

router.patch(
  '/:id',
  auth(USER_ROLES.USER, USER_ROLES.ADMIN),
  validateRequest(NotificationValidations.idParam),
  NotificationController.updateNotification,
)

router.patch(
  '/all',
  auth(USER_ROLES.USER, USER_ROLES.ADMIN),
  NotificationController.updateAllNotifications,
)

export const NotificationRoutes = router

