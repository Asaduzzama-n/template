import express from 'express'
import { PublicController } from './public.controller'
import validateRequest from '../../middleware/validateRequest'
import { FaqValidations, PublicValidation } from './public.validation'
import { USER_ROLES } from '../../../enum/user'
import auth from '../../middleware/auth'

const router = express.Router()

router.post(
  '/',
  validateRequest(PublicValidation.create),
  PublicController.createPublic,
)
router.get('/:type', PublicController.getAllPublics)

router.delete('/:id', PublicController.deletePublic)
router.post(
  '/contact',
  validateRequest(PublicValidation.contactZodSchema),
  PublicController.createContact,
)

router.post(
  '/',
  auth(USER_ROLES.ADMIN),
  validateRequest(FaqValidations.create),
  PublicController.createFaq,
)
router.patch(
  '/:id',
  auth(USER_ROLES.ADMIN),
  validateRequest(FaqValidations.update),
  PublicController.updateFaq,
)
router.get('/', PublicController.getAllFaqs)
router.get('/:id', PublicController.getSingleFaq)
router.delete('/:id', auth(USER_ROLES.ADMIN), PublicController.deleteFaq)

export const PublicRoutes = router
