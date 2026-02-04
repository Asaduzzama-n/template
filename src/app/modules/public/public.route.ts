import express from 'express'
import { PublicController } from './public.controller'
import validateRequest from '../../middleware/validateRequest'
import { FaqValidations, PublicValidation } from './public.validation'
import { USER_ROLES } from '../../../enum/user'
import auth from '../../middleware/auth'

const router = express.Router()

// Admin only - create/update public content (privacy policy, terms, etc.)
router.post(
  '/',
  auth(USER_ROLES.ADMIN),
  validateRequest(PublicValidation.create),
  PublicController.createPublic,
)

// Public - get public content by type
router.get(
  '/:type',
  validateRequest(PublicValidation.typeParam),
  PublicController.getAllPublics,
)

// Admin only - delete public content
router.delete(
  '/:id',
  auth(USER_ROLES.ADMIN),
  validateRequest(PublicValidation.idParam),
  PublicController.deletePublic,
)

// Public - contact form submission
router.post(
  '/contact',
  validateRequest(PublicValidation.contactZodSchema),
  PublicController.createContact,
)

// Admin only - FAQ management
router.post(
  '/faq',
  auth(USER_ROLES.ADMIN),
  validateRequest(FaqValidations.create),
  PublicController.createFaq,
)

router.patch(
  '/faq/:id',
  auth(USER_ROLES.ADMIN),
  validateRequest(FaqValidations.idParam),
  validateRequest(FaqValidations.update),
  PublicController.updateFaq,
)

// Public - get single FAQ
router.get(
  '/faq/single/:id',
  validateRequest(FaqValidations.idParam),
  PublicController.getSingleFaq,
)

// Public - get all FAQs
router.get('/faq/all', PublicController.getAllFaqs)

// Admin only - delete FAQ
router.delete(
  '/faq/:id',
  auth(USER_ROLES.ADMIN),
  validateRequest(FaqValidations.idParam),
  PublicController.deleteFaq,
)

export const PublicRoutes = router

