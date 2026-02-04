import express from 'express';
import { ReviewController } from './review.controller';
import auth from '../../middleware/auth';
import { USER_ROLES } from '../../../enum/user';
import validateRequest from '../../middleware/validateRequest';
import { ReviewValidations } from './review.validation';

const router = express.Router();

// Users can create reviews, admins can also create
router.post(
    '/',
    auth(USER_ROLES.USER, USER_ROLES.ADMIN),
    validateRequest(ReviewValidations.create),
    ReviewController.createReview
);

// Get reviews with type validation
router.get(
    '/:type',
    auth(USER_ROLES.USER, USER_ROLES.ADMIN),
    validateRequest(ReviewValidations.getByType),
    ReviewController.getAllReviews
);

// Update with id validation
router.patch(
    '/:id',
    auth(USER_ROLES.USER, USER_ROLES.ADMIN),
    validateRequest(ReviewValidations.idParam),
    validateRequest(ReviewValidations.update),
    ReviewController.updateReview
);

// Delete with id validation
router.delete(
    '/:id',
    auth(USER_ROLES.USER, USER_ROLES.ADMIN),
    validateRequest(ReviewValidations.idParam),
    ReviewController.deleteReview
);

export const ReviewRoutes = router;
