import express from 'express';
import { ReviewController } from './review.controller';
import auth from '../../middleware/auth';
import { USER_ROLES } from '../../../enum/user';
import validateRequest from '../../middleware/validateRequest';
import { ReviewValidations } from './review.validation';

const router = express.Router();

router.post('/', validateRequest(ReviewValidations.create), ReviewController.createReview);
router.get('/:type', ReviewController.getAllReviews);
router.patch('/:id', validateRequest(ReviewValidations.update), ReviewController.updateReview);
router.delete('/:id', ReviewController.deleteReview);

export const ReviewRoutes = router;
