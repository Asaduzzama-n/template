import { z } from 'zod';

// MongoDB ObjectId pattern
const objectIdSchema = z.string().regex(/^[a-fA-F0-9]{24}$/, 'Invalid ObjectId format');

export const ReviewValidations = {
  create: z.object({
    body: z.object({
      reviewee: objectIdSchema,
      rating: z.number().min(1, 'Rating must be at least 1').max(5, 'Rating must be at most 5'),
      review: z.string().max(1000, 'Review must be at most 1000 characters').optional(),
    }),
  }),

  update: z.object({
    body: z.object({
      rating: z.number().min(1, 'Rating must be at least 1').max(5, 'Rating must be at most 5').optional(),
      review: z.string().max(1000, 'Review must be at most 1000 characters').optional(),
    }),
  }),

  // For validating route params
  getByType: z.object({
    params: z.object({
      type: z.enum(['reviewer', 'reviewee'], {
        errorMap: () => ({ message: 'Type must be either "reviewer" or "reviewee"' })
      }),
    }),
  }),

  idParam: z.object({
    params: z.object({
      id: objectIdSchema,
    }),
  }),
};
