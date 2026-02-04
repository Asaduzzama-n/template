import { z } from 'zod'

// MongoDB ObjectId pattern
const objectIdSchema = z.string().regex(/^[a-fA-F0-9]{24}$/, 'Invalid ObjectId format')

// Valid public content types
const publicTypeEnum = z.enum(['privacy-policy', 'terms-and-condition', 'contact', 'about'], {
  errorMap: () => ({ message: 'Type must be one of: privacy-policy, terms-and-condition, contact, about' })
})

const contactZodSchema = z.object({
  body: z.object({
    name: z.string({
      required_error: 'Name is required',
    }).min(1, 'Name cannot be empty').max(100, 'Name must be at most 100 characters'),
    email: z
      .string({
        required_error: 'Email is required',
      })
      .email('Invalid email format')
      .max(255, 'Email must be at most 255 characters'),
    phone: z.string({
      required_error: 'Phone number is required',
    }).min(1, 'Phone cannot be empty').max(20, 'Phone must be at most 20 characters'),
    country: z.string({
      required_error: 'Country is required',
    }).min(1, 'Country cannot be empty').max(100, 'Country must be at most 100 characters'),
    message: z.string({
      required_error: 'Message is required',
    }).min(1, 'Message cannot be empty').max(5000, 'Message must be at most 5000 characters'),
  }),
})

export const PublicValidation = {
  create: z.object({
    body: z.object({
      content: z.string().min(1, 'Content cannot be empty').max(100000, 'Content must be at most 100000 characters'),
      type: publicTypeEnum,
    }),
  }),

  update: z.object({
    body: z.object({
      content: z.string().min(1, 'Content cannot be empty').max(100000, 'Content must be at most 100000 characters'),
      type: publicTypeEnum,
    }),
  }),

  // For validating route params
  typeParam: z.object({
    params: z.object({
      type: publicTypeEnum,
    }),
  }),

  idParam: z.object({
    params: z.object({
      id: objectIdSchema,
    }),
  }),

  contactZodSchema,
}

export const FaqValidations = {
  create: z.object({
    body: z.object({
      question: z.string().min(1, 'Question cannot be empty').max(500, 'Question must be at most 500 characters'),
      answer: z.string().min(1, 'Answer cannot be empty').max(5000, 'Answer must be at most 5000 characters'),
    }),
  }),

  update: z.object({
    body: z.object({
      question: z.string().min(1, 'Question cannot be empty').max(500, 'Question must be at most 500 characters').optional(),
      answer: z.string().min(1, 'Answer cannot be empty').max(5000, 'Answer must be at most 5000 characters').optional(),
    }),
  }),

  idParam: z.object({
    params: z.object({
      id: objectIdSchema,
    }),
  }),
}

