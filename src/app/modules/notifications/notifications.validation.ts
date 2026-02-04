import { z } from 'zod'

export const NotificationValidations = {
    idParam: z.object({
        params: z.object({
            id: z.string().regex(/^[a-fA-F0-9]{24}$/, 'Invalid notification ID'),
        }),
    }),
}
