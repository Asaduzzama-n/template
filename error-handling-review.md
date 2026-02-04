# Error Handling & Middleware Review

A comprehensive review of the middlewares, global error handlers, and error handling implementation in the codebase.

---

## 📁 Files Reviewed

| Category | Files |
|----------|-------|
| **Middlewares** | `auth.ts`, `validateRequest.ts`, `processReqBody.ts`, `socketAuth.ts`, `globalErrorHandler.ts` |
| **Error Handlers** | `ApiError.ts`, `handleCastError.ts`, `handleValidationError.ts`, `handleZodError.ts` |
| **Interfaces** | `error.ts`, `error.types.ts` |

---

## ✅ What's Working Well

### 1. Centralized Error Handling
- The `globalErrorHandler.ts` provides a single point for handling all errors
- Consistent JSON response structure across all error types
- Stack traces are properly hidden in production mode

### 2. Custom Error Class
- `ApiError` class extends the native `Error` with `statusCode` support
- Proper stack trace capture using `Error.captureStackTrace`

### 3. Zod Integration
- Clean integration with Zod for request validation via `validateRequest.ts`
- Proper error extraction from Zod issues in `handleZodError.ts`

### 4. Socket Authentication
- Comprehensive socket authentication with role-based access control
- Proper token extraction supporting multiple formats (Bearer, JSON, query params)
- Dedicated error emission via `socket_error` event

---

## ⚠️ Issues Found

### 🔴 Critical Issues

#### 1. Duplicate/Incorrect Import in `globalErrorHandler.ts`
```typescript
// Line 5-7: Conflicting imports
import handleValidationError from '../../errors/handleZodError'  // ❌ Wrong import
import { ZodError } from 'zod'
import handleZodError from '../../errors/handleZodError'
```
**Problem**: `handleValidationError` is imported from `handleZodError.ts` instead of `handleValidationError.ts`

**Fix**: 
```typescript
import handleValidationError from '../../errors/handleValidationError'
import { ZodError } from 'zod'
import handleZodError from '../../errors/handleZodError'
```

---

#### 2. Typo in Error Message (`globalErrorHandler.ts`)
```typescript
// Line 22
let message = 'Something wen wrong!'  // ❌ Typo: "wen" should be "went"
```

**Fix**:
```typescript
let message = 'Something went wrong!'
```

---

#### 3. Wrong Condition Check for Validation Error (`globalErrorHandler.ts`)
```typescript
// Line 25
if (error?.name === 'validationError')  // ❌ Lowercase 'v'
```
**Problem**: Mongoose validation errors have the name `ValidationError` (capital V)

**Fix**:
```typescript
if (error?.name === 'ValidationError')
```

---

#### 4. Image Optimization Field Mismatch (`processReqBody.ts`)
```typescript
// Line 96 & 236
if (fieldName === 'image' && file.mimetype.startsWith('image/'))
```
**Problem**: The field is named `images` (plural) in `uploadFields` but checked as `image` (singular)

**Fix**:
```typescript
if (fieldName === 'images' && file.mimetype.startsWith('image/'))
```

---

### 🟡 Medium Issues

#### 5. Missing Mongoose Validation Error Handling (`globalErrorHandler.ts`)
The Mongoose `ValidationError` is checked but imports the wrong handler. Additionally, there's no explicit check for `mongoose.Error.ValidationError`.

**Recommendation**: Add proper Mongoose validation error type checking:
```typescript
import mongoose from 'mongoose'
// ...
if (error instanceof mongoose.Error.ValidationError) {
  const simplifiedError = handleValidationError(error)
  // ...
}
```

---

#### 6. Unused `generateRandomString` Function (`processReqBody.ts`)
```typescript
// Lines 136-140: Function is defined but never used
function generateRandomString(length: number = 9): string {
  return Math.random()
    .toString(36)
    .slice(2, 2 + length)
}
```

**Recommendation**: Remove if not needed, or use it where appropriate.

---

#### 7. `any` Type Usage in Socket Handlers (`socketAuth.ts`)
```typescript
// Line 136
function handleSocketError(socket: SocketWithUser, error: any): void
// Line 200
data: any
```

**Recommendation**: Use proper typing:
```typescript
function handleSocketError(socket: SocketWithUser, error: Error | ApiError): void
data: unknown
```

---

#### 8. Missing `else` Branch in Auth Middleware (`auth.ts`)
```typescript
// Lines 26-57: No else branch if token doesn't start with 'Bearer'
if (tokenWithBearer && tokenWithBearer.startsWith('Bearer')) {
  // ...
}
// What happens if token exists but doesn't start with 'Bearer'? Silent pass!
```

**Fix**: Add error handling for invalid token format:
```typescript
if (tokenWithBearer && tokenWithBearer.startsWith('Bearer')) {
  // ... existing code
} else if (tokenWithBearer) {
  throw new ApiError(StatusCodes.BAD_REQUEST, 'Invalid token format. Use Bearer token.')
}
```

---

### 🟢 Minor Issues

#### 9. Inconsistent Error Message Format
- `handleCastError.ts` returns `{ message: 'Cast Error', errorMessages: [...] }` with generic message
- `handleZodError.ts` returns `{ message: 'Validation Error', errorMessages: [...] }`

**Recommendation**: Consider returning the first error message as the main message for consistency:
```typescript
message: errors[0]?.message || 'Cast Error'
```

---

#### 10. Missing Return Type for `handleCastError` Function
```typescript
const handleCastError = (error: mongoose.Error.CastError) => {  // ❌ No return type
```

**Fix**:
```typescript
const handleCastError = (error: mongoose.Error.CastError): IGenericErrorResponse => {
```

---

#### 11. Misnamed File: `error.types.ts`
The file `src/interfaces/error.types.ts` contains `ISendEmail` type, which is unrelated to errors.

**Recommendation**: Rename to `email.types.ts` or move the type to an appropriate file.

---

## 📋 Recommendations Summary

| Priority | Issue | File | Line(s) |
|----------|-------|------|---------|
| 🔴 Critical | Wrong import for `handleValidationError` | `globalErrorHandler.ts` | 5 |
| 🔴 Critical | Typo in error message | `globalErrorHandler.ts` | 22 |
| 🔴 Critical | Wrong validation error name check | `globalErrorHandler.ts` | 25 |
| 🔴 Critical | Image field name mismatch | `processReqBody.ts` | 96, 236 |
| 🟡 Medium | Missing Mongoose type import | `globalErrorHandler.ts` | - |
| 🟡 Medium | Unused function | `processReqBody.ts` | 136-140 |
| 🟡 Medium | `any` type usage | `socketAuth.ts` | 136, 200 |
| 🟡 Medium | Missing else branch for invalid token | `auth.ts` | 26-57 |
| 🟢 Minor | Inconsistent error messages | `handleCastError.ts` | - |
| 🟢 Minor | Missing return type | `handleCastError.ts` | 4 |
| 🟢 Minor | Misnamed file | `error.types.ts` | - |

---

## 💡 Additional Suggestions

### 1. Add Error Code System
Consider adding unique error codes for easier debugging and client-side handling:
```typescript
class ApiError extends Error {
  statusCode: number
  errorCode: string  // e.g., 'AUTH_001', 'VALIDATION_002'
  
  constructor(statusCode: number, message: string, errorCode?: string, stack = '') {
    // ...
  }
}
```

### 2. Add Request ID Tracking
Include a request ID in error responses for easier log correlation:
```typescript
res.status(statusCode).json({
  success: false,
  requestId: req.headers['x-request-id'] || generateRequestId(),
  message: message,
  errorMessages,
  stack: config.node_env === 'production' ? undefined : error?.stack,
})
```

### 3. Consider Async Error Handling Wrapper
Create a utility to wrap async route handlers:
```typescript
export const asyncHandler = (fn: RequestHandler) => 
  (req: Request, res: Response, next: NextFunction) => 
    Promise.resolve(fn(req, res, next)).catch(next)
```

### 4. Add Error Logging
Consider integrating proper logging in the global error handler:
```typescript
import { logger } from '../../shared/logger'

// In globalErrorHandler
logger.error({
  message: error.message,
  stack: error.stack,
  statusCode,
  path: req.path,
  method: req.method,
})
```

---

## ✨ Overall Assessment

The error handling architecture follows good practices with centralized handling and consistent response structures. However, there are **4 critical issues** that should be fixed immediately to ensure proper error handling functionality. The remaining issues are improvements that would enhance code quality and maintainability.

**Priority Order for Fixes:**
1. Fix the `handleValidationError` import
2. Fix the validation error name check (`validationError` → `ValidationError`)
3. Fix the image field name mismatch
4. Fix the typo in error message
