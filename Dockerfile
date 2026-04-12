# --- Build Stage ---
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies (needed for sharp/canvas if necessary)
RUN apk add --no-cache libc6-compat python3 make g++

# Copy package files
COPY package.json yarn.lock* package-lock.json* ./

# Install ALL dependencies
RUN npm install

# Copy source code
COPY . .

# Build the project (compile TypeScript)
RUN npm run build

# --- Production Stage ---
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# Copy necessary files from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./package.json

# Copy yarn.lock or package-lock.json
COPY --from=builder /app/package-lock.json* /app/yarn.lock* ./

# Install ONLY production dependencies
RUN npm install --omit=dev

# Create a non-root user for security
RUN addgroup -S nodejs && adduser -S nextjs -G nodejs
USER nextjs

EXPOSE 5000

CMD ["node", "dist/server.js"]
