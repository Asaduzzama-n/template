# Build stage
FROM node:22-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies (including devDependencies for build)
RUN npm ci

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Production stage
FROM node:22-alpine AS production

WORKDIR /app

# Install PM2 globally
RUN npm install -g pm2

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production

# Copy built files from builder stage
COPY --from=builder /app/dist ./dist

# Copy PM2 ecosystem config
COPY ecosystem.config.js ./

# Copy uploads directory if it exists
COPY --chown=node:node uploads ./uploads 2>/dev/null || true

# Create logs directory
RUN mkdir -p logs && chown -R node:node logs

# Set environment variables
ENV NODE_ENV=production
ENV PORT=5000

# Use non-root user for security
USER node

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5000/health || exit 1

# Start with PM2
CMD ["pm2-runtime", "start", "ecosystem.config.js"]
