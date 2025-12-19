# Build stage
FROM node:lts-alpine AS builder

WORKDIR /app

# Update npm to latest version
RUN npm install -g npm@latest

# Copy package files
COPY package*.json ./

# Install all dependencies (including devDependencies for build)
RUN npm ci

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Production stage
FROM node:lts-alpine AS production

WORKDIR /app

# Update npm to latest version
RUN npm install -g npm@latest

# Copy package files
COPY package*.json ./

# Install production dependencies only (skip prepare script which requires husky)
RUN npm ci --omit=dev --ignore-scripts

# Copy built files from builder stage
COPY --from=builder /app/dist ./dist

# Create uploads and logs directories with proper ownership
# Note: COPY doesn't support optional files, so we create dirs and copy via volume mounts
RUN mkdir -p uploads logs && chown -R node:node uploads logs

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

# Start Node directly (Docker handles restarts and process management)
CMD ["node", "dist/server.js"]

# =============================================================================
# PM2 NOTES (commented out - not needed with Docker)
# =============================================================================
# PM2 is redundant when using Docker because:
# - Docker handles process restarts via restart policies
# - For multi-core scaling, use: docker compose up --scale app=3
# - Docker orchestrators (Swarm, K8s) handle load balancing
#
# If you prefer PM2 for cluster mode within a single container:
# 1. Uncomment the PM2 setup below
# 2. Comment out the CMD ["node", "dist/server.js"] line above
#
# --- PM2 Setup (uncomment if needed) ---
# RUN npm install -g pm2
# COPY ecosystem.config.js ./
# CMD ["pm2-runtime", "start", "ecosystem.config.js"]
