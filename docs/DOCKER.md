# Docker Setup Guide

Complete guide for running the Express-Craft server using Docker.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Local Development (Hot Reload)](#local-development-hot-reload)
- [Production Deployment](#production-deployment)
- [Environment Configuration](#environment-configuration)
- [Common Commands](#common-commands)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| Docker | 20.10+ | Container runtime |
| Docker Compose | 2.0+ | Multi-container orchestration |
| Git | Any | Clone repository |

### Install Docker (Windows)

1. Download [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/)
2. Run the installer and enable WSL 2 backend
3. Restart your computer
4. Verify: `docker --version && docker compose version`

### Install Docker (Linux/Ubuntu)

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in
docker --version
```

---

## Local Development (Hot Reload)

> **🔥 Hot Reload Enabled!** The development setup mounts your source code and runs `ts-node-dev`. File changes automatically restart the server - no rebuild needed!

### Step 1: Setup Environment

```bash
git clone https://github.com/your-org/express-craft.git
cd express-craft
cp .example.env .env
# Edit .env with your settings
```

### Step 2: Configure `.env`

```env
NODE_ENV=development
PORT=5000
# DATABASE_URL now uses the internal 'mongodb' service name
DATABASE_URL=mongodb://mongodb:27017/template
REDIS_URL=redis://redis:6379
JWT_SECRET=your-dev-jwt-secret-key-min-32-chars
JWT_REFRESH_SECRET=your-dev-refresh-secret-key-min-32-chars
LOG_LEVEL=debug
```

### Step 3: Start Development

```bash
# Start with hot reload (app, redis, and mongodb)
docker compose -f docker-compose.dev.yml up

# Or run in background
docker compose -f docker-compose.dev.yml up -d
docker compose -f docker-compose.dev.yml logs -f app
```

### Step 4: Develop

- Edit any `.ts` file in `src/`
- Server **automatically restarts**
- Access at `http://localhost:5000`
- MongoDB is available on `localhost:27017` from your host machine.

### Step 5: Stop

```bash
docker compose -f docker-compose.dev.yml down
```

---

## Development vs Production

| Feature | Dev (`docker-compose.dev.yml`) | Prod (`docker-compose.yml`) |
|---------|--------------------------------|-----------------------------|
| Hot Reload | ✅ Live file watching | ❌ Compiled JS |
| Source | Mounted from host | Copied during build |
| Rebuild | ❌ Not needed | ✅ Required (`--build`) |
| Nginx | ❌ Not included | ✅ SSL + reverse proxy |
| Performance | Slower (TypeScript) | Faster (compiled) |
| Use Case | Active development | Production deployment |

---

## Production Deployment

### Step 1: Server Setup

```bash
sudo apt update && sudo apt upgrade -y
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
sudo mkdir -p /opt/app && cd /opt/app
git clone https://github.com/your-org/express-craft.git .
```

### Step 2: Configure Environment

```bash
cp .example.env .env
nano .env
```

```env
NODE_ENV=production
DATABASE_URL=mongodb+srv://user:password@cluster.mongodb.net/db
JWT_SECRET=your-64-char-production-secret
JWT_REFRESH_SECRET=another-64-char-secret
REDIS_PASSWORD=strong-redis-password
ALLOWED_ORIGINS=https://yourdomain.com
```

> Generate secrets: `openssl rand -hex 32`

### Step 3: SSL Setup

```bash
mkdir -p nginx/ssl
docker compose up -d nginx
docker compose run --rm certbot certonly \
  --webroot --webroot-path=/var/www/certbot \
  --email your@email.com --agree-tos \
  -d yourdomain.com -d www.yourdomain.com
```

### Step 4: Deploy

```bash
docker compose up -d --build
docker compose logs -f
```

---

## Common Commands

### Development

```bash
# Start (hot reload)
docker compose -f docker-compose.dev.yml up

# Background
docker compose -f docker-compose.dev.yml up -d

# Logs
docker compose -f docker-compose.dev.yml logs -f app

# Stop
docker compose -f docker-compose.dev.yml down
```

### Production

```bash
# Build and start
docker compose up -d --build

# Logs
docker compose logs -f

# Stop
docker compose down
```

---

## Troubleshooting

### Port 6379 Already in Use

You have Redis running locally. Stop it first:
```bash
# Windows
taskkill /F /IM redis-server.exe

# Or change port in docker-compose.dev.yml
ports:
  - "6380:6379"  # Use 6380 on host
```

### BullMQ Redis Error

**Error:** `maxRetriesPerRequest must be null`

**Status:** ✅ Fixed. The Redis adapter uses separate connections for general ops and BullMQ.

### Module Not Found

Ensure `@socket.io/redis-adapter` and `ioredis` are in `dependencies` (not devDependencies).

### Reset Everything

```bash
docker compose -f docker-compose.dev.yml down -v
docker system prune -af
docker compose -f docker-compose.dev.yml up
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Dev start | `docker compose -f docker-compose.dev.yml up` |
| Dev stop | `docker compose -f docker-compose.dev.yml down` |
| Prod start | `docker compose up -d --build` |
| Prod stop | `docker compose down` |
| View logs | `docker compose logs -f app` |
| Shell | `docker compose exec app sh` |
