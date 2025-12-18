# Deployment Guide

Step-by-step guide for deploying Express-Craft to production.

## Prerequisites

- Docker and Docker Compose installed
- Domain name with DNS configured
- Server with at least 2GB RAM
- MongoDB database (self-hosted or Atlas)

---

## Quick Start (Local Development)

```bash
# 1. Clone the repository
git clone https://github.com/your-org/express-craft.git
cd express-craft

# 2. Copy environment file
cp .example.env .env

# 3. Edit .env with your configuration
nano .env

# 4. Start development stack
docker compose -f docker-compose.dev.yml up -d

# 5. Check logs
docker compose -f docker-compose.dev.yml logs -f

# 6. Access the application
curl http://localhost/health
```

---

## Production Deployment

### Step 1: Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Create application directory
sudo mkdir -p /opt/app
sudo chown $USER:$USER /opt/app
```

### Step 2: Clone Repository

```bash
cd /opt/app
git clone https://github.com/your-org/express-craft.git .
```

### Step 3: Configure Environment

```bash
# Copy and edit environment file
cp .example.env .env
nano .env
```

**Required Environment Variables:**
```env
# CRITICAL - Change these!
NODE_ENV=production
DATABASE_URL=mongodb+srv://user:password@cluster.mongodb.net/dbname
JWT_SECRET=generate-a-64-character-random-string
JWT_REFRESH_SECRET=generate-another-64-character-string
REDIS_PASSWORD=strong-redis-password

# Email configuration
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_USER=apikey
EMAIL_PASS=your-sendgrid-api-key
EMAIL_FROM=noreply@yourdomain.com

# CORS
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

**Generate secure secrets:**
```bash
# Generate JWT secrets
openssl rand -hex 32
openssl rand -hex 32

# Generate Redis password
openssl rand -base64 24
```

### Step 4: SSL Certificate Setup

```bash
# Create SSL directory
mkdir -p nginx/ssl

# Start nginx temporarily for ACME challenge
docker compose up -d nginx

# Get SSL certificate
docker compose run --rm certbot certonly \
  --webroot \
  --webroot-path=/var/www/certbot \
  --email your@email.com \
  --agree-tos \
  --no-eff-email \
  -d yourdomain.com \
  -d www.yourdomain.com

# Restart nginx with SSL
docker compose restart nginx
```

### Step 5: Deploy Application

```bash
# Build and start all services
docker compose up -d --build

# Check status
docker compose ps

# View logs
docker compose logs -f
```

### Step 6: Verify Deployment

```bash
# Health check
curl https://yourdomain.com/health

# Ready check
curl https://yourdomain.com/ready

# Redis health
curl https://yourdomain.com/api/v1/cache/redis/health
```

---

## Automated Deployment with CI/CD

### GitHub Actions Setup

1. **Add GitHub Secrets** (Settings → Secrets → Actions):

| Secret | Value |
|--------|-------|
| `SSH_HOST` | Your server IP |
| `SSH_USER` | `deploy` or your user |
| `SSH_PRIVATE_KEY` | Your SSH private key |
| `SSH_PORT` | `22` (or custom port) |
| `DEPLOY_PATH` | `/opt/app` |
| `APP_URL` | `https://yourdomain.com` |

2. **Set up SSH key on server:**

```bash
# On your local machine
ssh-keygen -t ed25519 -C "github-actions-deploy"

# Copy public key to server
ssh-copy-id -i ~/.ssh/id_ed25519.pub deploy@your-server

# Add private key to GitHub Secrets as SSH_PRIVATE_KEY
cat ~/.ssh/id_ed25519
```

3. **Push to deploy:**

```bash
git push origin main
```

---

## Scaling

### Horizontal Scaling with PM2 (Default)

PM2 is configured to use cluster mode by default:

```javascript
// ecosystem.config.js
{
  instances: 'max',  // Uses all CPU cores
  exec_mode: 'cluster',
}
```

### Horizontal Scaling with Docker Compose

If you need more control:

```bash
# Scale to 3 instances
docker compose up -d --scale app=3

# Update nginx upstream (nginx/nginx.conf)
upstream app_servers {
    server app_1:5000;
    server app_2:5000;
    server app_3:5000;
}
```

### Vertical Scaling

Adjust container resources in `docker-compose.yml`:

```yaml
services:
  app:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
```

---

## Monitoring

### PM2 Monitoring

```bash
# Inside container
docker compose exec app pm2 status
docker compose exec app pm2 logs
docker compose exec app pm2 monit
```

### Log Aggregation

Logs are stored in:
- `./logs/pm2/out.log` - Application output
- `./logs/pm2/error.log` - Error logs
- `./logs/winston/combined/` - All logs (JSON)
- `./logs/winston/errors/` - Error logs (JSON)

For production, consider:
- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Datadog**
- **AWS CloudWatch**
- **Grafana + Loki**

### Cache Monitoring

```bash
# Get cache stats
curl -H "Authorization: Bearer <admin-token>" \
  https://yourdomain.com/api/v1/cache/stats
```

---

## Backup & Recovery

### Database Backup

```bash
# MongoDB backup (if using Docker)
docker compose exec mongodb mongodump --out /backup

# MongoDB Atlas - Use built-in backup
```

### Redis Backup

Redis is configured with AOF persistence. Data is stored in the `redis-data` volume.

```bash
# Manual backup
docker compose exec redis redis-cli BGSAVE
```

---

## Troubleshooting

### Common Issues

#### 1. Container won't start
```bash
# Check logs
docker compose logs app

# Common fix: check environment variables
docker compose config
```

#### 2. Redis connection refused
```bash
# Check Redis health
docker compose exec redis redis-cli ping

# Check Redis password
docker compose exec redis redis-cli -a <password> ping
```

#### 3. MongoDB connection timeout
```bash
# Check if it's a network issue
docker compose exec app ping mongodb-host

# Check connection string format
# mongodb+srv://user:password@cluster/dbname?retryWrites=true
```

#### 4. SSL certificate issues
```bash
# Check certificate
docker compose exec nginx nginx -t

# Renew certificate
docker compose run --rm certbot renew
docker compose restart nginx
```

### Container Access

```bash
# Shell into app container
docker compose exec app sh

# Shell into nginx
docker compose exec nginx sh

# Redis CLI
docker compose exec redis redis-cli -a <password>
```

### Reset Everything

```bash
# Stop all containers
docker compose down

# Remove volumes (DATA LOSS!)
docker compose down -v

# Rebuild and start
docker compose up -d --build
```

---

## Security Checklist

Before going live, verify:

- [ ] All secrets are strong and unique
- [ ] SSL is properly configured
- [ ] CORS is restricted to your domains
- [ ] Rate limiting is enabled
- [ ] MongoDB requires authentication
- [ ] Redis requires password
- [ ] Admin endpoint is protected
- [ ] Logs don't contain sensitive data
- [ ] Error messages don't leak internal details
- [ ] File uploads have size limits
- [ ] Server firewall is configured (only 80, 443 open)
