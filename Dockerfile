FROM node:20-alpine

# Install build dependencies for native modules (bcrypt, sharp, etc.)
RUN apk add --no-cache python3 make g++ libc6-compat

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install ALL dependencies
RUN npm install

# Copy the rest of the code
COPY . .

# Expose the application port
EXPOSE 5000

# Run in development mode
CMD ["npm", "run", "dev"]
