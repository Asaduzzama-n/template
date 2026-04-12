# Express Craft: The Ultimate Enterprise Backend Template 🚀

Welcome to **Express Craft**, a meticulously designed, enterprise-grade boilerplate for Node.js and TypeScript. This repository is not just a collection of files; it is a battle-tested architecture designed to handle high-concurrency workloads, secure data management, and rapid feature iteration. This template is designed for developers who need to move from 'Zero to Production' without sacrificing code quality, security, or performance. Every decision made in this template—from the folder structure to the choice of secondary languages—is aimed at solving real-world production scaling issues.

---

## 🏛️ Comprehensive Architecture & Philosophy

The core philosophy behind Express Craft is **Decoupling and Performance Isolation**. Traditional Express.js templates often suffer from "Monolithic Bloat," where the main API server handles everything from database queries to complex image processing and heavy disk I/O. As your user base grows, this single-threaded nature of Node.js becomes a significant bottleneck. When a server is busy resizing a 10MB image or writing a large file to a slow hard drive, its ability to respond to simple API requests for other users drops significantly. 

### Why RustFS?
In Express Craft, we have fundamentally solved the "I/O Wait" problem by integrating **RustFS**. Unlike local filesystem uploads that block the event loop, every file upload in this template is optimized on-the-fly using the high-performance `sharp` library and then immediately streamed to a dedicated Rust-based storage service. Rust is a language designed for extreme memory safety and performance, often performing on par with C++. By offloading image management to a separate RustFS container, your main Node.js application remains "Lightweight and Stateless." 

This architectural decision means that your API can handle thousands of simultaneous requests while the heavy binary processing and disk management happen in a secondary, isolated environment. This design also facilitates easier horizontal scaling; you can spin up 10 instances of your Node.js API server, and they can all communicate with a single, high-speed RustFS cluster. You never have to worry about syncing local `uploads/` folders across different servers or saturating your server's primary disk bandwidth with static file requests. This is the same logic used by global platforms to ensure that file management never impacts API responsiveness.

### The Power of Redis
We utilize **Redis** not just as a simple cache, but as the high-speed backbone of our entire infrastructure. It serves as a real-time message broker for Socket.IO scaling and handles our distributed background tasks. This ensures that even if you have multiple instances of your app running, your real-time notifications, chat messages, and background workers stay perfectly synchronized across the entire cluster. By using Redis as a shared state, we ensure that no matter which server instance a user is connected to, they receive their data instantly and accurately.

---

## 🚀 Full Dockerization & Deployment Workflow

This project is built to be "Environment Agnostic." Whether you are running on a local development machine, a staging server, or a multi-cloud Kubernetes cluster, the application's behavior remains identical thanks to our sophisticated Docker configuration. Dockerization isn't just about "making it run anywhere"; it's about defining the exact OS environment, system libraries (like `libvips` for image processing), and service dependencies that your code requires to function optimally.

### The Multi-Stage Build Strategy
Our **Dockerfile** utilizes a **multi-stage build** strategy, which is the industry standard for creating secure and efficient production images. 
1.  **Stage 1 (The Builder)**: We start with a full Node.js environment that includes all the heavy compilers and build tools (like `python3`, `make`, and `g++`). This layer is used to install all development dependencies, transpile your TypeScript code into clean JavaScript, and compile native C++ modules required for high-performance tasks.
2.  **Stage 2 (The Runner)**: Once the build is complete, we discard the entire builder layer. We move ONLY the production-ready JavaScript code and the minimal set of production dependencies into a fresh, slim Alpine Linux image. 

This strategy reduces your final image size from potentially 1.5GB down to less than 200MB. This not only saves expensive storage in your container registry but also makes your deployments significantly faster. More importantly, it enhances security: by removing compilers, shell tools, and dev-dependencies from the production image, you drastically reduce the "attack surface" available to a potential hacker who manages to gain entry to the container.

### Running the Full Stack with Orchestration
To launch every component of the ecosystem (The App, MongoDB, Redis, and RustFS) with a single command, use:
```bash
docker-compose up --build -d
```
The `-d` flag runs the containers in "detached" mode, meaning they run in the background while keeping your terminal free for other tasks. This command automatically sets up the internal Docker network, allowing the containers to talk to each other using their service names (like `mongodb` or `rustfs`) instead of fragile IP addresses. If you make changes to the source code, simply run the command again, and Docker will intelligently rebuild only the parts that have changed, saving you time during development.

---

## 🛡️ Enterprise-Grade Security & Authentication

Security is not an "add-on" in Express Craft; it is woven into the very fabric of every route, middleware, and service. We follow the **OWASP Top 10** guidelines and the principle of **Least Privilege** to ensure your application is protected against common vulnerabilities from the very first line of code.

### Hybrid JWT & Session Management
We implement a **Hybrid JWT Strategy** to provide a secure and seamless user experience. Many boilerplates use simple, long-lived tokens that are difficult to revoke. In Express Craft, we use:
-   **Short-lived Access Tokens**: These expire in minutes and are used for stateless, lightning-fast authorization checking. They are never stored in the database, reducing database load on every request.
-   **Long-lived, Rotatable Refresh Tokens**: These are stored securely and are used to obtain new access tokens. Because they are tracked, you can implement a "Log out from all devices" feature or revoke access immediately if a user's account is compromised.

### The Defensive Middleware Stack
Every incoming request must pass through a multi-layered security gate before it even touches your business logic:
-   **Helmet.js**: Automatically sets over 15 critical HTTP headers (including `Content-Security-Policy`, `X-Frame-Options`, and `Strict-Transport-Security`) to prevent Cross-Site Scripting (XSS), Clickjacking, and protocol-based attacks.
-   **Rate Limiting**: Our integrated `express-rate-limit` middleware prevents Brute-Force attacks on your login endpoints and mitigates Denial of Service (DoS) attempts by limiting how many requests a single IP can make within a specific window.
-   **Zod Schema Validation**: We operate on a "Trust No One" basis for user input. Every API request is strictly validated against a Zod schema. If the data is missing a field, has the wrong type, or fails a regex check (like an email or password format), the request is rejected with a clear, machine-readable 400 Bad Request error.
-   **Config Integrity**: Our application uses a validated `config` module. If a critical environment variable (like a JWT secret or DB URL) is missing or malformed, the app will throw an error and refuse to start, preventing "Silent Failures" that could lead to security holes in production.

---

## 🏗️ Domain-Driven Module Development

Express Craft follows a **Domain-Driven Design (DDD)** inspired modular pattern. Instead of splitting your application by technical type (putting all controllers in one folder and all models in another), we group everything by its **Business Domain**. This structure is what allows a codebase to remain manageable even when it grows to hundreds of thousands of lines of code.

### Anatomy of a Module
When you look into `src/app/modules`, you will see folders like `user`, `auth`, or `payment`. Each of these is a self-contained feature that can be easily understood, tested, or even moved to a separate microservice in the future. A standard module contains:
1.  **`routes.ts`**: The entry point that defines the API surface for the domain.
2.  **`controller.ts`**: The bridge between HTTP and your code; it extracts data from the request and sends the standardized response.
3.  **`service.ts`**: The "Brain" of the module. This is where your business logic lives, where you interact with the database, and where you orchestrate other services.
4.  **`validation.ts`**: The Zod schemas that protect your functions from invalid data.
5.  **`interface.ts`**: The TypeScript definitions that ensure type-safety across your entire application.

### Speeding up Development with Generators
To eliminate "Copy-Paste Errors" and speed up your workflow, we have pre-configured the `@asad_dev/leo-generator`. Instead of manually creating five new files every time you want to add a feature, you can use the generator to scaffold the entire module structure in a single second. This ensures that every developer on your team—whether they joined yesterday or a year ago—follows the exact same architectural patterns. Consistent code is maintainable code.

---

## 📈 Operational Management & Maintenance Commands

A production-ready application is only as good as its management tools. Express Craft provides a comprehensive suite of CLI commands to help you monitor, debug, and maintain your infrastructure.

### Intelligent Logging & Monitoring
Monitoring your infrastructure is critical for identifying performance regressions and security incidents. You can view logs for specific services or the entire stack with fine-grained control:
```bash
# View all logs with real-time streaming and timestamps
docker-compose logs -f -t

# Isolate only the application logic logs to debug a specific route
docker-compose logs -f app

# Monitor background infrastructure like MongoDB or Redis
docker-compose logs -f mongodb
docker-compose logs -f redis
```

### Database Persistence & Shell Access
Your data is stored securely in **Docker Named Volumes**. This ensures that shutting down your computer or restarting the containers will NEVER result in data loss. The data lives on your host machine but is managed by Docker.
```bash
# Gracefully stop the entire stack while KEEPING all data
docker-compose down

# Stop the stack and PRUNE all data (Used for resetting the environment)
docker-compose down -v

# Open an interactive shell directly inside the MongoDB container
docker exec -it mongodb_db mongosh
```

### Cache & Storage Maintenance
Because the app is dockerized, you can interact with the supporting services without installing their CLI tools on your main OS:
```bash
# Access the Redis CLI to inspect cached sessions or clear temporary data
docker exec -it redis_cache redis-cli

# Rebuild the Docker image from scratch (Use after updating package.json)
docker-compose build --no-cache
```

---

## 📚 API Endpoints Reference

Express Craft comes with a pre-built set of core endpoints to get you started. All endpoints return standardized JSON responses.

### 🔑 Authentication Module
- **`POST /api/v1/auth/register`**: Handles user onboarding and triggers the email/verification workflow.
- **`POST /api/v1/auth/login`**: The primary entry point; validates credentials and returns the Access & Refresh token pair.
- **`POST /api/v1/auth/refresh-token`**: Extends the user's session by exchanging a valid Refresh Token for a new Access Token.
- **`POST /api/v1/auth/change-password`**: Securely updates the user's password with old-password verification.

### 👤 User & Profile Module
- **`GET /api/v1/user/profile`**: Returns the sanitized profile data for the currently authenticated user.
- **`PATCH /api/v1/user/profile`**: Updates profile information. **Crucially, this endpoint is integrated with our RustFS middleware, allowing you to upload avatars or identity documents that are processed and stored in your dedicated Rust storage server.**

---

## 🤝 Contributing & Support

We believe in the power of open-source collaboration. If you encounter a bug, have a suggestion for an enterprise-level feature, or want to contribute to the performance optimizations, please feel free to open an issue or submit a pull request. This template is a living project, designed to evolve alongside the latest security standards and performance benchmarks.

**Maintained by**: Asaduzzaman
**License**: MIT License
**Support**: Use the GitHub Issues tab for bug reports or architectural questions.

---
*Generated with ❤️ for developers who demand the best in performance, security, and scalability.*