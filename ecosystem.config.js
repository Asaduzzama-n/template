module.exports = {
    apps: [
        {
            name: 'express-craft',
            script: './dist/server.js',
            instances: 'max', // Use all available CPUs
            exec_mode: 'cluster', // Enable cluster mode for horizontal scaling
            autorestart: true,
            watch: false,
            max_memory_restart: '1G',

            // Environment variables for production
            env_production: {
                NODE_ENV: 'production',
                PORT: 5000,
            },

            // Environment variables for development
            env_development: {
                NODE_ENV: 'development',
                PORT: 5000,
            },

            // Logging
            log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
            error_file: './logs/pm2/error.log',
            out_file: './logs/pm2/out.log',
            merge_logs: true,

            // Graceful shutdown
            kill_timeout: 5000, // Time to wait before forcing kill
            wait_ready: true, // Wait for process.send('ready')
            listen_timeout: 10000,

            // Restart settings
            max_restarts: 10,
            min_uptime: '10s',
            restart_delay: 4000,

            // Source maps for error tracking
            source_map_support: true,
        },
    ],
}
