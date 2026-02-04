import mongoose from 'mongoose'
import config from '../../../config'
import { UserServices } from './user.service'
import { logger } from '../../../shared/logger'
import colors from 'colors'

const seedAdmin = async () => {
    try {
        // Connect to database
        await mongoose.connect(config.database.url as string)
        logger.info(colors.green('🚀 Database connected for seeding'))

        // Run seeding
        logger.info(colors.yellow('🌱 Seeding admin account...'))
        await UserServices.createAdmin()
        logger.info(colors.green('✅ Admin seeded successfully!'))

    } catch (error) {
        logger.error(colors.red('❌ Seeding failed:'), error)
    } finally {
        // Close connection
        await mongoose.connection.close()
        logger.info(colors.blue('🔌 Database connection closed'))
        process.exit(0)
    }
}

seedAdmin()
