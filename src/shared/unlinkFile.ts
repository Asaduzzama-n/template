import fs from 'fs/promises'
import path from 'path'

const unlinkFile = async (file: string): Promise<void> => {
  const filePath = path.join('uploads', file)
  try {
    await fs.unlink(filePath)
  } catch {
    // File doesn't exist - ignore
  }
}

export default unlinkFile
