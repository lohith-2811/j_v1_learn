import { createClient } from '@libsql/client';
import dotenv from 'dotenv';

dotenv.config();

const db = createClient({
  url: process.env.DATABASE_URL,
  authToken: process.env.DATABASE_AUTH_TOKEN,
});

export async function initDB() {
  try {
    await db.batch([
      {
        sql: `
          CREATE TABLE IF NOT EXISTS user_profiles (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            is_verified BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at INTEGER
          )
        `,
      },
      {
        sql: `
          CREATE TABLE IF NOT EXISTS user_module_progress (
            user_id INTEGER,
            language VARCHAR(50),
            level INTEGER,
            module_id INTEGER,
            completion_mask BIGINT DEFAULT 0,
            current_lesson_id INTEGER DEFAULT 1,
            current_question_index INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, language, level, module_id),
            FOREIGN KEY (user_id) REFERENCES user_profiles(user_id) ON DELETE CASCADE
          )
        `,
      },
      {
        sql: `
          CREATE TABLE IF NOT EXISTS user_achievements (
            user_id INTEGER PRIMARY KEY,
            xp_points INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES user_profiles(user_id) ON DELETE CASCADE
          )
        `,
      },
      {
        sql: `
          CREATE TABLE IF NOT EXISTS lesson_details (
            language VARCHAR(50),
            level INTEGER,
            module_id INTEGER,
            total_lessons INTEGER,
            PRIMARY KEY (language, level, module_id)
          )
        `,
      },
      {
        sql: `
          CREATE TABLE IF NOT EXISTS user_otp_verification (
            email VARCHAR(255) PRIMARY KEY,
            otp VARCHAR(6) NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        `,
      }
    ]);

    // Apply the ALTER TABLE to add is_verified if it doesn't exist
    await db.execute(`
      ALTER TABLE user_profiles ADD COLUMN is_verified BOOLEAN DEFAULT 0;
    `).catch(err => {
      if (!err.message.includes('duplicate column name')) {
        throw err;
      }
    });

    // Apply the ALTER TABLE to add expires_at if it doesn't exist
    await db.execute(`
      ALTER TABLE user_profiles ADD COLUMN expires_at INTEGER;
    `).catch(err => {
      if (!err.message.includes('duplicate column name')) {
        throw err;
      }
    });

    console.log('Database tables created successfully');
  } catch (err) {
    console.error('Failed to create database tables:', err);
    throw err;
  }
}

export function getDB() {
  return db;
}
