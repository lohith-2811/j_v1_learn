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
            password_hash VARCHAR(255),
            is_google_auth BOOLEAN DEFAULT 0,
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
      },
      {
        sql: `
          CREATE TABLE IF NOT EXISTS user_switched_course (
            user_id INTEGER PRIMARY KEY,
            course_id TEXT NOT NULL,
            language TEXT NOT NULL,
            level INTEGER NOT NULL,
            switched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user_profiles(user_id) ON DELETE CASCADE
          )
        `,
      },
      {
        sql: `
          CREATE TABLE IF NOT EXISTS stock (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            voucher_name VARCHAR(255) NOT NULL,
            voucher_code VARCHAR(50) NOT NULL UNIQUE,
            expire_date INTEGER NOT NULL,
            points_price INTEGER NOT NULL
          )
        `,
      },
      {
        sql: `
          CREATE TABLE IF NOT EXISTS user_vouchers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            voucher_name VARCHAR(255) NOT NULL,
            voucher_code VARCHAR(50) NOT NULL UNIQUE,
            redeemed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expire_date INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES user_profiles(user_id) ON DELETE CASCADE
          )
        `,
      }
    ]);

    // Apply the ALTER TABLE to add is_verified if it doesn't exist
    await db.execute(`
      ALTER TABLE user_profiles ADD COLUMN is_verified BOOLEAN DEFAULT 0;
    `).catch(err => {
      // Ignore error if column already exists
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
