/**
 * Fix Missing Firebase UID Column
 * Adds the firebase_uid column to the users table if it doesn't exist
 */

import { Pool } from 'pg';
import 'dotenv/config';

async function fixFirebaseUidColumn() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });

  try {
    console.log('🔧 Checking users table structure...');
    
    // Check if firebase_uid column exists
    const checkColumn = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'users' AND column_name = 'firebase_uid'
    `);

    if (checkColumn.rows.length === 0) {
      console.log('❌ firebase_uid column missing. Adding it now...');
      
      // Add the firebase_uid column
      await pool.query(`
        ALTER TABLE users 
        ADD COLUMN firebase_uid TEXT UNIQUE
      `);
      
      console.log('✅ Successfully added firebase_uid column to users table');
    } else {
      console.log('✅ firebase_uid column already exists');
    }

    // Show current table structure
    console.log('\n📋 Current users table structure:');
    const tableStructure = await pool.query(`
      SELECT column_name, data_type, is_nullable, column_default
      FROM information_schema.columns 
      WHERE table_name = 'users'
      ORDER BY ordinal_position
    `);

    tableStructure.rows.forEach(row => {
      console.log(`  - ${row.column_name}: ${row.data_type}${row.is_nullable === 'NO' ? ' NOT NULL' : ''}${row.column_default ? ` DEFAULT ${row.column_default}` : ''}`);
    });

  } catch (error) {
    console.error('❌ Error fixing firebase_uid column:', error);
    throw error;
  } finally {
    await pool.end();
  }
}

// Run the fix
fixFirebaseUidColumn()
  .then(() => {
    console.log('\n🎉 Database fix completed successfully!');
    process.exit(0);
  })
  .catch(error => {
    console.error('💥 Database fix failed:', error);
    process.exit(1);
  });