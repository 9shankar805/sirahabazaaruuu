#!/usr/bin/env node

/**
 * Quick Database Connection Test
 * Tests if your database is accessible and shows basic info
 */

import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is required');
  console.log('💡 Make sure your .env file has the correct DATABASE_URL');
  process.exit(1);
}

async function testConnection() {
  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: DATABASE_URL.includes('sslmode=require') ? { rejectUnauthorized: false } : false,
    connectionTimeoutMillis: 5000
  });

  try {
    console.log('🔌 Testing database connection...');
    
    const client = await pool.connect();
    console.log('✅ Connected successfully!');
    
    // Basic info
    const result = await client.query('SELECT NOW() as time, version() as version');
    console.log('⏰ Current time:', result.rows[0].time);
    console.log('🗄️  Database:', result.rows[0].version.split(' ')[0]);
    
    // Count tables
    const tables = await client.query(`
      SELECT COUNT(*) as table_count 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    console.log('📋 Total tables:', tables.rows[0].table_count);
    
    client.release();
    
    console.log('\n✅ Your database is ready!');
    console.log('🚀 Next step: Run the migration analysis');
    console.log('   node safe-database-migration.js');
    
  } catch (error) {
    console.error('❌ Connection failed:', error.message);
    console.log('\n💡 Troubleshooting:');
    console.log('   1. Check your DATABASE_URL in .env file');
    console.log('   2. Ensure database server is running');
    console.log('   3. Check network connectivity');
    console.log('   4. Verify credentials are correct');
  } finally {
    await pool.end();
  }
}

testConnection();