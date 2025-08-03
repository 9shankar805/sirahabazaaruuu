#!/usr/bin/env node

/**
 * Database Connection Test Script
 * Tests connection to the specified PostgreSQL database
 */

import { Pool } from 'pg';

// Your database URL - using postgres database
const DATABASE_URL = "postgresql://mydreamv50:123456@139.59.19.202:5432/postgres";

async function testDatabaseConnection() {
  console.log('🔍 Testing database connection...');
  console.log('📍 Database URL:', DATABASE_URL.replace(/:[^:]*@/, ':****@')); // Hide password
  
  const pool = new Pool({ 
    connectionString: DATABASE_URL,
    ssl: false, // Try without SSL first
    connectionTimeoutMillis: 10000, // 10 second timeout
  });

  try {
    console.log('⚡ Attempting to connect...');
    const client = await pool.connect();
    
    console.log('✅ Database connection successful!');
    
    // Test basic query
    const result = await client.query('SELECT version()');
    console.log('📊 PostgreSQL Version:', result.rows[0].version.substring(0, 80) + '...');
    
    // Check if tables exist
    const tablesResult = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);
    
    console.log(`📋 Found ${tablesResult.rows.length} existing tables:`, 
      tablesResult.rows.map(row => row.table_name).join(', '));
    
    client.release();
    await pool.end();
    
    console.log('🎉 Connection test completed successfully!');
    
  } catch (error) {
    console.error('❌ Database connection failed:');
    console.error('   Error type:', error.code || 'UNKNOWN');
    console.error('   Message:', error.message);
    
    if (error.code === 'EHOSTUNREACH') {
      console.log('💡 Suggestions:');
      console.log('   • Check if the database server is running');
      console.log('   • Verify firewall settings allow connections on port 5432');
      console.log('   • Ensure the IP address 139.59.19.202 is correct');
      console.log('   • Check if your hosting environment allows external database connections');
    } else if (error.code === 'ECONNREFUSED') {
      console.log('💡 The server refused the connection - check if PostgreSQL is running on port 5432');
    } else if (error.code === '28P01') {
      console.log('💡 Authentication failed - check username and password');
    }
    
    await pool.end();
  }
}

// Run the test
testDatabaseConnection().catch(console.error);