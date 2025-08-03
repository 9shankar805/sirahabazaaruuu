#!/usr/bin/env node

/**
 * Check Available Databases Script
 * Lists all databases on the PostgreSQL server
 */

import { Pool } from 'pg';

// Connect to PostgreSQL server (default postgres database)
const SERVER_URL = "postgresql://mydreamv50:123456@139.59.19.202:5432/postgres";

async function checkAvailableDatabases() {
  console.log('🔍 Checking available databases...');
  
  const pool = new Pool({ 
    connectionString: SERVER_URL,
    ssl: false,
    connectionTimeoutMillis: 10000,
  });

  try {
    console.log('⚡ Connecting to PostgreSQL server...');
    const client = await pool.connect();
    
    console.log('✅ Connected to PostgreSQL server!');
    
    // List all databases
    const result = await client.query(`
      SELECT datname 
      FROM pg_database 
      WHERE datistemplate = false
      ORDER BY datname
    `);
    
    console.log(`📋 Available databases (${result.rows.length}):`);
    result.rows.forEach((row, index) => {
      console.log(`   ${index + 1}. ${row.datname}`);
    });
    
    // Check if mydreamv50 database exists
    const mydreamExists = result.rows.some(row => row.datname === 'mydreamv50');
    
    if (mydreamExists) {
      console.log('✅ Database "mydreamv50" exists!');
    } else {
      console.log('❌ Database "mydreamv50" does not exist');
      console.log('💡 Will attempt to create it...');
      
      // Create the database
      await client.query('CREATE DATABASE mydreamv50');
      console.log('✅ Database "mydreamv50" created successfully!');
    }
    
    client.release();
    await pool.end();
    
    console.log('🎉 Database check completed!');
    
  } catch (error) {
    console.error('❌ Database check failed:');
    console.error('   Error type:', error.code || 'UNKNOWN');
    console.error('   Message:', error.message);
    
    if (error.code === '42P04') {
      console.log('✅ Database "mydreamv50" already exists!');
    }
    
    await pool.end();
  }
}

// Run the check
checkAvailableDatabases().catch(console.error);