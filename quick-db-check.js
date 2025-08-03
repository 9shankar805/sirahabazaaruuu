#!/usr/bin/env node

/**
 * Quick Database Status Checker
 * Fast health check for PostgreSQL to identify issues immediately
 */

import { Pool } from 'pg';

const DATABASE_URL = process.env.DATABASE_URL;

async function quickHealthCheck() {
  console.log('🔍 Quick Database Health Check\n');
  
  if (!DATABASE_URL) {
    console.error('❌ DATABASE_URL not found');
    return false;
  }
  
  console.log('📍 Database URL configured');
  
  const pool = new Pool({
    connectionString: DATABASE_URL,
    max: 1,
    connectionTimeoutMillis: 5000,
  });
  
  try {
    // Test basic connectivity
    console.log('🔗 Testing connection...');
    const startTime = Date.now();
    const client = await pool.connect();
    const connectTime = Date.now() - startTime;
    
    console.log(`✅ Connected in ${connectTime}ms`);
    
    // Test query execution
    console.log('⚡ Testing query...');
    const queryStart = Date.now();
    const result = await client.query('SELECT version(), now() as current_time');
    const queryTime = Date.now() - queryStart;
    
    console.log(`✅ Query executed in ${queryTime}ms`);
    console.log(`📊 PostgreSQL Version: ${result.rows[0].version.split(' ')[1]}`);
    
    // Check connection stats
    const statsResult = await client.query(`
      SELECT 
        count(*) as total_connections,
        count(*) FILTER (WHERE state = 'active') as active_connections,
        count(*) FILTER (WHERE state = 'idle') as idle_connections
      FROM pg_stat_activity
    `);
    
    const stats = statsResult.rows[0];
    console.log(`🔗 Connections: ${stats.total_connections} total, ${stats.active_connections} active, ${stats.idle_connections} idle`);
    
    // Check database size
    const sizeResult = await client.query(`
      SELECT pg_size_pretty(pg_database_size(current_database())) as size
    `);
    console.log(`💾 Database size: ${sizeResult.rows[0].size}`);
    
    client.release();
    await pool.end();
    
    console.log('\n✅ Database is healthy and responsive');
    return true;
    
  } catch (error) {
    console.error(`\n❌ Database check failed: ${error.message}`);
    
    if (error.code === 'ECONNREFUSED') {
      console.error('💥 Database server is not running or not accessible');
    } else if (error.code === 'ENOTFOUND') {
      console.error('🔍 Database host not found - check your DATABASE_URL');
    } else if (error.code === '28P01') {
      console.error('🔐 Authentication failed - check username/password');
    } else if (error.code === '3D000') {
      console.error('🗃️ Database does not exist');
    }
    
    try {
      await pool.end();
    } catch (closeError) {
      // Ignore close errors
    }
    
    return false;
  }
}

// Run the check
quickHealthCheck()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('Unexpected error:', error);
    process.exit(1);
  });