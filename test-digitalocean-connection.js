
#!/usr/bin/env node

import { Pool } from 'pg';

const DATABASE_URL = "postgresql://doadmin:AVNS_3UkZ6PqedWGFkdV6amW@db-postgresql-blr1-34567-do-user-23211066-0.d.db.ondigitalocean.com:25060/defaultdb?sslmode=require";

async function testDigitalOceanConnection() {
  console.log('🔍 Testing DigitalOcean PostgreSQL connection...');
  
  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
      rejectUnauthorized: false,
      sslmode: 'require'
    },
    max: 1,
    connectionTimeoutMillis: 10000,
  });

  try {
    console.log('📡 Connecting to database...');
    const client = await pool.connect();
    
    console.log('✅ Connected successfully!');
    
    // Test basic query
    const result = await client.query('SELECT NOW(), version()');
    console.log('📅 Current time:', result.rows[0].now);
    console.log('🔢 PostgreSQL version:', result.rows[0].version);
    
    // Check existing tables
    const tablesResult = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);
    
    console.log('📋 Existing tables:');
    tablesResult.rows.forEach(row => {
      console.log(`  - ${row.table_name}`);
    });
    
    client.release();
    console.log('✅ Connection test completed successfully!');
    
  } catch (error) {
    console.error('❌ Connection failed:', error.message);
    console.error('🔧 Error details:', {
      code: error.code,
      detail: error.detail,
      hint: error.hint
    });
  } finally {
    await pool.end();
  }
}

testDigitalOceanConnection();
