#!/usr/bin/env node

/**
 * Check Replit Database Data Script
 * Checks what tables and data exist in the Replit PostgreSQL database
 */

import { Pool } from 'pg';

const DATABASE_URL = process.env.DATABASE_URL;

async function checkReplitDatabase() {
  console.log('🔍 Checking Replit PostgreSQL database...');
  
  if (!DATABASE_URL) {
    console.error('❌ DATABASE_URL environment variable not found');
    return;
  }
  
  console.log('🔗 Database URL configured:', DATABASE_URL.split('@')[1] || 'hidden');
  
  const pool = new Pool({ 
    connectionString: DATABASE_URL,
    ssl: false,
    connectionTimeoutMillis: 10000,
  });

  try {
    const client = await pool.connect();
    console.log('✅ Connected to Replit database');
    
    // Check current database info
    const dbInfoResult = await client.query('SELECT current_database(), current_user, version()');
    const dbInfo = dbInfoResult.rows[0];
    console.log('📊 Database:', dbInfo.current_database);
    console.log('👤 User:', dbInfo.current_user);
    console.log('🏗️ PostgreSQL Version:', dbInfo.version.split(' ').slice(0, 2).join(' '));
    
    // Check all tables
    const tablesResult = await client.query(`
      SELECT table_name, table_type
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);
    
    console.log(`\n📋 Tables found: ${tablesResult.rows.length}`);
    
    if (tablesResult.rows.length === 0) {
      console.log('📭 Database is empty - no tables exist');
      console.log('💡 This explains why the application cannot load data');
    } else {
      console.log('📄 Available tables:');
      
      for (const table of tablesResult.rows) {
        console.log(`\n  📊 Table: ${table.table_name}`);
        
        try {
          // Get row count
          const countResult = await client.query(`SELECT COUNT(*) FROM "${table.table_name}"`);
          const count = parseInt(countResult.rows[0].count);
          
          console.log(`     Rows: ${count}`);
          
          if (count > 0) {
            // Show column info
            const columnsResult = await client.query(`
              SELECT column_name, data_type, is_nullable
              FROM information_schema.columns 
              WHERE table_name = $1 AND table_schema = 'public'
              ORDER BY ordinal_position
            `, [table.table_name]);
            
            console.log(`     Columns: ${columnsResult.rows.map(col => col.column_name).join(', ')}`);
            
            // Show sample data for small tables
            if (count <= 5) {
              const sampleResult = await client.query(`SELECT * FROM "${table.table_name}" LIMIT 2`);
              if (sampleResult.rows.length > 0) {
                console.log(`     Sample:`, JSON.stringify(sampleResult.rows[0], null, 2));
              }
            }
          } else {
            console.log('     Status: Empty table');
          }
        } catch (error) {
          console.log(`     Error: ${error.message}`);
        }
      }
    }
    
    client.release();
    await pool.end();
    
    console.log('\n🎉 Database check completed!');
    
  } catch (error) {
    console.error('❌ Database check failed:');
    console.error('   Error:', error.message);
    console.error('   Code:', error.code);
    await pool.end();
  }
}

checkReplitDatabase().catch(console.error);