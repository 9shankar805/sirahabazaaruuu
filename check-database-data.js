#!/usr/bin/env node

/**
 * Check Database Data Script
 * Checks what tables and data are available in the database
 */

import { Pool } from 'pg';

const DATABASE_URL = "postgresql://mydreamv50:123456@139.59.19.202:5432/postgres";

async function checkDatabaseData() {
  console.log('🔍 Checking database data...');
  
  const pool = new Pool({ 
    connectionString: DATABASE_URL,
    ssl: false,
    connectionTimeoutMillis: 10000,
  });

  try {
    const client = await pool.connect();
    console.log('✅ Connected to database');
    
    // Check current user and permissions
    const userResult = await client.query('SELECT current_user, current_database()');
    console.log('👤 Current user:', userResult.rows[0].current_user);
    console.log('🗄️ Current database:', userResult.rows[0].current_database);
    
    // Check what schemas exist
    const schemasResult = await client.query(`
      SELECT schema_name 
      FROM information_schema.schemata 
      WHERE schema_name NOT IN ('information_schema', 'pg_catalog', 'pg_toast')
      ORDER BY schema_name
    `);
    console.log('📁 Available schemas:', schemasResult.rows.map(row => row.schema_name));
    
    // Check all tables across all schemas
    const allTablesResult = await client.query(`
      SELECT table_schema, table_name, table_type
      FROM information_schema.tables 
      WHERE table_schema NOT IN ('information_schema', 'pg_catalog', 'pg_toast')
      ORDER BY table_schema, table_name
    `);
    
    console.log(`📋 Total tables found: ${allTablesResult.rows.length}`);
    
    if (allTablesResult.rows.length > 0) {
      console.log('📄 Tables by schema:');
      const tablesBySchema = {};
      allTablesResult.rows.forEach(row => {
        if (!tablesBySchema[row.table_schema]) {
          tablesBySchema[row.table_schema] = [];
        }
        tablesBySchema[row.table_schema].push(row.table_name);
      });
      
      for (const [schema, tables] of Object.entries(tablesBySchema)) {
        console.log(`  ${schema}: ${tables.join(', ')}`);
      }
      
      // Check data in existing tables
      for (const row of allTablesResult.rows) {
        try {
          const countResult = await client.query(`SELECT COUNT(*) FROM "${row.table_schema}"."${row.table_name}"`);
          const count = countResult.rows[0].count;
          console.log(`📊 ${row.table_schema}.${row.table_name}: ${count} rows`);
          
          if (count > 0 && count <= 10) {
            // Show sample data for small tables
            const sampleResult = await client.query(`SELECT * FROM "${row.table_schema}"."${row.table_name}" LIMIT 3`);
            if (sampleResult.rows.length > 0) {
              console.log(`   Sample data:`, JSON.stringify(sampleResult.rows[0], null, 2));
            }
          }
        } catch (error) {
          console.log(`⚠️ Cannot access ${row.table_schema}.${row.table_name}: ${error.message}`);
        }
      }
    } else {
      console.log('📭 No tables found in the database');
    }
    
    // Check permissions on public schema
    try {
      const permResult = await client.query(`
        SELECT grantee, privilege_type 
        FROM information_schema.schema_privileges 
        WHERE schema_name = 'public' AND grantee = current_user
      `);
      console.log('🔐 Current user permissions on public schema:', 
        permResult.rows.map(row => row.privilege_type));
    } catch (error) {
      console.log('⚠️ Cannot check permissions:', error.message);
    }
    
    client.release();
    await pool.end();
    
    console.log('🎉 Database data check completed!');
    
  } catch (error) {
    console.error('❌ Database check failed:');
    console.error('   Error:', error.message);
    await pool.end();
  }
}

checkDatabaseData().catch(console.error);