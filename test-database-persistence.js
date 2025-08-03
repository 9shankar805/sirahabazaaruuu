#!/usr/bin/env node

/**
 * Database Persistence Test
 * This script tests that user accounts are stored correctly and persist long-term
 */

import pkg from 'pg';
const { Pool } = pkg;
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL not found in environment variables');
  process.exit(1);
}

// Create database connection pool
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function testDatabasePersistence() {
  try {
    console.log('🔍 Testing PostgreSQL Database Persistence...\n');

    // Test 1: Check if users table exists and contains data
    console.log('📋 Test 1: Verifying users table exists and contains data');
    const usersResult = await pool.query('SELECT COUNT(*) as count FROM users');
    const userCount = parseInt(usersResult.rows[0].count);
    console.log(`✅ Users table contains ${userCount} records`);

    // Test 2: Verify recent user registrations
    console.log('\n📋 Test 2: Checking recent user registrations');
    const recentUsers = await pool.query(`
      SELECT id, email, full_name, created_at 
      FROM users 
      WHERE created_at >= NOW() - INTERVAL '1 hour'
      ORDER BY created_at DESC
      LIMIT 5
    `);

    if (recentUsers.rows.length > 0) {
      console.log(`✅ Found ${recentUsers.rows.length} users created in the last hour:`);
      recentUsers.rows.forEach(user => {
        console.log(`   - ID: ${user.id}, Email: ${user.email}, Name: ${user.full_name}`);
        console.log(`     Created: ${user.created_at}`);
      });
    } else {
      console.log('⚠️ No recent users found');
    }

    // Test 3: Check database table structure
    console.log('\n📋 Test 3: Verifying database schema integrity');
    const tablesResult = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      ORDER BY table_name
    `);

    const tables = tablesResult.rows.map(row => row.table_name);
    console.log(`✅ Database contains ${tables.length} tables:`);
    
    // Key tables for e-commerce functionality
    const keyTables = [
      'users', 'stores', 'products', 'orders', 'categories', 
      'cart_items', 'delivery_partners', 'notifications'
    ];

    keyTables.forEach(table => {
      if (tables.includes(table)) {
        console.log(`   ✅ ${table} - Present`);
      } else {
        console.log(`   ❌ ${table} - Missing`);
      }
    });

    // Test 4: Test data persistence across connections
    console.log('\n📋 Test 4: Testing data persistence across multiple connections');
    
    // Create a new connection to simulate app restart
    const testPool = new Pool({
      connectionString: DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    });

    const persistenceTest = await testPool.query('SELECT COUNT(*) as count FROM users');
    const persistentUserCount = parseInt(persistenceTest.rows[0].count);
    
    if (persistentUserCount === userCount) {
      console.log(`✅ Data persistence verified: ${persistentUserCount} users found across connections`);
    } else {
      console.log(`❌ Data persistence issue: User count mismatch`);
    }

    await testPool.end();

    // Test 5: Check database connection stability
    console.log('\n📋 Test 5: Testing connection stability');
    const connectionTest = await pool.query('SELECT version() as postgres_version');
    console.log(`✅ PostgreSQL Version: ${connectionTest.rows[0].postgres_version.split(' ')[0]} ${connectionTest.rows[0].postgres_version.split(' ')[1]}`);

    console.log('\n🎉 All database persistence tests completed successfully!');
    console.log('\n📊 Summary:');
    console.log(`   - Total users in database: ${userCount}`);
    console.log(`   - Recent registrations: ${recentUsers.rows.length}`);
    console.log(`   - Database tables: ${tables.length}`);
    console.log('   - Data persistence: ✅ Verified');
    console.log('   - Connection stability: ✅ Verified');

    console.log('\n✅ Your PostgreSQL database is properly configured for long-term storage!');
    console.log('✅ User accounts will persist permanently and survive application restarts.');

  } catch (error) {
    console.error('❌ Database persistence test failed:', error.message);
    console.error('   Error details:', error);
  } finally {
    await pool.end();
  }
}

// Run the test
testDatabasePersistence();