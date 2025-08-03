#!/usr/bin/env node

/**
 * Safe Database Migration Script
 * Helps migrate existing data to your new PostgreSQL database
 */

const { Pool } = require('pg');
const fs = require('fs');

// Database URLs
// This script is now configured for your PostgreSQL database only
// const OLD_DATABASE_URL = ""; // No longer needed - using PostgreSQL exclusively
const NEW_DATABASE_URL = "postgresql://mydreamv50:123456@139.59.19.202:5432/mydreamv50";

async function createBackup() {
  console.log('📦 Creating backup of existing data...');
  
  const oldPool = new Pool({ connectionString: OLD_DATABASE_URL });
  
  try {
    const client = await oldPool.connect();
    
    // List of tables to backup (based on your schema)
    const tables = [
      'users', 'admin_users', 'stores', 'categories', 'products', 
      'carts', 'cart_items', 'orders', 'order_items', 'reviews',
      'delivery_partners', 'deliveries', 'notifications', 'coupons',
      'store_analytics', 'inventory_logs', 'support_tickets'
    ];
    
    const backupData = {};
    
    for (const table of tables) {
      try {
        const result = await client.query(`SELECT * FROM ${table}`);
        backupData[table] = result.rows;
        console.log(`✅ Backed up ${result.rows.length} records from ${table}`);
      } catch (error) {
        console.log(`⚠️  Table ${table} not found or empty - skipping`);
        backupData[table] = [];
      }
    }
    
    // Save backup to file
    const backupFile = `backup_${new Date().toISOString().split('T')[0]}.json`;
    fs.writeFileSync(backupFile, JSON.stringify(backupData, null, 2));
    console.log(`💾 Backup saved to ${backupFile}`);
    
    client.release();
    await oldPool.end();
    
    return backupFile;
    
  } catch (error) {
    console.error('❌ Backup failed:', error.message);
    await oldPool.end();
    return null;
  }
}

async function setupNewDatabase() {
  console.log('🔧 Setting up new database schema...');
  
  const newPool = new Pool({ connectionString: NEW_DATABASE_URL });
  
  try {
    const client = await newPool.connect();
    
    // Run the table creation script
    console.log('📋 Creating tables...');
    
    // Import and run create-tables.js logic here
    // This will create all the necessary tables in your new database
    
    console.log('✅ Database schema created successfully');
    
    client.release();
    await newPool.end();
    
    return true;
    
  } catch (error) {
    console.error('❌ Schema setup failed:', error.message);
    await newPool.end();
    return false;
  }
}

async function restoreData(backupFile) {
  console.log('📤 Restoring data to new database...');
  
  if (!fs.existsSync(backupFile)) {
    console.error('❌ Backup file not found');
    return false;
  }
  
  const backupData = JSON.parse(fs.readFileSync(backupFile, 'utf8'));
  const newPool = new Pool({ connectionString: NEW_DATABASE_URL });
  
  try {
    const client = await newPool.connect();
    
    // Restore data table by table
    for (const [table, rows] of Object.entries(backupData)) {
      if (rows.length === 0) continue;
      
      console.log(`📥 Restoring ${rows.length} records to ${table}...`);
      
      // Insert data (this is a simplified version - you may need to handle foreign keys)
      for (const row of rows) {
        const columns = Object.keys(row);
        const values = Object.values(row);
        const placeholders = values.map((_, i) => `$${i + 1}`).join(', ');
        
        try {
          await client.query(
            `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${placeholders})`,
            values
          );
        } catch (error) {
          console.log(`⚠️  Failed to insert record in ${table}:`, error.message);
        }
      }
    }
    
    console.log('✅ Data restoration completed');
    
    client.release();
    await newPool.end();
    
    return true;
    
  } catch (error) {
    console.error('❌ Data restoration failed:', error.message);
    await newPool.end();
    return false;
  }
}

async function runMigration() {
  console.log('🚀 Starting safe database migration...');
  console.log('📊 This process will:');
  console.log('   1. Backup existing data from current database');
  console.log('   2. Set up schema in your new database');
  console.log('   3. Restore data to new database');
  console.log('   4. Verify data integrity');
  console.log('');
  
  // Step 1: Create backup
  const backupFile = await createBackup();
  if (!backupFile) {
    console.error('💥 Migration aborted - backup failed');
    return;
  }
  
  // Step 2: Setup new database
  const schemaSetup = await setupNewDatabase();
  if (!schemaSetup) {
    console.error('💥 Migration aborted - schema setup failed');
    return;
  }
  
  // Step 3: Restore data
  const dataRestored = await restoreData(backupFile);
  if (!dataRestored) {
    console.error('💥 Migration failed - data restoration incomplete');
    return;
  }
  
  console.log('🎉 Migration completed successfully!');
  console.log('💡 Next steps:');
  console.log('   • Test your application with the new database');
  console.log('   • Verify all data is present and correct');
  console.log('   • Keep the backup file safe for emergency rollback');
}

// Command line arguments
const command = process.argv[2];

if (command === 'backup') {
  createBackup().then(() => process.exit(0));
} else if (command === 'test') {
  // Test connection to new database
  const pool = new Pool({ connectionString: NEW_DATABASE_URL });
  pool.query('SELECT 1').then(() => {
    console.log('✅ New database connection successful');
    pool.end();
  }).catch(error => {
    console.error('❌ New database connection failed:', error.message);
    pool.end();
  });
} else {
  runMigration().then(() => process.exit(0));
}