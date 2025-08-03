#!/usr/bin/env node

/**
 * Fix Delivery Partner Schema
 * Adds missing columns to the delivery_partners table
 */

import { pool } from './server/db.ts';

async function fixDeliveryPartnerSchema() {
  try {
    console.log('=== FIXING DELIVERY PARTNER SCHEMA ===');
    
    // Add missing columns to delivery_partners table
    const alterTableQuery = `
      ALTER TABLE delivery_partners 
      ADD COLUMN IF NOT EXISTS vehicle_brand VARCHAR(100),
      ADD COLUMN IF NOT EXISTS vehicle_model VARCHAR(100),
      ADD COLUMN IF NOT EXISTS vehicle_year VARCHAR(10),
      ADD COLUMN IF NOT EXISTS vehicle_color VARCHAR(50),
      ADD COLUMN IF NOT EXISTS license_expiry_date VARCHAR(20),
      ADD COLUMN IF NOT EXISTS bank_name VARCHAR(200),
      ADD COLUMN IF NOT EXISTS account_holder_name VARCHAR(200),
      ADD COLUMN IF NOT EXISTS emergency_contact_name VARCHAR(200),
      ADD COLUMN IF NOT EXISTS emergency_contact_phone VARCHAR(20),
      ADD COLUMN IF NOT EXISTS emergency_contact_relation VARCHAR(100),
      ADD COLUMN IF NOT EXISTS working_hours VARCHAR(100),
      ADD COLUMN IF NOT EXISTS previous_employment VARCHAR(500),
      ADD COLUMN IF NOT EXISTS experience_years INTEGER DEFAULT 0;
    `;

    await pool.query(alterTableQuery);
    console.log('✅ Added missing columns to delivery_partners table');

    // Check current table structure
    const tableStructure = await pool.query(`
      SELECT column_name, data_type, is_nullable 
      FROM information_schema.columns 
      WHERE table_name = 'delivery_partners' 
      ORDER BY ordinal_position;
    `);

    console.log('\n📋 Current delivery_partners table structure:');
    tableStructure.rows.forEach(row => {
      console.log(`  ${row.column_name}: ${row.data_type} (${row.is_nullable === 'YES' ? 'nullable' : 'not null'})`);
    });

    console.log('\n✅ Schema fix completed successfully!');
    
  } catch (error) {
    console.error('❌ Error fixing delivery partner schema:', error);
  } finally {
    await pool.end();
  }
}

// Run the fix
fixDeliveryPartnerSchema();