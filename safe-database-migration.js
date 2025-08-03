#!/usr/bin/env node

/**
 * Safe Database Migration Script
 * This script helps you safely integrate your existing database with the project
 * without losing any data by following these steps:
 * 1. Inspect existing database structure
 * 2. Compare with current schema
 * 3. Generate safe migration commands
 * 4. Create backup before any changes
 */

import { Pool } from 'pg';
import fs from 'fs/promises';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is required');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('sslmode=require') ? { rejectUnauthorized: false } : false
});

async function inspectExistingDatabase() {
  try {
    console.log('🔍 Inspecting your existing database structure...\n');
    
    const client = await pool.connect();
    
    // Get all tables
    const tablesResult = await client.query(`
      SELECT table_name, table_type
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);
    
    console.log(`📋 Found ${tablesResult.rows.length} existing tables:`);
    tablesResult.rows.forEach(row => {
      console.log(`   ✓ ${row.table_name} (${row.table_type})`);
    });
    
    // Get table sizes and data counts
    console.log('\n📊 Data analysis:');
    for (const table of tablesResult.rows) {
      try {
        const countResult = await client.query(`SELECT COUNT(*) FROM "${table.table_name}"`);
        const count = parseInt(countResult.rows[0].count);
        console.log(`   📄 ${table.table_name}: ${count.toLocaleString()} records`);
      } catch (error) {
        console.log(`   ⚠️  ${table.table_name}: Unable to count records`);
      }
    }
    
    // Get column information for each table
    console.log('\n🔧 Table structures:');
    const tableStructures = {};
    
    for (const table of tablesResult.rows) {
      const columnsResult = await client.query(`
        SELECT column_name, data_type, is_nullable, column_default, character_maximum_length
        FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = $1
        ORDER BY ordinal_position
      `, [table.table_name]);
      
      tableStructures[table.table_name] = columnsResult.rows;
      
      console.log(`\n   📋 ${table.table_name}:`);
      columnsResult.rows.forEach(col => {
        const nullable = col.is_nullable === 'YES' ? 'NULL' : 'NOT NULL';
        const defaultVal = col.column_default ? ` DEFAULT ${col.column_default}` : '';
        console.log(`      - ${col.column_name}: ${col.data_type}${col.character_maximum_length ? `(${col.character_maximum_length})` : ''} ${nullable}${defaultVal}`);
      });
    }
    
    client.release();
    
    // Save analysis to file
    const analysisData = {
      timestamp: new Date().toISOString(),
      totalTables: tablesResult.rows.length,
      tables: tablesResult.rows,
      structures: tableStructures,
      migrationNote: 'This database contains existing data that should be preserved'
    };
    
    await fs.writeFile('database-analysis.json', JSON.stringify(analysisData, null, 2));
    console.log('\n💾 Database analysis saved to database-analysis.json');
    
    return analysisData;
    
  } catch (error) {
    console.error('❌ Error inspecting database:', error.message);
    throw error;
  }
}

async function createBackupScript() {
  console.log('\n🛡️  Creating backup script...');
  
  const backupScript = `#!/bin/bash

# Database Backup Script
# Run this before making any schema changes

echo "🛡️  Creating database backup..."

# Create backup directory
mkdir -p backups/$(date +%Y-%m-%d)

# Create full database backup
pg_dump "${DATABASE_URL}" > "backups/$(date +%Y-%m-%d)/full-backup-$(date +%H-%M-%S).sql"

# Create schema-only backup
pg_dump --schema-only "${DATABASE_URL}" > "backups/$(date +%Y-%m-%d)/schema-$(date +%H-%M-%S).sql"

# Create data-only backup
pg_dump --data-only "${DATABASE_URL}" > "backups/$(date +%Y-%m-%d)/data-$(date +%H-%M-%S).sql"

echo "✅ Backup completed in backups/$(date +%Y-%m-%d)/"
echo "📋 Files created:"
echo "   - full-backup-*.sql (complete database)"
echo "   - schema-*.sql (table structures only)"  
echo "   - data-*.sql (data only)"
`;

  await fs.writeFile('create-backup.sh', backupScript);
  await fs.chmod('create-backup.sh', 0o755);
  
  console.log('✅ Backup script created: create-backup.sh');
}

async function generateSafeMigration() {
  console.log('\n🔧 Generating safe migration strategy...');
  
  const migrationGuide = `# Safe Database Migration Guide

## Your Current Situation
✅ You have an existing database with data
✅ You want to integrate it with this Siraha Bazaar project
✅ You want to preserve all existing data

## Safe Migration Steps

### Step 1: Create Backup (CRITICAL)
\`\`\`bash
# Run the backup script first
./create-backup.sh
\`\`\`

### Step 2: Check Schema Compatibility
Instead of \`npm run db:push\` which can destroy data, use:

\`\`\`bash
# Generate migration files (safe)
npx drizzle-kit generate

# Review the generated migration files in ./migrations/
# They will show exactly what changes will be made
\`\`\`

### Step 3: Apply Safe Migrations
\`\`\`bash
# Apply migrations safely (preserves data)
npx drizzle-kit migrate
\`\`\`

## Alternative: Manual Schema Alignment

If you prefer full control:

### Option A: Modify Project Schema to Match Your Database
1. Update \`shared/schema.ts\` to match your existing database structure
2. This preserves your data and adapts the project to your database

### Option B: Add Missing Tables Only
1. Identify which tables from \`shared/schema.ts\` don't exist in your database
2. Create only those missing tables manually
3. Keep your existing tables unchanged

## NEVER DO THIS (Data Loss Risk):
❌ \`npm run db:push\` - Can drop and recreate tables
❌ Directly modifying table structures without backup
❌ Renaming tables without proper migration

## Safe Commands Only:
✅ \`npx drizzle-kit generate\` - Creates migration files
✅ \`npx drizzle-kit migrate\` - Applies migrations safely
✅ \`./create-backup.sh\` - Creates backup
✅ Manual table creation for missing tables only

## Emergency Recovery
If something goes wrong:
\`\`\`bash
# Restore from backup
psql "$DATABASE_URL" < "backups/YYYY-MM-DD/full-backup-HH-MM-SS.sql"
\`\`\`
`;

  await fs.writeFile('SAFE_MIGRATION_GUIDE.md', migrationGuide);
  console.log('✅ Migration guide created: SAFE_MIGRATION_GUIDE.md');
}

async function checkProjectCompatibility(analysisData) {
  console.log('\n🔄 Checking compatibility with project schema...');
  
  // Read the current project schema
  try {
    const schemaContent = await fs.readFile('shared/schema.ts', 'utf8');
    const projectTables = schemaContent.match(/export const (\w+) = pgTable/g)?.map(match => 
      match.replace('export const ', '').replace(' = pgTable', '')
    ) || [];
    
    console.log(`\n📋 Project defines ${projectTables.length} tables:`);
    projectTables.forEach(table => console.log(`   - ${table}`));
    
    console.log('\n🔍 Compatibility analysis:');
    
    const existingTableNames = analysisData.tables.map(t => t.table_name);
    const missingTables = projectTables.filter(table => !existingTableNames.includes(table));
    const extraTables = existingTableNames.filter(table => !projectTables.includes(table));
    
    if (missingTables.length > 0) {
      console.log('\n➕ Tables that need to be created:');
      missingTables.forEach(table => console.log(`   + ${table}`));
    }
    
    if (extraTables.length > 0) {
      console.log('\n📊 Extra tables in your database (will be preserved):');
      extraTables.forEach(table => console.log(`   • ${table}`));
    }
    
    console.log('\n💡 Recommendation:');
    if (missingTables.length === 0) {
      console.log('   ✅ Your database already has all required tables!');
      console.log('   ✅ You can safely connect this project to your database');
    } else {
      console.log('   🔧 You need to add some missing tables');
      console.log('   🛡️  Use migration approach to safely add them');
    }
    
  } catch (error) {
    console.log('⚠️  Could not read project schema file');
  }
}

async function main() {
  try {
    console.log('🚀 Safe Database Migration Tool\n');
    console.log('This tool will help you integrate your existing database');
    console.log('with the Siraha Bazaar project without losing any data.\n');
    
    // Step 1: Inspect existing database
    const analysisData = await inspectExistingDatabase();
    
    // Step 2: Create backup script
    await createBackupScript();
    
    // Step 3: Generate migration guide
    await generateSafeMigration();
    
    // Step 4: Check compatibility
    await checkProjectCompatibility(analysisData);
    
    console.log('\n🎉 Analysis Complete!');
    console.log('\n📋 Files created:');
    console.log('   📄 database-analysis.json - Your database structure');
    console.log('   🛡️  create-backup.sh - Backup script');
    console.log('   📖 SAFE_MIGRATION_GUIDE.md - Step-by-step guide');
    
    console.log('\n🚀 Next Steps:');
    console.log('   1. Review database-analysis.json');
    console.log('   2. Read SAFE_MIGRATION_GUIDE.md');
    console.log('   3. Create backup: ./create-backup.sh');
    console.log('   4. Follow the migration guide');
    
  } catch (error) {
    console.error('\n❌ Migration analysis failed:', error.message);
  } finally {
    await pool.end();
  }
}

// Run the analysis
main();