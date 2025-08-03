#!/usr/bin/env node

/**
 * Production Migration Toolkit
 * Safe database updates for production deployments
 */

import { Pool } from 'pg';
import fs from 'fs/promises';
import path from 'path';
import { execSync } from 'child_process';
import dotenv from 'dotenv';

dotenv.config();

const PRODUCTION_DATABASE_URL = process.env.PRODUCTION_DATABASE_URL || process.env.DATABASE_URL;
const DEVELOPMENT_DATABASE_URL = process.env.DEVELOPMENT_DATABASE_URL;

class ProductionMigrationToolkit {
  constructor() {
    this.productionPool = null;
    this.developmentPool = null;
  }

  async init() {
    if (!PRODUCTION_DATABASE_URL) {
      throw new Error('PRODUCTION_DATABASE_URL is required');
    }

    this.productionPool = new Pool({
      connectionString: PRODUCTION_DATABASE_URL,
      ssl: PRODUCTION_DATABASE_URL.includes('sslmode=require') ? { rejectUnauthorized: false } : false
    });

    if (DEVELOPMENT_DATABASE_URL) {
      this.developmentPool = new Pool({
        connectionString: DEVELOPMENT_DATABASE_URL,
        ssl: DEVELOPMENT_DATABASE_URL.includes('sslmode=require') ? { rejectUnauthorized: false } : false
      });
    }
  }

  async createBackup() {
    console.log('🛡️ Creating production database backup...');
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupDir = `backups/production/${timestamp}`;
    
    try {
      await fs.mkdir(backupDir, { recursive: true });
      
      // Create full backup
      console.log('📦 Creating full backup...');
      execSync(`pg_dump "${PRODUCTION_DATABASE_URL}" > "${backupDir}/full-backup.sql"`);
      
      // Create schema-only backup
      console.log('🏗️ Creating schema backup...');
      execSync(`pg_dump --schema-only "${PRODUCTION_DATABASE_URL}" > "${backupDir}/schema.sql"`);
      
      // Create data-only backup
      console.log('📊 Creating data backup...');
      execSync(`pg_dump --data-only "${PRODUCTION_DATABASE_URL}" > "${backupDir}/data.sql"`);
      
      console.log(`✅ Backup completed: ${backupDir}`);
      return backupDir;
      
    } catch (error) {
      console.error('❌ Backup failed:', error.message);
      throw error;
    }
  }

  async analyzeDataDifferences() {
    if (!this.developmentPool) {
      console.log('ℹ️ Development database not configured, skipping analysis');
      return;
    }

    console.log('🔍 Analyzing data differences...');
    
    const prodClient = await this.productionPool.connect();
    const devClient = await this.developmentPool.connect();
    
    try {
      // Compare table counts
      const tables = ['users', 'products', 'stores', 'orders', 'categories'];
      
      console.log('\n📊 Data comparison:');
      console.log('Table'.padEnd(15) + 'Production'.padEnd(12) + 'Development'.padEnd(12) + 'Difference');
      console.log('-'.repeat(50));
      
      for (const table of tables) {
        try {
          const prodResult = await prodClient.query(`SELECT COUNT(*) FROM ${table}`);
          const devResult = await devClient.query(`SELECT COUNT(*) FROM ${table}`);
          
          const prodCount = parseInt(prodResult.rows[0].count);
          const devCount = parseInt(devResult.rows[0].count);
          const diff = devCount - prodCount;
          
          console.log(
            table.padEnd(15) + 
            prodCount.toString().padEnd(12) + 
            devCount.toString().padEnd(12) + 
            (diff > 0 ? `+${diff}` : diff.toString())
          );
        } catch (error) {
          console.log(table.padEnd(15) + 'Error'.padEnd(12) + 'Error'.padEnd(12) + 'N/A');
        }
      }
      
    } finally {
      prodClient.release();
      devClient.release();
    }
  }

  async addEnvironmentFlags() {
    console.log('🏷️ Adding environment flags to production data...');
    
    const client = await this.productionPool.connect();
    
    try {
      // Add environment columns if they don't exist
      const queries = [
        `ALTER TABLE products ADD COLUMN IF NOT EXISTS environment VARCHAR(20) DEFAULT 'production'`,
        `ALTER TABLE stores ADD COLUMN IF NOT EXISTS environment VARCHAR(20) DEFAULT 'production'`,
        `ALTER TABLE users ADD COLUMN IF NOT EXISTS environment VARCHAR(20) DEFAULT 'production'`,
        `ALTER TABLE categories ADD COLUMN IF NOT EXISTS environment VARCHAR(20) DEFAULT 'production'`
      ];
      
      for (const query of queries) {
        try {
          await client.query(query);
          console.log(`✅ Added environment column: ${query.split(' ')[2]}`);
        } catch (error) {
          if (!error.message.includes('already exists')) {
            console.log(`⚠️ Warning: ${error.message}`);
          }
        }
      }
      
      // Mark all existing data as production
      const updateQueries = [
        `UPDATE products SET environment = 'production' WHERE environment IS NULL`,
        `UPDATE stores SET environment = 'production' WHERE environment IS NULL`,
        `UPDATE users SET environment = 'production' WHERE environment IS NULL`,
        `UPDATE categories SET environment = 'production' WHERE environment IS NULL`
      ];
      
      for (const query of updateQueries) {
        const result = await client.query(query);
        console.log(`✅ Updated ${result.rowCount} records in ${query.split(' ')[1]}`);
      }
      
    } finally {
      client.release();
    }
  }

  async generateMigrations() {
    console.log('📝 Generating migration files...');
    
    try {
      execSync('npx drizzle-kit generate', { stdio: 'inherit' });
      console.log('✅ Migration files generated');
      
      // List generated files
      const migrationsDir = './migrations';
      try {
        const files = await fs.readdir(migrationsDir);
        const sqlFiles = files.filter(f => f.endsWith('.sql')).sort();
        
        if (sqlFiles.length > 0) {
          console.log('\n📋 Generated migration files:');
          sqlFiles.forEach(file => console.log(`   - ${file}`));
        }
      } catch (error) {
        console.log('📁 Migrations directory not found or empty');
      }
      
    } catch (error) {
      console.error('❌ Migration generation failed:', error.message);
      throw error;
    }
  }

  async applyMigrations() {
    console.log('🔄 Applying migrations to production...');
    
    try {
      execSync('npx drizzle-kit migrate', { stdio: 'inherit' });
      console.log('✅ Migrations applied successfully');
    } catch (error) {
      console.error('❌ Migration failed:', error.message);
      throw error;
    }
  }

  async verifyDataIntegrity() {
    console.log('🔍 Verifying data integrity...');
    
    const client = await this.productionPool.connect();
    
    try {
      // Check table counts
      const tables = ['users', 'products', 'stores', 'orders', 'categories'];
      
      console.log('\n📊 Current data status:');
      for (const table of tables) {
        try {
          const result = await client.query(`SELECT COUNT(*) FROM ${table}`);
          const count = parseInt(result.rows[0].count);
          console.log(`   ${table}: ${count.toLocaleString()} records`);
        } catch (error) {
          console.log(`   ${table}: Error reading table`);
        }
      }
      
      // Check for environment flags
      console.log('\n🏷️ Environment data distribution:');
      for (const table of ['products', 'stores', 'users']) {
        try {
          const result = await client.query(`
            SELECT environment, COUNT(*) as count 
            FROM ${table} 
            WHERE environment IS NOT NULL 
            GROUP BY environment
          `);
          
          if (result.rows.length > 0) {
            console.log(`   ${table}:`);
            result.rows.forEach(row => {
              console.log(`     ${row.environment}: ${row.count} records`);
            });
          }
        } catch (error) {
          // Environment column might not exist yet
        }
      }
      
    } finally {
      client.release();
    }
  }

  async cleanup() {
    if (this.productionPool) {
      await this.productionPool.end();
    }
    if (this.developmentPool) {
      await this.developmentPool.end();
    }
  }
}

// Command line interface
async function main() {
  const toolkit = new ProductionMigrationToolkit();
  
  try {
    await toolkit.init();
    
    const command = process.argv[2];
    
    switch (command) {
      case 'backup':
        await toolkit.createBackup();
        break;
        
      case 'analyze':
        await toolkit.analyzeDataDifferences();
        break;
        
      case 'add-flags':
        await toolkit.addEnvironmentFlags();
        break;
        
      case 'generate':
        await toolkit.generateMigrations();
        break;
        
      case 'migrate':
        await toolkit.applyMigrations();
        break;
        
      case 'verify':
        await toolkit.verifyDataIntegrity();
        break;
        
      case 'full-update':
        console.log('🚀 Starting full production update process...\n');
        
        // Step 1: Backup
        await toolkit.createBackup();
        console.log('');
        
        // Step 2: Add environment flags
        await toolkit.addEnvironmentFlags();
        console.log('');
        
        // Step 3: Generate migrations
        await toolkit.generateMigrations();
        console.log('');
        
        // Step 4: Apply migrations
        await toolkit.applyMigrations();
        console.log('');
        
        // Step 5: Verify
        await toolkit.verifyDataIntegrity();
        
        console.log('\n🎉 Production update completed successfully!');
        break;
        
      default:
        console.log(`
Production Migration Toolkit

Usage: node production-migration-toolkit.js <command>

Commands:
  backup        Create production database backup
  analyze       Compare production vs development data
  add-flags     Add environment flags to production data
  generate      Generate migration files
  migrate       Apply migrations to production
  verify        Verify data integrity
  full-update   Complete update process (backup + migrate + verify)

Examples:
  node production-migration-toolkit.js backup
  node production-migration-toolkit.js full-update
        `);
    }
    
  } catch (error) {
    console.error('\n❌ Operation failed:', error.message);
    process.exit(1);
  } finally {
    await toolkit.cleanup();
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export default ProductionMigrationToolkit;