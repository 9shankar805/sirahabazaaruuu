#!/usr/bin/env node

/**
 * Siraha Bazaar Database Crash Prevention System
 * Implements automatic safeguards to prevent PostgreSQL crashes
 */

import { Pool } from 'pg';

const DATABASE_URL = process.env.DATABASE_URL;

class CrashPrevention {
  constructor() {
    this.isRunning = false;
    this.safeguards = {
      connectionLimit: true,
      queryTimeout: true,
      memoryMonitoring: true,
      autoCleanup: true,
    };
  }

  // Enhanced connection pool with crash prevention
  createSafePool() {
    return new Pool({
      connectionString: DATABASE_URL,
      max: 15,                    // Limit connections to prevent overload
      min: 2,                     // Keep minimum connections alive
      idleTimeoutMillis: 20000,   // Close idle connections quickly
      connectionTimeoutMillis: 3000, // Fast timeout to prevent hanging
      acquireTimeoutMillis: 5000, // Timeout for acquiring connections
      createTimeoutMillis: 3000,  // Timeout for creating connections
      destroyTimeoutMillis: 5000, // Timeout for destroying connections
      reapIntervalMillis: 1000,   // Check for idle connections frequently
      createRetryIntervalMillis: 200, // Retry connection creation
      
      // Advanced crash prevention settings
      statement_timeout: 30000,   // Kill queries after 30 seconds
      idle_in_transaction_session_timeout: 10000, // Kill idle transactions
    });
  }

  // Automatic connection cleanup
  async cleanupConnections(pool) {
    try {
      const client = await pool.connect();
      
      // Kill idle connections older than 5 minutes
      await client.query(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE state = 'idle'
        AND now() - state_change > interval '5 minutes'
        AND pid != pg_backend_pid()
      `);

      // Kill long-running queries over 2 minutes
      await client.query(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE state = 'active'
        AND now() - query_start > interval '2 minutes'
        AND pid != pg_backend_pid()
      `);

      client.release();
      console.log('✅ Connection cleanup completed');
      
    } catch (error) {
      console.error('⚠️ Cleanup failed:', error.message);
    }
  }

  // Memory pressure monitoring
  async checkMemoryPressure(pool) {
    try {
      const client = await pool.connect();
      
      // Check active connections vs limit
      const result = await client.query(`
        SELECT 
          count(*) as current_connections,
          setting::int as max_connections
        FROM pg_stat_activity, pg_settings 
        WHERE pg_settings.name = 'max_connections'
      `);
      
      const { current_connections, max_connections } = result.rows[0];
      const usage_percent = (current_connections / max_connections) * 100;
      
      if (usage_percent > 80) {
        console.warn(`🚨 HIGH CONNECTION USAGE: ${usage_percent}% (${current_connections}/${max_connections})`);
        await this.cleanupConnections(pool);
      }
      
      client.release();
      
    } catch (error) {
      console.error('Memory check failed:', error.message);
    }
  }

  // Query performance monitoring
  async monitorSlowQueries(pool) {
    try {
      const client = await pool.connect();
      
      const result = await client.query(`
        SELECT count(*) as slow_queries
        FROM pg_stat_activity
        WHERE state = 'active'
        AND now() - query_start > interval '10 seconds'
      `);
      
      const slowQueries = parseInt(result.rows[0].slow_queries);
      
      if (slowQueries > 3) {
        console.warn(`⚠️ ${slowQueries} slow queries detected - potential performance issue`);
      }
      
      client.release();
      
    } catch (error) {
      console.error('Query monitoring failed:', error.message);
    }
  }

  // Disk space monitoring
  async checkDiskSpace(pool) {
    try {
      const client = await pool.connect();
      
      const result = await client.query(`
        SELECT pg_size_pretty(pg_database_size(current_database())) as db_size,
               pg_database_size(current_database()) as db_size_bytes
      `);
      
      const { db_size, db_size_bytes } = result.rows[0];
      const sizeGB = db_size_bytes / (1024 * 1024 * 1024);
      
      if (sizeGB > 1) { // Alert if database > 1GB
        console.warn(`📊 Database size: ${db_size} - Monitor disk space`);
      }
      
      client.release();
      
    } catch (error) {
      console.error('Disk space check failed:', error.message);
    }
  }

  // Emergency recovery procedures
  async emergencyRecovery(pool) {
    console.log('🚨 EMERGENCY RECOVERY MODE ACTIVATED');
    
    try {
      // Force close all idle connections
      await this.cleanupConnections(pool);
      
      // Reduce memory usage
      const client = await pool.connect();
      await client.query('SET work_mem = "2MB"');
      await client.query('SET shared_buffers = "128MB"');
      client.release();
      
      console.log('✅ Emergency recovery completed');
      
    } catch (error) {
      console.error('❌ Emergency recovery failed:', error.message);
      console.log('💡 Manual intervention required - restart PostgreSQL service');
    }
  }

  // Main crash prevention loop
  async startPrevention() {
    if (this.isRunning) {
      console.log('⚠️ Crash prevention already running');
      return;
    }

    this.isRunning = true;
    console.log('🛡️ Starting database crash prevention system...');
    
    const pool = this.createSafePool();
    
    // Set up error handlers
    pool.on('error', async (err) => {
      console.error('🚨 Pool error detected:', err.message);
      
      if (err.code === '53300') { // Too many connections
        await this.emergencyRecovery(pool);
      }
    });

    // Main monitoring loop
    const monitoringInterval = setInterval(async () => {
      try {
        await this.checkMemoryPressure(pool);
        await this.monitorSlowQueries(pool);
        await this.checkDiskSpace(pool);
        
      } catch (error) {
        console.error('Monitoring error:', error.message);
        
        if (error.code === 'ECONNREFUSED') {
          console.error('💥 DATABASE CONNECTION LOST');
          await this.emergencyRecovery(pool);
        }
      }
    }, 10000); // Check every 10 seconds

    // Cleanup interval
    const cleanupInterval = setInterval(async () => {
      await this.cleanupConnections(pool);
    }, 60000); // Cleanup every minute

    // Graceful shutdown
    process.on('SIGINT', async () => {
      console.log('\n🛑 Stopping crash prevention...');
      clearInterval(monitoringInterval);
      clearInterval(cleanupInterval);
      await pool.end();
      this.isRunning = false;
      process.exit(0);
    });

    console.log('✅ Crash prevention system is active');
    console.log('📊 Monitoring every 10 seconds, cleanup every minute');
    
    return pool;
  }

  // Test database resilience
  async testResilience() {
    console.log('🧪 Testing database resilience...');
    
    const pool = this.createSafePool();
    
    try {
      // Test connection timeout
      const startTime = Date.now();
      const client = await pool.connect();
      const connectTime = Date.now() - startTime;
      
      console.log(`⏱️ Connection time: ${connectTime}ms`);
      
      if (connectTime > 2000) {
        console.warn('⚠️ Slow connection detected');
      }
      
      // Test query execution
      const queryStart = Date.now();
      await client.query('SELECT version()');
      const queryTime = Date.now() - queryStart;
      
      console.log(`⚡ Query time: ${queryTime}ms`);
      
      client.release();
      await pool.end();
      
      console.log('✅ Resilience test completed');
      
    } catch (error) {
      console.error('❌ Resilience test failed:', error.message);
      return false;
    }
    
    return true;
  }
}

// Command line interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const prevention = new CrashPrevention();
  
  const command = process.argv[2];
  
  switch (command) {
    case 'start':
      prevention.startPrevention();
      break;
      
    case 'test':
      prevention.testResilience();
      break;
      
    default:
      console.log('🛡️ Siraha Bazaar Database Crash Prevention');
      console.log('');
      console.log('Commands:');
      console.log('  start  - Start crash prevention monitoring');
      console.log('  test   - Test database resilience');
      console.log('');
      console.log('Example:');
      console.log('  node prevent-database-crashes.js start');
      break;
  }
}

export default CrashPrevention;