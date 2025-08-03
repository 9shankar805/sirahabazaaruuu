#!/usr/bin/env node

/**
 * Database Health Monitor
 * Continuously monitors PostgreSQL health and prevents crashes
 */

import { Pool } from 'pg';

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is not set');
  process.exit(1);
}

class DatabaseHealthMonitor {
  constructor() {
    this.pool = new Pool({
      connectionString: DATABASE_URL,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });
    
    this.metrics = {
      connectionCount: 0,
      slowQueries: 0,
      errors: 0,
      lastCheck: new Date(),
    };

    this.setupEventHandlers();
  }

  setupEventHandlers() {
    // Monitor pool events
    this.pool.on('connect', (client) => {
      this.metrics.connectionCount++;
      console.log(`🔗 New connection established. Total: ${this.metrics.connectionCount}`);
    });

    this.pool.on('remove', (client) => {
      this.metrics.connectionCount--;
      console.log(`📤 Connection removed. Total: ${this.metrics.connectionCount}`);
    });

    this.pool.on('error', (err, client) => {
      this.metrics.errors++;
      console.error('❌ Unexpected database error:', err.message);
      this.handleDatabaseError(err);
    });

    // Graceful shutdown
    process.on('SIGINT', () => {
      console.log('\n🛑 Shutting down database monitor...');
      this.shutdown();
    });

    process.on('SIGTERM', () => {
      console.log('\n🛑 Shutting down database monitor...');
      this.shutdown();
    });
  }

  async checkDatabaseHealth() {
    try {
      const client = await this.pool.connect();
      
      try {
        // Basic connectivity test
        const startTime = Date.now();
        await client.query('SELECT 1');
        const responseTime = Date.now() - startTime;

        if (responseTime > 1000) {
          console.warn(`⚠️  Slow database response: ${responseTime}ms`);
          this.metrics.slowQueries++;
        }

        // Check active connections
        const connectionsResult = await client.query(`
          SELECT count(*) as active_connections 
          FROM pg_stat_activity 
          WHERE state = 'active'
        `);
        const activeConnections = parseInt(connectionsResult.rows[0].active_connections);

        // Check database size
        const sizeResult = await client.query(`
          SELECT pg_size_pretty(pg_database_size(current_database())) as db_size
        `);
        const dbSize = sizeResult.rows[0].db_size;

        // Check for long-running queries
        const longQueriesResult = await client.query(`
          SELECT count(*) as long_queries
          FROM pg_stat_activity 
          WHERE state = 'active' 
          AND now() - query_start > interval '30 seconds'
        `);
        const longQueries = parseInt(longQueriesResult.rows[0].long_queries);

        // Check cache hit ratio
        const cacheResult = await client.query(`
          SELECT round(
            (blks_hit::float / (blks_hit + blks_read) * 100)::numeric, 2
          ) as cache_hit_ratio
          FROM pg_stat_database
          WHERE datname = current_database()
        `);
        const cacheHitRatio = parseFloat(cacheResult.rows[0].cache_hit_ratio || 0);

        // Display health status
        console.log('\n📊 Database Health Status:');
        console.log(`   Response Time: ${responseTime}ms`);
        console.log(`   Active Connections: ${activeConnections}`);
        console.log(`   Database Size: ${dbSize}`);
        console.log(`   Long Queries: ${longQueries}`);
        console.log(`   Cache Hit Ratio: ${cacheHitRatio}%`);
        console.log(`   Pool Connections: ${this.pool.totalCount}/${this.pool.options.max}`);

        // Alert on concerning metrics
        if (activeConnections > 15) {
          console.warn('⚠️  HIGH CONNECTION COUNT - Risk of connection limit reached');
        }

        if (longQueries > 0) {
          console.warn('⚠️  LONG-RUNNING QUERIES DETECTED - Risk of blocking');
          await this.showLongQueries(client);
        }

        if (cacheHitRatio < 95) {
          console.warn('⚠️  LOW CACHE HIT RATIO - Performance issue detected');
        }

        if (this.pool.totalCount > this.pool.options.max * 0.8) {
          console.warn('⚠️  HIGH POOL USAGE - Consider increasing pool size');
        }

      } finally {
        client.release();
      }

    } catch (error) {
      console.error('❌ Health check failed:', error.message);
      this.metrics.errors++;
      
      if (error.code === 'ECONNREFUSED') {
        console.error('💥 DATABASE IS DOWN - PostgreSQL server not responding');
        await this.attemptReconnection();
      }
    }
  }

  async showLongQueries(client) {
    try {
      const result = await client.query(`
        SELECT pid, now() - query_start as duration, query
        FROM pg_stat_activity 
        WHERE state = 'active' 
        AND now() - query_start > interval '30 seconds'
        ORDER BY duration DESC
        LIMIT 5
      `);

      if (result.rows.length > 0) {
        console.log('\n🐌 Long-running queries:');
        result.rows.forEach((row, index) => {
          console.log(`   ${index + 1}. PID ${row.pid} (${row.duration})`);
          console.log(`      Query: ${row.query.substring(0, 100)}...`);
        });
      }
    } catch (error) {
      console.error('Failed to fetch long queries:', error.message);
    }
  }

  async attemptReconnection() {
    console.log('🔄 Attempting to reconnect to database...');
    
    let attempts = 0;
    const maxAttempts = 5;
    
    while (attempts < maxAttempts) {
      try {
        await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
        
        const testPool = new Pool({
          connectionString: DATABASE_URL,
          max: 1,
          connectionTimeoutMillis: 5000,
        });
        
        const client = await testPool.connect();
        await client.query('SELECT 1');
        client.release();
        await testPool.end();
        
        console.log('✅ Database connection restored');
        return true;
        
      } catch (error) {
        attempts++;
        console.log(`💔 Reconnection attempt ${attempts}/${maxAttempts} failed`);
        
        if (attempts === maxAttempts) {
          console.error('🚨 CRITICAL: Database is completely unavailable');
          console.error('📞 Contact system administrator immediately');
        }
      }
    }
    
    return false;
  }

  handleDatabaseError(error) {
    switch (error.code) {
      case '53300': // Too many connections
        console.error('🚨 CRITICAL: Too many database connections');
        console.error('💡 Solution: Restart application or kill idle connections');
        break;
        
      case '53200': // Out of memory
        console.error('🚨 CRITICAL: Database out of memory');
        console.error('💡 Solution: Reduce memory usage or restart PostgreSQL');
        break;
        
      case '57P01': // Admin shutdown
        console.error('🚨 CRITICAL: Database was shut down by administrator');
        break;
        
      case 'ENOTFOUND':
        console.error('🚨 CRITICAL: Database server not found');
        console.error('💡 Solution: Check DATABASE_URL and network connectivity');
        break;
        
      default:
        console.error(`🚨 Database error (${error.code}): ${error.message}`);
    }
  }

  async startMonitoring(intervalSeconds = 30) {
    console.log('🚀 Starting database health monitoring...');
    console.log(`📅 Check interval: ${intervalSeconds} seconds`);
    
    // Initial health check
    await this.checkDatabaseHealth();
    
    // Start periodic monitoring
    this.monitorInterval = setInterval(async () => {
      await this.checkDatabaseHealth();
      this.metrics.lastCheck = new Date();
    }, intervalSeconds * 1000);
    
    console.log('\n✅ Database monitor is running');
    console.log('Press Ctrl+C to stop monitoring\n');
  }

  async shutdown() {
    if (this.monitorInterval) {
      clearInterval(this.monitorInterval);
    }
    
    try {
      await this.pool.end();
      console.log('✅ Database connections closed gracefully');
    } catch (error) {
      console.error('Error during shutdown:', error.message);
    }
    
    process.exit(0);
  }

  getMetrics() {
    return {
      ...this.metrics,
      uptime: Date.now() - this.metrics.lastCheck.getTime(),
    };
  }
}

// Start monitoring if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const monitor = new DatabaseHealthMonitor();
  monitor.startMonitoring(30); // Check every 30 seconds
}

export default DatabaseHealthMonitor;