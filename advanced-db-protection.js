#!/usr/bin/env node

/**
 * Advanced PostgreSQL Protection System
 * Ultra-robust crash prevention with automatic recovery and intelligent monitoring
 */

import { Pool } from 'pg';
import { EventEmitter } from 'events';

class AdvancedDatabaseProtection extends EventEmitter {
  constructor() {
    super();
    this.isActive = false;
    this.healthScore = 100;
    this.criticalThresholds = {
      connectionCount: 12,
      responseTime: 2000,
      activeQueries: 5,
      memoryUsage: 85,
      diskUsage: 90,
      errorRate: 0.1
    };
    
    this.metrics = {
      totalQueries: 0,
      errors: 0,
      slowQueries: 0,
      connectionPeaks: 0,
      recoveryAttempts: 0,
      uptime: Date.now()
    };

    this.protectionPool = null;
    this.monitoringIntervals = [];
    this.emergencyMode = false;
  }

  async initialize() {
    console.log('🛡️ Initializing Advanced Database Protection...');
    
    this.protectionPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 20,
      min: 3,
      idleTimeoutMillis: 15000,
      connectionTimeoutMillis: 2000,
      acquireTimeoutMillis: 3000,
      createTimeoutMillis: 2000,
      destroyTimeoutMillis: 3000,
      reapIntervalMillis: 500,
      createRetryIntervalMillis: 100,
      
      // Advanced pool settings
      allowExitOnIdle: false,
      maxUses: 7500,
      
      // Connection validation
      application_name: 'siraha_bazaar_protection',
      statement_timeout: 25000,
      idle_in_transaction_session_timeout: 8000,
      lock_timeout: 10000,
    });

    // Enhanced error handling
    this.protectionPool.on('error', (err, client) => {
      this.handlePoolError(err, client);
    });

    this.protectionPool.on('connect', (client) => {
      this.metrics.totalQueries++;
      this.optimizeConnection(client);
    });

    this.protectionPool.on('acquire', (client) => {
      client.lastUsed = Date.now();
    });

    this.protectionPool.on('remove', (client) => {
      console.log('🔌 Connection removed from pool');
    });

    await this.createMissingTables();
    this.startAdvancedMonitoring();
    this.isActive = true;
    
    console.log('✅ Advanced Database Protection Active');
  }

  async optimizeConnection(client) {
    try {
      // Optimize connection settings for crash prevention
      await client.query(`
        SET work_mem = '4MB';
        SET maintenance_work_mem = '64MB';
        SET effective_cache_size = '256MB';
        SET random_page_cost = 1.1;
        SET cpu_tuple_cost = 0.01;
        SET cpu_index_tuple_cost = 0.005;
        SET cpu_operator_cost = 0.0025;
        SET effective_io_concurrency = 200;
        SET max_worker_processes = 8;
        SET max_parallel_workers_per_gather = 2;
        SET max_parallel_workers = 8;
        SET wal_buffers = '16MB';
        SET checkpoint_completion_target = 0.9;
        SET default_statistics_target = 100;
      `);
    } catch (error) {
      console.warn('Connection optimization failed:', error.message);
    }
  }

  async createMissingTables() {
    const client = await this.protectionPool.connect();
    try {
      // Create missing tables that were causing errors
      await client.query(`
        CREATE TABLE IF NOT EXISTS website_visits (
          id SERIAL PRIMARY KEY,
          user_id INTEGER,
          ip_address INET,
          user_agent TEXT,
          page_url VARCHAR(500),
          referrer VARCHAR(500),
          session_id VARCHAR(100),
          visit_duration INTEGER DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_website_visits_user_id ON website_visits(user_id);
        CREATE INDEX IF NOT EXISTS idx_website_visits_created_at ON website_visits(created_at);
      `);

      // Create protection monitoring tables
      await client.query(`
        CREATE TABLE IF NOT EXISTS db_health_logs (
          id SERIAL PRIMARY KEY,
          health_score INTEGER,
          connection_count INTEGER,
          active_queries INTEGER,
          response_time INTEGER,
          error_rate DECIMAL(5,4),
          memory_usage DECIMAL(5,2),
          disk_usage DECIMAL(5,2),
          status VARCHAR(20),
          details JSONB,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_db_health_logs_created_at ON db_health_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_db_health_logs_status ON db_health_logs(status);
      `);

      console.log('✅ Missing tables created successfully');
    } finally {
      client.release();
    }
  }

  startAdvancedMonitoring() {
    // Real-time health monitoring (every 5 seconds)
    this.monitoringIntervals.push(setInterval(async () => {
      await this.performHealthCheck();
    }, 5000));

    // Connection optimization (every 30 seconds)
    this.monitoringIntervals.push(setInterval(async () => {
      await this.optimizeConnections();
    }, 30000));

    // Proactive cleanup (every 10 seconds)
    this.monitoringIntervals.push(setInterval(async () => {
      await this.proactiveCleanup();
    }, 10000));

    // Deep analysis (every 2 minutes)
    this.monitoringIntervals.push(setInterval(async () => {
      await this.deepHealthAnalysis();
    }, 120000));

    // Emergency recovery check (every 3 seconds)
    this.monitoringIntervals.push(setInterval(async () => {
      await this.emergencyRecoveryCheck();
    }, 3000));
  }

  async performHealthCheck() {
    try {
      const startTime = Date.now();
      const client = await this.protectionPool.connect();
      const connectTime = Date.now() - startTime;

      try {
        const queryStart = Date.now();
        const result = await client.query(`
          SELECT 
            count(*) as total_connections,
            count(*) FILTER (WHERE state = 'active') as active_connections,
            count(*) FILTER (WHERE state = 'idle') as idle_connections,
            count(*) FILTER (WHERE now() - query_start > interval '15 seconds') as long_queries,
            pg_database_size(current_database()) as db_size
          FROM pg_stat_activity
        `);
        const queryTime = Date.now() - queryStart;

        const stats = result.rows[0];
        this.updateHealthScore(stats, connectTime, queryTime);

        // Log health data
        await this.logHealthData(stats, connectTime, queryTime);

        // Check for immediate threats
        this.checkCriticalThresholds(stats, connectTime, queryTime);

      } finally {
        client.release();
      }
    } catch (error) {
      this.metrics.errors++;
      this.healthScore = Math.max(0, this.healthScore - 10);
      console.error('Health check failed:', error.message);
      
      if (error.code === 'ECONNREFUSED') {
        await this.triggerEmergencyRecovery('database_down');
      }
    }
  }

  updateHealthScore(stats, connectTime, queryTime) {
    let score = 100;

    // Connection penalty
    if (stats.total_connections > 15) score -= 15;
    if (stats.active_connections > 8) score -= 10;

    // Performance penalty
    if (connectTime > 1500) score -= 10;
    if (queryTime > 500) score -= 5;

    // Long query penalty
    if (stats.long_queries > 0) score -= 20;

    // Pool utilization penalty
    const poolUsage = (this.protectionPool.totalCount / this.protectionPool.options.max) * 100;
    if (poolUsage > 80) score -= 15;

    this.healthScore = Math.max(0, Math.min(100, score));

    if (this.healthScore < 50) {
      console.warn(`⚠️ Database health declining: ${this.healthScore}%`);
    }
  }

  async checkCriticalThresholds(stats, connectTime, queryTime) {
    const threats = [];

    if (stats.total_connections >= this.criticalThresholds.connectionCount) {
      threats.push('connection_overload');
    }
    if (connectTime >= this.criticalThresholds.responseTime) {
      threats.push('slow_response');
    }
    if (stats.active_connections >= this.criticalThresholds.activeQueries) {
      threats.push('query_bottleneck');
    }
    if (stats.long_queries > 2) {
      threats.push('query_deadlock');
    }

    if (threats.length > 0) {
      console.warn(`🚨 Critical threats detected: ${threats.join(', ')}`);
      await this.mitigateThreats(threats);
    }
  }

  async mitigateThreats(threats) {
    const client = await this.protectionPool.connect();
    try {
      for (const threat of threats) {
        switch (threat) {
          case 'connection_overload':
            await this.forceCloseIdleConnections(client);
            break;
          case 'slow_response':
            await this.optimizeCurrentQueries(client);
            break;
          case 'query_bottleneck':
            await this.terminateLongQueries(client);
            break;
          case 'query_deadlock':
            await this.resolveDeadlocks(client);
            break;
        }
      }
    } finally {
      client.release();
    }
  }

  async forceCloseIdleConnections(client) {
    console.log('🔧 Force closing idle connections...');
    await client.query(`
      SELECT pg_terminate_backend(pid)
      FROM pg_stat_activity
      WHERE state = 'idle'
      AND now() - state_change > interval '30 seconds'
      AND pid != pg_backend_pid()
      AND application_name != 'siraha_bazaar_protection'
    `);
  }

  async terminateLongQueries(client) {
    console.log('⚡ Terminating long-running queries...');
    await client.query(`
      SELECT pg_terminate_backend(pid)
      FROM pg_stat_activity
      WHERE state = 'active'
      AND now() - query_start > interval '45 seconds'
      AND pid != pg_backend_pid()
      AND application_name != 'siraha_bazaar_protection'
    `);
  }

  async resolveDeadlocks(client) {
    console.log('🔓 Resolving potential deadlocks...');
    await client.query(`
      SELECT pg_cancel_backend(pid)
      FROM pg_stat_activity
      WHERE state = 'active'
      AND wait_event_type = 'Lock'
      AND now() - query_start > interval '20 seconds'
    `);
  }

  async optimizeCurrentQueries(client) {
    console.log('⚡ Optimizing current database session...');
    await client.query(`
      SET work_mem = '2MB';
      SET enable_hashjoin = on;
      SET enable_mergejoin = on;
      SET enable_nestloop = off;
    `);
  }

  async proactiveCleanup() {
    if (this.emergencyMode) return;

    try {
      const client = await this.protectionPool.connect();
      try {
        // Clean up old logs and temporary data
        await client.query(`
          DELETE FROM db_health_logs 
          WHERE created_at < now() - interval '7 days'
        `);

        await client.query(`
          DELETE FROM website_visits 
          WHERE created_at < now() - interval '30 days'
        `);

        // Update table statistics
        await client.query('ANALYZE;');

      } finally {
        client.release();
      }
    } catch (error) {
      console.warn('Proactive cleanup failed:', error.message);
    }
  }

  async deepHealthAnalysis() {
    try {
      const client = await this.protectionPool.connect();
      try {
        // Check for table bloat
        const bloatResult = await client.query(`
          SELECT schemaname, tablename, 
                 pg_size_pretty(pg_total_relation_size(tablename::text)) as size
          FROM pg_tables 
          WHERE schemaname = 'public'
          ORDER BY pg_total_relation_size(tablename::text) DESC
          LIMIT 5
        `);

        // Check index usage
        const indexResult = await client.query(`
          SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
          FROM pg_stat_user_indexes
          WHERE idx_tup_read = 0
          LIMIT 5
        `);

        // Log findings
        if (bloatResult.rows.length > 0) {
          console.log('📊 Largest tables:', bloatResult.rows);
        }

        if (indexResult.rows.length > 0) {
          console.log('🔍 Unused indexes detected:', indexResult.rows.length);
        }

      } finally {
        client.release();
      }
    } catch (error) {
      console.warn('Deep analysis failed:', error.message);
    }
  }

  async emergencyRecoveryCheck() {
    if (this.healthScore < 20) {
      await this.triggerEmergencyRecovery('critical_health');
    }

    if (this.metrics.errors > 10) {
      await this.triggerEmergencyRecovery('error_threshold');
    }
  }

  async triggerEmergencyRecovery(reason) {
    if (this.emergencyMode) return;

    console.log(`🚨 EMERGENCY RECOVERY TRIGGERED: ${reason}`);
    this.emergencyMode = true;
    this.metrics.recoveryAttempts++;

    try {
      // Emergency connection pool reset
      await this.protectionPool.end();
      
      // Wait before reconnecting
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Reinitialize with emergency settings
      this.protectionPool = new Pool({
        connectionString: process.env.DATABASE_URL,
        max: 5,
        min: 1,
        idleTimeoutMillis: 5000,
        connectionTimeoutMillis: 1000,
      });

      // Test emergency connection
      const client = await this.protectionPool.connect();
      await client.query('SELECT 1');
      client.release();

      console.log('✅ Emergency recovery successful');
      this.emergencyMode = false;
      this.healthScore = 50; // Partial recovery

    } catch (error) {
      console.error('❌ Emergency recovery failed:', error.message);
      // Last resort: wait and retry
      setTimeout(() => {
        this.emergencyMode = false;
      }, 30000);
    }
  }

  async logHealthData(stats, connectTime, queryTime) {
    try {
      const client = await this.protectionPool.connect();
      try {
        await client.query(`
          INSERT INTO db_health_logs 
          (health_score, connection_count, active_queries, response_time, 
           error_rate, status, details)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [
          this.healthScore,
          stats.total_connections,
          stats.active_connections,
          connectTime + queryTime,
          this.metrics.errors / Math.max(1, this.metrics.totalQueries),
          this.emergencyMode ? 'emergency' : 'normal',
          JSON.stringify({
            poolSize: this.protectionPool.totalCount,
            uptime: Date.now() - this.metrics.uptime,
            longQueries: stats.long_queries
          })
        ]);
      } finally {
        client.release();
      }
    } catch (error) {
      // Don't log logging errors to avoid recursion
    }
  }

  getStatus() {
    return {
      isActive: this.isActive,
      healthScore: this.healthScore,
      emergencyMode: this.emergencyMode,
      metrics: this.metrics,
      poolStatus: {
        total: this.protectionPool?.totalCount || 0,
        idle: this.protectionPool?.idleCount || 0,
        waiting: this.protectionPool?.waitingCount || 0
      },
      uptime: Math.floor((Date.now() - this.metrics.uptime) / 1000)
    };
  }

  async shutdown() {
    console.log('🛑 Shutting down Advanced Database Protection...');
    
    this.monitoringIntervals.forEach(interval => clearInterval(interval));
    
    if (this.protectionPool) {
      await this.protectionPool.end();
    }
    
    this.isActive = false;
    console.log('✅ Protection system shutdown complete');
  }
}

// Auto-start if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const protection = new AdvancedDatabaseProtection();
  
  protection.initialize().catch(console.error);
  
  // Graceful shutdown
  process.on('SIGINT', async () => {
    await protection.shutdown();
    process.exit(0);
  });
  
  process.on('SIGTERM', async () => {
    await protection.shutdown();
    process.exit(0);
  });
}

export default AdvancedDatabaseProtection;