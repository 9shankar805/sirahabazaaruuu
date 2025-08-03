#!/usr/bin/env node

/**
 * Ultra-Strong Database Wrapper
 * Maximum protection with circuit breaker, automatic recovery, and intelligent failover
 */

import { Pool } from 'pg';
import { EventEmitter } from 'events';

class UltraStrongDatabaseWrapper extends EventEmitter {
  constructor(connectionString) {
    super();
    this.connectionString = connectionString;
    this.primaryPool = null;
    this.backupPool = null;
    
    // Circuit breaker state
    this.circuitState = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
    this.failureCount = 0;
    this.lastFailureTime = null;
    this.successCount = 0;
    
    // Circuit breaker thresholds
    this.failureThreshold = 5;
    this.recoveryTimeout = 30000; // 30 seconds
    this.successThreshold = 3;
    
    // Connection health tracking
    this.healthMetrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      avgResponseTime: 0,
      lastHealthCheck: Date.now()
    };
    
    // Retry configuration
    this.retryConfig = {
      maxRetries: 3,
      baseDelay: 1000,
      maxDelay: 10000,
      backoffMultiplier: 2
    };
    
    this.isInitialized = false;
    this.recoveryInterval = null;
  }

  async initialize() {
    console.log('🛡️ Initializing Ultra-Strong Database Wrapper...');
    
    await this.createPrimaryPool();
    await this.createBackupPool();
    this.startHealthMonitoring();
    this.startRecoveryService();
    
    this.isInitialized = true;
    console.log('✅ Ultra-Strong Database Wrapper Ready');
  }

  async createPrimaryPool() {
    this.primaryPool = new Pool({
      connectionString: this.connectionString,
      max: 8,
      min: 2,
      idleTimeoutMillis: 8000,
      connectionTimeoutMillis: 1500,
      acquireTimeoutMillis: 2000,
      createTimeoutMillis: 1500,
      destroyTimeoutMillis: 500,
      reapIntervalMillis: 250,
      createRetryIntervalMillis: 50,
      
      application_name: 'ultra_strong_primary',
      statement_timeout: 15000,
      idle_in_transaction_session_timeout: 3000,
      lock_timeout: 5000,
      
      keepAlive: true,
      keepAliveInitialDelayMillis: 5000,
      allowExitOnIdle: false,
      maxUses: 3000,
    });

    this.primaryPool.on('error', (err, client) => {
      this.handlePoolError('primary', err, client);
    });

    this.primaryPool.on('connect', (client) => {
      this.optimizeConnection(client);
    });
  }

  async createBackupPool() {
    this.backupPool = new Pool({
      connectionString: this.connectionString,
      max: 4,
      min: 1,
      idleTimeoutMillis: 15000,
      connectionTimeoutMillis: 3000,
      acquireTimeoutMillis: 4000,
      
      application_name: 'ultra_strong_backup',
      statement_timeout: 30000,
      idle_in_transaction_session_timeout: 10000,
      
      keepAlive: true,
      allowExitOnIdle: false,
    });

    this.backupPool.on('error', (err, client) => {
      this.handlePoolError('backup', err, client);
    });
  }

  async optimizeConnection(client) {
    try {
      await client.query(`
        SET work_mem = '2MB';
        SET maintenance_work_mem = '32MB';
        SET effective_cache_size = '128MB';
        SET shared_preload_libraries = '';
        SET log_statement = 'none';
        SET log_min_duration_statement = 5000;
        SET deadlock_timeout = '1s';
        SET max_locks_per_transaction = 64;
      `);
    } catch (error) {
      console.warn('Connection optimization failed:', error.message);
    }
  }

  handlePoolError(poolType, err, client) {
    console.error(`${poolType} pool error:`, err.message);
    this.recordFailure();
    
    // Handle specific error types
    switch (err.code) {
      case '53300': // Too many connections
        this.triggerEmergencyCleanup();
        break;
      case '53200': // Out of memory
        this.reduceMemoryUsage();
        break;
      case '57P01': // Admin shutdown
        this.circuitState = 'OPEN';
        break;
      case 'ECONNREFUSED':
        this.circuitState = 'OPEN';
        break;
    }
  }

  async executeQuery(query, params = [], options = {}) {
    if (!this.isInitialized) {
      throw new Error('Database wrapper not initialized');
    }

    const startTime = Date.now();
    this.healthMetrics.totalRequests++;

    // Check circuit breaker
    if (this.circuitState === 'OPEN') {
      if (this.shouldAttemptRecovery()) {
        this.circuitState = 'HALF_OPEN';
        console.log('🔄 Circuit breaker: Attempting recovery');
      } else {
        throw new Error('Circuit breaker is OPEN - database unavailable');
      }
    }

    let lastError = null;
    const maxRetries = options.maxRetries || this.retryConfig.maxRetries;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const result = await this.attemptQuery(query, params, attempt);
        
        // Success - update metrics
        const responseTime = Date.now() - startTime;
        this.recordSuccess(responseTime);
        
        return result;
        
      } catch (error) {
        lastError = error;
        console.warn(`Query attempt ${attempt + 1} failed:`, error.message);
        
        if (attempt < maxRetries) {
          const delay = this.calculateRetryDelay(attempt);
          await this.sleep(delay);
        }
      }
    }

    // All retries failed
    this.recordFailure();
    throw lastError;
  }

  async attemptQuery(query, params, attempt) {
    const pool = this.selectPool(attempt);
    const client = await pool.connect();
    
    try {
      // Add query timeout wrapper
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Query timeout')), 25000);
      });
      
      const queryPromise = client.query(query, params);
      const result = await Promise.race([queryPromise, timeoutPromise]);
      
      return result;
      
    } finally {
      client.release();
    }
  }

  selectPool(attempt) {
    // Use backup pool on retries or when primary is stressed
    if (attempt > 0 || this.circuitState === 'HALF_OPEN') {
      return this.backupPool;
    }
    
    // Check primary pool health
    const primaryUsage = (this.primaryPool.totalCount / this.primaryPool.options.max) * 100;
    if (primaryUsage > 75) {
      return this.backupPool;
    }
    
    return this.primaryPool;
  }

  calculateRetryDelay(attempt) {
    const baseDelay = this.retryConfig.baseDelay;
    const multiplier = Math.pow(this.retryConfig.backoffMultiplier, attempt);
    const delay = Math.min(baseDelay * multiplier, this.retryConfig.maxDelay);
    
    // Add jitter to prevent thundering herd
    const jitter = Math.random() * 0.3 * delay;
    return delay + jitter;
  }

  recordSuccess(responseTime) {
    this.healthMetrics.successfulRequests++;
    this.successCount++;
    
    // Update average response time
    const totalTime = this.healthMetrics.avgResponseTime * (this.healthMetrics.successfulRequests - 1);
    this.healthMetrics.avgResponseTime = (totalTime + responseTime) / this.healthMetrics.successfulRequests;
    
    // Circuit breaker recovery
    if (this.circuitState === 'HALF_OPEN') {
      if (this.successCount >= this.successThreshold) {
        this.circuitState = 'CLOSED';
        this.failureCount = 0;
        this.successCount = 0;
        console.log('✅ Circuit breaker: RECOVERED');
      }
    }
  }

  recordFailure() {
    this.healthMetrics.failedRequests++;
    this.failureCount++;
    this.lastFailureTime = Date.now();
    this.successCount = 0;
    
    if (this.failureCount >= this.failureThreshold) {
      this.circuitState = 'OPEN';
      console.log('🚨 Circuit breaker: OPENED due to failures');
    }
  }

  shouldAttemptRecovery() {
    return Date.now() - this.lastFailureTime > this.recoveryTimeout;
  }

  startHealthMonitoring() {
    setInterval(async () => {
      await this.performHealthCheck();
    }, 10000); // Every 10 seconds
  }

  async performHealthCheck() {
    try {
      const result = await this.executeQuery('SELECT 1 as health_check', []);
      
      if (result.rows[0].health_check === 1) {
        this.healthMetrics.lastHealthCheck = Date.now();
        
        // Auto-recovery if circuit is open but health check passes
        if (this.circuitState === 'OPEN') {
          this.circuitState = 'HALF_OPEN';
          console.log('🔄 Auto-recovery initiated - health check passed');
        }
      }
      
    } catch (error) {
      console.warn('Health check failed:', error.message);
    }
  }

  startRecoveryService() {
    this.recoveryInterval = setInterval(async () => {
      if (this.circuitState === 'OPEN') {
        await this.attemptRecovery();
      }
      
      await this.performMaintenance();
    }, 30000); // Every 30 seconds
  }

  async attemptRecovery() {
    console.log('🔧 Attempting database recovery...');
    
    try {
      // Try to recreate pools
      await this.primaryPool.end();
      await this.createPrimaryPool();
      
      // Test connectivity
      const client = await this.primaryPool.connect();
      await client.query('SELECT version()');
      client.release();
      
      console.log('✅ Recovery successful');
      this.circuitState = 'HALF_OPEN';
      this.failureCount = 0;
      
    } catch (error) {
      console.error('❌ Recovery failed:', error.message);
    }
  }

  async performMaintenance() {
    try {
      const client = await this.backupPool.connect();
      
      try {
        // Kill long-running idle connections
        await client.query(`
          SELECT pg_terminate_backend(pid)
          FROM pg_stat_activity
          WHERE state = 'idle'
          AND now() - state_change > interval '2 minutes'
          AND pid != pg_backend_pid()
          AND application_name NOT LIKE 'ultra_strong%'
        `);
        
        // Cancel very long queries
        await client.query(`
          SELECT pg_cancel_backend(pid)
          FROM pg_stat_activity
          WHERE state = 'active'
          AND now() - query_start > interval '1 minute'
          AND pid != pg_backend_pid()
          AND application_name NOT LIKE 'ultra_strong%'
        `);
        
      } finally {
        client.release();
      }
      
    } catch (error) {
      console.warn('Maintenance failed:', error.message);
    }
  }

  async triggerEmergencyCleanup() {
    console.log('🚨 Emergency cleanup initiated');
    
    try {
      const client = await this.backupPool.connect();
      
      try {
        await client.query(`
          SELECT pg_terminate_backend(pid)
          FROM pg_stat_activity
          WHERE state = 'idle'
          AND pid != pg_backend_pid()
          AND application_name NOT LIKE 'ultra_strong%'
        `);
        
      } finally {
        client.release();
      }
      
    } catch (error) {
      console.error('Emergency cleanup failed:', error.message);
    }
  }

  async reduceMemoryUsage() {
    console.log('💾 Reducing memory usage');
    
    try {
      const client = await this.backupPool.connect();
      
      try {
        await client.query(`
          SET work_mem = '1MB';
          SET maintenance_work_mem = '16MB';
          SET effective_cache_size = '64MB';
        `);
        
      } finally {
        client.release();
      }
      
    } catch (error) {
      console.warn('Memory reduction failed:', error.message);
    }
  }

  getStatus() {
    return {
      circuitState: this.circuitState,
      healthMetrics: this.healthMetrics,
      failureCount: this.failureCount,
      successCount: this.successCount,
      primaryPool: {
        total: this.primaryPool?.totalCount || 0,
        idle: this.primaryPool?.idleCount || 0,
        waiting: this.primaryPool?.waitingCount || 0,
      },
      backupPool: {
        total: this.backupPool?.totalCount || 0,
        idle: this.backupPool?.idleCount || 0,
        waiting: this.backupPool?.waitingCount || 0,
      }
    };
  }

  async sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async shutdown() {
    console.log('🛑 Shutting down Ultra-Strong Database Wrapper');
    
    if (this.recoveryInterval) {
      clearInterval(this.recoveryInterval);
    }
    
    await Promise.all([
      this.primaryPool?.end(),
      this.backupPool?.end()
    ]);
    
    console.log('✅ Ultra-Strong wrapper shutdown complete');
  }
}

export default UltraStrongDatabaseWrapper;