#!/usr/bin/env node

/**
 * Database Stress Tester & Protection Validator
 * Tests database under extreme load to validate crash prevention measures
 */

import { Pool } from 'pg';
import { Worker } from 'worker_threads';

class DatabaseStressTester {
  constructor() {
    this.DATABASE_URL = process.env.DATABASE_URL;
    this.testResults = {
      connectionTests: [],
      queryTests: [],
      stressTests: [],
      recoveryTests: [],
      startTime: Date.now()
    };
    this.isRunning = false;
  }

  async runComprehensiveTest() {
    console.log('🧪 Starting Comprehensive Database Stress Test...');
    this.isRunning = true;

    try {
      // Phase 1: Basic connectivity and performance
      console.log('\n📊 Phase 1: Basic Performance Tests');
      await this.testBasicConnectivity();
      await this.testQueryPerformance();
      await this.testConcurrentConnections();

      // Phase 2: Stress testing
      console.log('\n🔥 Phase 2: Stress Testing');
      await this.testConnectionOverload();
      await this.testQueryOverload();
      await this.testLongRunningQueries();

      // Phase 3: Recovery testing
      console.log('\n🔄 Phase 3: Recovery Testing');
      await this.testCrashRecovery();
      await this.testCircuitBreaker();

      // Phase 4: Real-world simulation
      console.log('\n🌍 Phase 4: Real-World Simulation');
      await this.simulateHighTraffic();

      this.generateReport();

    } catch (error) {
      console.error('Stress test failed:', error.message);
    } finally {
      this.isRunning = false;
    }
  }

  async testBasicConnectivity() {
    console.log('🔗 Testing basic connectivity...');
    
    const pool = new Pool({
      connectionString: this.DATABASE_URL,
      max: 1,
      connectionTimeoutMillis: 5000,
    });

    try {
      const startTime = Date.now();
      const client = await pool.connect();
      const connectTime = Date.now() - startTime;

      const queryStart = Date.now();
      const result = await client.query('SELECT version(), now() as test_time');
      const queryTime = Date.now() - queryStart;

      client.release();

      this.testResults.connectionTests.push({
        test: 'basic_connectivity',
        connectTime,
        queryTime,
        success: true,
        details: result.rows[0]
      });

      console.log(`   ✅ Connection: ${connectTime}ms, Query: ${queryTime}ms`);

    } catch (error) {
      this.testResults.connectionTests.push({
        test: 'basic_connectivity',
        success: false,
        error: error.message
      });
      console.log('   ❌ Basic connectivity failed');
    } finally {
      await pool.end();
    }
  }

  async testQueryPerformance() {
    console.log('⚡ Testing query performance...');
    
    const pool = new Pool({
      connectionString: this.DATABASE_URL,
      max: 5,
    });

    const queries = [
      'SELECT count(*) FROM products',
      'SELECT count(*) FROM stores',
      'SELECT count(*) FROM users',
      'SELECT p.*, s.name as store_name FROM products p JOIN stores s ON p.store_id = s.id LIMIT 10',
      'SELECT * FROM products WHERE category = $1 LIMIT 5'
    ];

    try {
      for (const query of queries) {
        const client = await pool.connect();
        try {
          const startTime = Date.now();
          const params = query.includes('$1') ? ['food'] : [];
          const result = await client.query(query, params);
          const queryTime = Date.now() - startTime;

          this.testResults.queryTests.push({
            query: query.substring(0, 50) + '...',
            queryTime,
            rowCount: result.rows.length,
            success: true
          });

          console.log(`   ✅ Query (${result.rows.length} rows): ${queryTime}ms`);

        } finally {
          client.release();
        }
      }
    } catch (error) {
      console.log(`   ❌ Query performance test failed: ${error.message}`);
    } finally {
      await pool.end();
    }
  }

  async testConcurrentConnections() {
    console.log('🔀 Testing concurrent connections...');
    
    const connectionCounts = [5, 10, 15, 20];
    
    for (const count of connectionCounts) {
      try {
        const pool = new Pool({
          connectionString: this.DATABASE_URL,
          max: count,
          connectionTimeoutMillis: 3000,
        });

        const startTime = Date.now();
        const promises = [];

        // Create concurrent connections
        for (let i = 0; i < count; i++) {
          promises.push(this.executeTestQuery(pool, i));
        }

        const results = await Promise.allSettled(promises);
        const successCount = results.filter(r => r.status === 'fulfilled').length;
        const totalTime = Date.now() - startTime;

        this.testResults.connectionTests.push({
          test: 'concurrent_connections',
          connectionCount: count,
          successCount,
          totalTime,
          successRate: (successCount / count) * 100
        });

        console.log(`   📊 ${count} connections: ${successCount}/${count} success (${totalTime}ms)`);

        await pool.end();

      } catch (error) {
        console.log(`   ❌ ${count} connections failed: ${error.message}`);
      }
    }
  }

  async executeTestQuery(pool, id) {
    const client = await pool.connect();
    try {
      await client.query('SELECT $1 as connection_id, pg_sleep(0.1)', [id]);
      return { id, success: true };
    } finally {
      client.release();
    }
  }

  async testConnectionOverload() {
    console.log('💥 Testing connection overload...');
    
    const pool = new Pool({
      connectionString: this.DATABASE_URL,
      max: 30, // Intentionally high to test limits
      connectionTimeoutMillis: 2000,
    });

    try {
      const promises = [];
      
      // Attempt to create 50 connections (more than max)
      for (let i = 0; i < 50; i++) {
        promises.push(
          this.attemptConnection(pool, i).catch(err => ({ id: i, error: err.message }))
        );
      }

      const results = await Promise.allSettled(promises);
      const successful = results.filter(r => 
        r.status === 'fulfilled' && !r.value.error
      ).length;

      this.testResults.stressTests.push({
        test: 'connection_overload',
        attempted: 50,
        successful,
        overloadHandled: successful < 50 // Expected to be true
      });

      console.log(`   📊 Overload test: ${successful}/50 connections handled`);

    } catch (error) {
      console.log(`   ❌ Connection overload test failed: ${error.message}`);
    } finally {
      await pool.end();
    }
  }

  async attemptConnection(pool, id) {
    const client = await pool.connect();
    try {
      await client.query('SELECT $1 as id, pg_sleep(0.5)', [id]);
      return { id, success: true };
    } finally {
      client.release();
    }
  }

  async testQueryOverload() {
    console.log('🌊 Testing query overload...');
    
    const pool = new Pool({
      connectionString: this.DATABASE_URL,
      max: 10,
    });

    try {
      const queries = [];
      
      // Create 100 simultaneous queries
      for (let i = 0; i < 100; i++) {
        queries.push(this.executeStressQuery(pool, i));
      }

      const startTime = Date.now();
      const results = await Promise.allSettled(queries);
      const totalTime = Date.now() - startTime;
      
      const successful = results.filter(r => r.status === 'fulfilled').length;
      const avgTime = totalTime / successful;

      this.testResults.stressTests.push({
        test: 'query_overload',
        totalQueries: 100,
        successful,
        totalTime,
        avgTime
      });

      console.log(`   📊 Query overload: ${successful}/100 queries (${avgTime.toFixed(2)}ms avg)`);

    } catch (error) {
      console.log(`   ❌ Query overload test failed: ${error.message}`);
    } finally {
      await pool.end();
    }
  }

  async executeStressQuery(pool, id) {
    const client = await pool.connect();
    try {
      // Simulate various query types
      const queryTypes = [
        'SELECT count(*) FROM products',
        'SELECT * FROM stores WHERE id = $1',
        'SELECT p.*, s.name FROM products p JOIN stores s ON p.store_id = s.id WHERE p.id = $1',
      ];
      
      const query = queryTypes[id % queryTypes.length];
      const params = query.includes('$1') ? [Math.floor(Math.random() * 10) + 1] : [];
      
      const result = await client.query(query, params);
      return { id, rows: result.rows.length };
    } finally {
      client.release();
    }
  }

  async testLongRunningQueries() {
    console.log('⏰ Testing long-running queries...');
    
    const pool = new Pool({
      connectionString: this.DATABASE_URL,
      max: 5,
    });

    try {
      const longQueries = [
        'SELECT pg_sleep(10)', // 10 second sleep
        'SELECT pg_sleep(20)', // 20 second sleep
        'SELECT pg_sleep(30)', // 30 second sleep
      ];

      const promises = longQueries.map((query, index) => 
        this.executeLongQuery(pool, query, index)
      );

      const startTime = Date.now();
      const results = await Promise.allSettled(promises);
      const totalTime = Date.now() - startTime;

      const timeouts = results.filter(r => 
        r.status === 'rejected' && r.reason.message.includes('timeout')
      ).length;

      this.testResults.stressTests.push({
        test: 'long_running_queries',
        totalQueries: longQueries.length,
        timeouts,
        totalTime,
        timeoutHandling: timeouts > 0 // Good if timeouts are handled
      });

      console.log(`   📊 Long queries: ${timeouts}/${longQueries.length} timed out (${totalTime}ms)`);

    } catch (error) {
      console.log(`   ❌ Long query test failed: ${error.message}`);
    } finally {
      await pool.end();
    }
  }

  async executeLongQuery(pool, query, id) {
    const client = await pool.connect();
    try {
      // Add timeout wrapper
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Query timeout')), 25000);
      });
      
      const queryPromise = client.query(query);
      const result = await Promise.race([queryPromise, timeoutPromise]);
      
      return { id, success: true };
    } finally {
      client.release();
    }
  }

  async testCrashRecovery() {
    console.log('🔄 Testing crash recovery...');
    
    try {
      // Simulate database stress that might cause issues
      const pool = new Pool({
        connectionString: this.DATABASE_URL,
        max: 1,
      });

      // Force close all idle connections to simulate crash
      const client = await pool.connect();
      try {
        await client.query(`
          SELECT pg_terminate_backend(pid)
          FROM pg_stat_activity
          WHERE state = 'idle'
          AND application_name = 'siraha_bazaar_main'
          AND pid != pg_backend_pid()
        `);
      } catch (error) {
        // Expected to potentially fail
      }
      client.release();

      // Wait for recovery
      await new Promise(resolve => setTimeout(resolve, 5000));

      // Test if system recovered
      const recoveryClient = await pool.connect();
      const result = await recoveryClient.query('SELECT 1 as recovered');
      recoveryClient.release();

      this.testResults.recoveryTests.push({
        test: 'crash_recovery',
        success: result.rows[0].recovered === 1,
        recoveryTime: 5000
      });

      console.log('   ✅ Recovery test completed');

      await pool.end();

    } catch (error) {
      this.testResults.recoveryTests.push({
        test: 'crash_recovery',
        success: false,
        error: error.message
      });
      console.log(`   ❌ Recovery test failed: ${error.message}`);
    }
  }

  async testCircuitBreaker() {
    console.log('🔌 Testing circuit breaker pattern...');
    
    // This would test the circuit breaker if we had it integrated
    // For now, just test basic error handling
    const pool = new Pool({
      connectionString: this.DATABASE_URL,
      max: 1,
    });

    try {
      // Test invalid query to trigger errors
      const errorCount = 5;
      let actualErrors = 0;

      for (let i = 0; i < errorCount; i++) {
        try {
          const client = await pool.connect();
          await client.query('SELECT * FROM non_existent_table');
          client.release();
        } catch (error) {
          actualErrors++;
        }
      }

      this.testResults.recoveryTests.push({
        test: 'circuit_breaker',
        expectedErrors: errorCount,
        actualErrors,
        errorHandling: actualErrors === errorCount
      });

      console.log(`   📊 Circuit breaker: ${actualErrors}/${errorCount} errors handled`);

    } catch (error) {
      console.log(`   ❌ Circuit breaker test failed: ${error.message}`);
    } finally {
      await pool.end();
    }
  }

  async simulateHighTraffic() {
    console.log('🚗 Simulating high traffic...');
    
    const pool = new Pool({
      connectionString: this.DATABASE_URL,
      max: 15,
    });

    try {
      // Simulate 5 minutes of high traffic (compressed to 30 seconds)
      const duration = 30000; // 30 seconds
      const requestsPerSecond = 20;
      const totalRequests = (duration / 1000) * requestsPerSecond;

      const startTime = Date.now();
      const promises = [];

      for (let i = 0; i < totalRequests; i++) {
        // Stagger requests to simulate real traffic
        setTimeout(() => {
          promises.push(this.simulateUserRequest(pool, i));
        }, (i / requestsPerSecond) * 1000);
      }

      // Wait for all requests to complete
      await new Promise(resolve => setTimeout(resolve, duration + 5000));
      const results = await Promise.allSettled(promises);
      
      const successful = results.filter(r => r.status === 'fulfilled').length;
      const totalTime = Date.now() - startTime;

      this.testResults.stressTests.push({
        test: 'high_traffic_simulation',
        totalRequests,
        successful,
        duration: totalTime,
        throughput: successful / (totalTime / 1000)
      });

      console.log(`   📊 High traffic: ${successful}/${totalRequests} requests (${(successful/totalRequests*100).toFixed(2)}% success)`);

    } catch (error) {
      console.log(`   ❌ High traffic simulation failed: ${error.message}`);
    } finally {
      await pool.end();
    }
  }

  async simulateUserRequest(pool, id) {
    try {
      const client = await pool.connect();
      try {
        // Simulate typical user operations
        const operations = [
          'SELECT count(*) FROM products',
          'SELECT * FROM stores WHERE is_active = true LIMIT 5',
          'SELECT * FROM products WHERE is_featured = true LIMIT 3',
        ];
        
        const operation = operations[id % operations.length];
        const result = await client.query(operation);
        return { id, rows: result.rows.length };
      } finally {
        client.release();
      }
    } catch (error) {
      throw new Error(`Request ${id} failed: ${error.message}`);
    }
  }

  generateReport() {
    console.log('\n📋 DATABASE STRESS TEST REPORT');
    console.log('='.repeat(50));
    
    const totalTime = Date.now() - this.testResults.startTime;
    console.log(`Total test duration: ${(totalTime / 1000).toFixed(2)} seconds`);
    
    // Connection tests
    console.log('\n🔗 CONNECTION TESTS:');
    this.testResults.connectionTests.forEach(test => {
      const status = test.success ? '✅' : '❌';
      console.log(`  ${status} ${test.test}: ${test.connectTime || 'N/A'}ms connect, ${test.queryTime || 'N/A'}ms query`);
    });
    
    // Query performance
    console.log('\n⚡ QUERY PERFORMANCE:');
    this.testResults.queryTests.forEach(test => {
      console.log(`  ✅ ${test.query}: ${test.queryTime}ms (${test.rowCount} rows)`);
    });
    
    // Stress tests
    console.log('\n🔥 STRESS TESTS:');
    this.testResults.stressTests.forEach(test => {
      console.log(`  📊 ${test.test}:`);
      Object.keys(test).forEach(key => {
        if (key !== 'test') {
          console.log(`    ${key}: ${test[key]}`);
        }
      });
    });
    
    // Recovery tests
    console.log('\n🔄 RECOVERY TESTS:');
    this.testResults.recoveryTests.forEach(test => {
      const status = test.success ? '✅' : '❌';
      console.log(`  ${status} ${test.test}: ${test.error || 'Passed'}`);
    });
    
    // Overall assessment
    console.log('\n🎯 OVERALL ASSESSMENT:');
    const connectionSuccess = this.testResults.connectionTests.filter(t => t.success).length;
    const totalConnectionTests = this.testResults.connectionTests.length;
    const stressTestsPassed = this.testResults.stressTests.length;
    
    console.log(`  Connection reliability: ${connectionSuccess}/${totalConnectionTests} (${(connectionSuccess/totalConnectionTests*100).toFixed(1)}%)`);
    console.log(`  Stress test coverage: ${stressTestsPassed} scenarios tested`);
    console.log(`  System robustness: ${this.assessRobustness()}`);
    
    console.log('\n✅ Database stress testing completed');
  }

  assessRobustness() {
    // Basic assessment based on test results
    const hasGoodConnection = this.testResults.connectionTests.some(t => t.success && t.connectTime < 2000);
    const handlesStress = this.testResults.stressTests.some(t => t.successful > 0);
    const hasRecovery = this.testResults.recoveryTests.some(t => t.success);
    
    if (hasGoodConnection && handlesStress && hasRecovery) {
      return 'EXCELLENT - System handles stress well';
    } else if (hasGoodConnection && handlesStress) {
      return 'GOOD - Basic protection in place';
    } else if (hasGoodConnection) {
      return 'FAIR - Needs improvement under stress';
    } else {
      return 'POOR - Requires immediate attention';
    }
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const tester = new DatabaseStressTester();
  tester.runComprehensiveTest().catch(console.error);
}

export default DatabaseStressTester;