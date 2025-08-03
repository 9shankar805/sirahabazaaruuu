#!/usr/bin/env node

/**
 * Database Command Center
 * Unified monitoring, control, and protection dashboard for PostgreSQL
 */

import { Pool } from 'pg';
import { execSync } from 'child_process';

class DatabaseCommandCenter {
  constructor() {
    this.pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 3,
      min: 1,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
      application_name: 'db_command_center'
    });
    
    this.monitoring = {
      isActive: false,
      interval: null,
      alerts: [],
      metrics: {}
    };
    
    this.thresholds = {
      connectionCount: 10,
      responseTime: 1000,
      errorRate: 0.05,
      cpuUsage: 80,
      memoryUsage: 85
    };
  }

  async initialize() {
    console.log('🎛️ Database Command Center Initializing...');
    await this.displaySystemStatus();
    this.startRealTimeMonitoring();
    this.showMainMenu();
  }

  showMainMenu() {
    console.log('\n' + '='.repeat(60));
    console.log('🎛️  DATABASE COMMAND CENTER');
    console.log('='.repeat(60));
    console.log('1. 📊 Real-time Status Dashboard');
    console.log('2. 🔍 Deep Health Analysis');
    console.log('3. 🧪 Run Stress Test');
    console.log('4. 🛡️ Start Advanced Protection');
    console.log('5. 🔧 Emergency Cleanup');
    console.log('6. 📈 Performance Optimization');
    console.log('7. 💾 Backup & Recovery');
    console.log('8. ⚡ Quick Actions');
    console.log('9. 📋 Generate Report');
    console.log('0. 🚪 Exit');
    console.log('='.repeat(60));
    
    this.handleUserInput();
  }

  handleUserInput() {
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('data', async (key) => {
      const choice = key.toString();
      
      switch (choice) {
        case '1':
          await this.showRealtimeDashboard();
          break;
        case '2':
          await this.runDeepHealthAnalysis();
          break;
        case '3':
          await this.runStressTest();
          break;
        case '4':
          await this.startAdvancedProtection();
          break;
        case '5':
          await this.emergencyCleanup();
          break;
        case '6':
          await this.optimizePerformance();
          break;
        case '7':
          await this.backupRecovery();
          break;
        case '8':
          await this.quickActions();
          break;
        case '9':
          await this.generateReport();
          break;
        case '0':
        case '\u0003': // Ctrl+C
          await this.shutdown();
          process.exit(0);
        default:
          console.log('Invalid option. Press 1-9 or 0 to exit.');
      }
    });
  }

  async displaySystemStatus() {
    try {
      const client = await this.pool.connect();
      
      // Get basic system info
      const versionResult = await client.query('SELECT version()');
      const statsResult = await client.query(`
        SELECT 
          count(*) as total_connections,
          count(*) FILTER (WHERE state = 'active') as active_connections,
          count(*) FILTER (WHERE state = 'idle') as idle_connections,
          pg_database_size(current_database()) as db_size,
          current_database() as db_name
        FROM pg_stat_activity
      `);
      
      const stats = statsResult.rows[0];
      const version = versionResult.rows[0].version;
      
      console.log('\n🖥️  SYSTEM STATUS:');
      console.log(`   Database: ${stats.db_name}`);
      console.log(`   Version: ${version.split(' ')[1]}`);
      console.log(`   Size: ${this.formatBytes(stats.db_size)}`);
      console.log(`   Connections: ${stats.total_connections} (${stats.active_connections} active, ${stats.idle_connections} idle)`);
      
      // Get table info
      const tablesResult = await client.query(`
        SELECT 
          schemaname, 
          tablename, 
          pg_size_pretty(pg_total_relation_size(tablename::text)) as size
        FROM pg_tables 
        WHERE schemaname = 'public' 
        ORDER BY pg_total_relation_size(tablename::text) DESC 
        LIMIT 5
      `);
      
      console.log('\n📊 TOP TABLES:');
      tablesResult.rows.forEach(table => {
        console.log(`   ${table.tablename}: ${table.size}`);
      });
      
      client.release();
      
    } catch (error) {
      console.error('❌ Failed to get system status:', error.message);
    }
  }

  async showRealtimeDashboard() {
    console.clear();
    console.log('📊 REAL-TIME DASHBOARD (Press any key to return to menu)\n');
    
    const dashboardInterval = setInterval(async () => {
      try {
        const client = await this.pool.connect();
        
        const result = await client.query(`
          SELECT 
            count(*) as total_connections,
            count(*) FILTER (WHERE state = 'active') as active_connections,
            count(*) FILTER (WHERE state = 'idle') as idle_connections,
            count(*) FILTER (WHERE now() - query_start > interval '30 seconds') as long_queries,
            pg_database_size(current_database()) as db_size,
            extract(epoch from now()) as current_time
          FROM pg_stat_activity
        `);
        
        const stats = result.rows[0];
        const timestamp = new Date().toLocaleTimeString();
        
        // Clear previous output and redraw
        process.stdout.write('\u001b[H\u001b[J');
        console.log('📊 REAL-TIME DASHBOARD (Press any key to return to menu)\n');
        console.log(`⏰ ${timestamp}`);
        console.log(`🔗 Connections: ${stats.total_connections} total, ${stats.active_connections} active, ${stats.idle_connections} idle`);
        console.log(`⚠️  Long Queries: ${stats.long_queries}`);
        console.log(`💾 Database Size: ${this.formatBytes(stats.db_size)}`);
        
        // Connection status indicator
        const connectionStatus = stats.total_connections > this.thresholds.connectionCount ? '🔴' : '🟢';
        const queryStatus = stats.long_queries > 0 ? '🔴' : '🟢';
        
        console.log(`\n${connectionStatus} Connection Health: ${stats.total_connections}/${this.thresholds.connectionCount}`);
        console.log(`${queryStatus} Query Health: ${stats.long_queries} long-running`);
        
        client.release();
        
      } catch (error) {
        console.log('❌ Dashboard error:', error.message);
      }
    }, 2000);
    
    // Wait for user input to exit dashboard
    process.stdin.once('data', () => {
      clearInterval(dashboardInterval);
      console.clear();
      this.showMainMenu();
    });
  }

  async runDeepHealthAnalysis() {
    console.log('\n🔍 Running Deep Health Analysis...');
    
    try {
      const client = await this.pool.connect();
      
      // Connection analysis
      const connResult = await client.query(`
        SELECT 
          application_name,
          state,
          count(*) as count,
          avg(extract(epoch from now() - query_start)) as avg_duration
        FROM pg_stat_activity 
        WHERE state != 'idle'
        GROUP BY application_name, state
        ORDER BY count DESC
      `);
      
      console.log('\n📊 Connection Analysis:');
      connResult.rows.forEach(row => {
        console.log(`   ${row.application_name || 'Unknown'}: ${row.count} ${row.state} (avg: ${Math.round(row.avg_duration || 0)}s)`);
      });
      
      // Lock analysis
      const lockResult = await client.query(`
        SELECT 
          locktype, 
          mode, 
          count(*) as count
        FROM pg_locks 
        WHERE granted = true
        GROUP BY locktype, mode
        ORDER BY count DESC
        LIMIT 5
      `);
      
      console.log('\n🔒 Lock Analysis:');
      lockResult.rows.forEach(row => {
        console.log(`   ${row.locktype} (${row.mode}): ${row.count} locks`);
      });
      
      // Performance analysis
      const perfResult = await client.query(`
        SELECT 
          query,
          calls,
          total_time,
          mean_time,
          rows
        FROM pg_stat_statements 
        ORDER BY total_time DESC 
        LIMIT 5
      `).catch(() => ({ rows: [] })); // pg_stat_statements might not be enabled
      
      if (perfResult.rows.length > 0) {
        console.log('\n⚡ Performance Analysis:');
        perfResult.rows.forEach(row => {
          console.log(`   Calls: ${row.calls}, Avg: ${Math.round(row.mean_time)}ms`);
          console.log(`   Query: ${row.query.substring(0, 60)}...`);
        });
      }
      
      client.release();
      
    } catch (error) {
      console.error('❌ Health analysis failed:', error.message);
    }
    
    console.log('\n✅ Deep health analysis complete. Press any key to continue...');
    process.stdin.once('data', () => this.showMainMenu());
  }

  async emergencyCleanup() {
    console.log('\n🔧 Starting Emergency Cleanup...');
    
    try {
      const client = await this.pool.connect();
      
      // Kill idle connections
      const idleResult = await client.query(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE state = 'idle'
        AND now() - state_change > interval '5 minutes'
        AND pid != pg_backend_pid()
      `);
      
      console.log(`   ✅ Terminated ${idleResult.rowCount} idle connections`);
      
      // Cancel long queries
      const longResult = await client.query(`
        SELECT pg_cancel_backend(pid)
        FROM pg_stat_activity
        WHERE state = 'active'
        AND now() - query_start > interval '2 minutes'
        AND pid != pg_backend_pid()
      `);
      
      console.log(`   ✅ Cancelled ${longResult.rowCount} long queries`);
      
      // Clean old logs
      await client.query(`
        DELETE FROM db_health_logs 
        WHERE created_at < now() - interval '7 days'
      `).catch(() => console.log('   ⚠️ No health logs table found'));
      
      console.log('   ✅ Cleaned old health logs');
      
      // Analyze tables
      await client.query('ANALYZE');
      console.log('   ✅ Updated table statistics');
      
      client.release();
      
    } catch (error) {
      console.error('❌ Emergency cleanup failed:', error.message);
    }
    
    console.log('\n✅ Emergency cleanup complete. Press any key to continue...');
    process.stdin.once('data', () => this.showMainMenu());
  }

  async optimizePerformance() {
    console.log('\n📈 Starting Performance Optimization...');
    
    try {
      const client = await this.pool.connect();
      
      // Optimize connection settings
      await client.query(`
        SET work_mem = '4MB';
        SET maintenance_work_mem = '64MB';
        SET effective_cache_size = '256MB';
        SET random_page_cost = 1.1;
        SET effective_io_concurrency = 200;
      `);
      
      console.log('   ✅ Optimized memory settings');
      
      // Check for missing indexes
      const indexResult = await client.query(`
        SELECT 
          schemaname, 
          tablename, 
          indexname, 
          idx_tup_read, 
          idx_tup_fetch
        FROM pg_stat_user_indexes
        WHERE idx_tup_read = 0
        AND schemaname = 'public'
        LIMIT 5
      `);
      
      if (indexResult.rows.length > 0) {
        console.log('   ⚠️ Found unused indexes:');
        indexResult.rows.forEach(row => {
          console.log(`     ${row.tablename}.${row.indexname}`);
        });
      }
      
      // VACUUM and ANALYZE critical tables
      const tables = ['products', 'stores', 'users', 'orders'];
      for (const table of tables) {
        try {
          await client.query(`VACUUM ANALYZE ${table}`);
          console.log(`   ✅ Optimized ${table} table`);
        } catch (error) {
          console.log(`   ⚠️ Could not optimize ${table}: table may not exist`);
        }
      }
      
      client.release();
      
    } catch (error) {
      console.error('❌ Performance optimization failed:', error.message);
    }
    
    console.log('\n✅ Performance optimization complete. Press any key to continue...');
    process.stdin.once('data', () => this.showMainMenu());
  }

  async quickActions() {
    console.log('\n⚡ Quick Actions:');
    console.log('1. Kill all idle connections');
    console.log('2. Cancel long-running queries');
    console.log('3. Show active queries');
    console.log('4. Check connection count');
    console.log('5. Database size check');
    console.log('6. Back to main menu');
    
    process.stdin.once('data', async (key) => {
      const choice = key.toString().trim();
      
      try {
        const client = await this.pool.connect();
        
        switch (choice) {
          case '1':
            const result1 = await client.query(`
              SELECT pg_terminate_backend(pid)
              FROM pg_stat_activity
              WHERE state = 'idle' AND pid != pg_backend_pid()
            `);
            console.log(`✅ Killed ${result1.rowCount} idle connections`);
            break;
            
          case '2':
            const result2 = await client.query(`
              SELECT pg_cancel_backend(pid)
              FROM pg_stat_activity
              WHERE state = 'active' 
              AND now() - query_start > interval '1 minute'
              AND pid != pg_backend_pid()
            `);
            console.log(`✅ Cancelled ${result2.rowCount} long queries`);
            break;
            
          case '3':
            const result3 = await client.query(`
              SELECT pid, state, query_start, query
              FROM pg_stat_activity
              WHERE state = 'active' AND pid != pg_backend_pid()
              ORDER BY query_start
            `);
            console.log(`📊 Active queries: ${result3.rowCount}`);
            result3.rows.forEach(row => {
              console.log(`   PID ${row.pid}: ${row.query.substring(0, 50)}...`);
            });
            break;
            
          case '4':
            const result4 = await client.query(`
              SELECT count(*) as total, state
              FROM pg_stat_activity
              GROUP BY state
            `);
            console.log('📊 Connection counts:');
            result4.rows.forEach(row => {
              console.log(`   ${row.state}: ${row.total}`);
            });
            break;
            
          case '5':
            const result5 = await client.query(`
              SELECT pg_size_pretty(pg_database_size(current_database())) as size
            `);
            console.log(`💾 Database size: ${result5.rows[0].size}`);
            break;
            
          case '6':
            client.release();
            this.showMainMenu();
            return;
        }
        
        client.release();
        
      } catch (error) {
        console.error('❌ Quick action failed:', error.message);
      }
      
      console.log('\nPress any key to continue...');
      process.stdin.once('data', () => this.showMainMenu());
    });
  }

  async generateReport() {
    console.log('\n📋 Generating System Report...');
    
    const report = {
      timestamp: new Date().toISOString(),
      system: {},
      health: {},
      recommendations: []
    };
    
    try {
      const client = await this.pool.connect();
      
      // System info
      const sysResult = await client.query(`
        SELECT 
          version(),
          current_database() as db_name,
          pg_database_size(current_database()) as db_size,
          current_setting('shared_buffers') as shared_buffers,
          current_setting('work_mem') as work_mem
      `);
      
      report.system = sysResult.rows[0];
      
      // Health metrics
      const healthResult = await client.query(`
        SELECT 
          count(*) as total_connections,
          count(*) FILTER (WHERE state = 'active') as active_connections,
          count(*) FILTER (WHERE state = 'idle') as idle_connections,
          count(*) FILTER (WHERE now() - query_start > interval '30 seconds') as long_queries
        FROM pg_stat_activity
      `);
      
      report.health = healthResult.rows[0];
      
      // Generate recommendations
      if (report.health.total_connections > 15) {
        report.recommendations.push('Consider reducing connection pool size');
      }
      if (report.health.long_queries > 0) {
        report.recommendations.push('Investigate long-running queries');
      }
      if (parseInt(report.system.db_size) > 1000000000) { // 1GB
        report.recommendations.push('Database size is large - consider archiving old data');
      }
      
      client.release();
      
      // Display report
      console.log('\n📊 SYSTEM REPORT');
      console.log('='.repeat(40));
      console.log(`Generated: ${report.timestamp}`);
      console.log(`Database: ${report.system.db_name}`);
      console.log(`Size: ${this.formatBytes(report.system.db_size)}`);
      console.log(`Connections: ${report.health.total_connections} (${report.health.active_connections} active)`);
      console.log(`Long Queries: ${report.health.long_queries}`);
      
      if (report.recommendations.length > 0) {
        console.log('\n💡 RECOMMENDATIONS:');
        report.recommendations.forEach((rec, i) => {
          console.log(`   ${i + 1}. ${rec}`);
        });
      }
      
    } catch (error) {
      console.error('❌ Report generation failed:', error.message);
    }
    
    console.log('\n✅ Report complete. Press any key to continue...');
    process.stdin.once('data', () => this.showMainMenu());
  }

  startRealTimeMonitoring() {
    this.monitoring.isActive = true;
    this.monitoring.interval = setInterval(async () => {
      try {
        const client = await this.pool.connect();
        const result = await client.query(`
          SELECT count(*) as connections
          FROM pg_stat_activity
        `);
        
        const connectionCount = parseInt(result.rows[0].connections);
        if (connectionCount > this.thresholds.connectionCount) {
          this.monitoring.alerts.push({
            type: 'high_connections',
            value: connectionCount,
            threshold: this.thresholds.connectionCount,
            timestamp: new Date().toISOString()
          });
        }
        
        client.release();
      } catch (error) {
        // Silent monitoring failure
      }
    }, 30000); // Check every 30 seconds
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  async shutdown() {
    console.log('\n🛑 Shutting down Command Center...');
    
    if (this.monitoring.interval) {
      clearInterval(this.monitoring.interval);
    }
    
    await this.pool.end();
    
    console.log('✅ Command Center shutdown complete');
  }

  // Placeholder methods for menu options
  async runStressTest() {
    console.log('\n🧪 To run stress test, execute: node database-stress-tester.js');
    console.log('Press any key to continue...');
    process.stdin.once('data', () => this.showMainMenu());
  }

  async startAdvancedProtection() {
    console.log('\n🛡️ To start advanced protection, execute: node advanced-db-protection.js');
    console.log('Press any key to continue...');
    process.stdin.once('data', () => this.showMainMenu());
  }

  async backupRecovery() {
    console.log('\n💾 Backup & Recovery options:');
    console.log('1. pg_dump database_name > backup.sql');
    console.log('2. psql database_name < backup.sql');
    console.log('3. Use automated backup script');
    console.log('Press any key to continue...');
    process.stdin.once('data', () => this.showMainMenu());
  }
}

// Auto-start if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const commandCenter = new DatabaseCommandCenter();
  commandCenter.initialize().catch(console.error);
  
  // Graceful shutdown
  process.on('SIGINT', async () => {
    await commandCenter.shutdown();
    process.exit(0);
  });
}

export default DatabaseCommandCenter;