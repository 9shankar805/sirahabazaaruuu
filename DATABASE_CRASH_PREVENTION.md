# PostgreSQL Crash Prevention Guide

## Common Causes of PostgreSQL Crashes

### 1. Memory Issues
- **Out of Memory (OOM)**: Most common cause
- **Shared buffers too large**: Exceeds available RAM
- **Work memory misconfiguration**: Too high values

### 2. Connection Problems
- **Too many connections**: Exceeds max_connections limit
- **Connection leaks**: Unclosed database connections
- **Connection timeout**: Long-running queries

### 3. Disk Space Issues
- **Full disk**: No space for WAL files or data
- **Corrupted data files**: Hardware or filesystem issues
- **Log files growing too large**: Unrotated logs

### 4. Configuration Problems
- **Invalid configuration**: Wrong postgresql.conf settings
- **Incompatible extensions**: Conflicting PostgreSQL extensions
- **Version mismatches**: Client/server version conflicts

## Prevention Strategies

### 1. Memory Management
```sql
-- Check current memory settings
SHOW shared_buffers;
SHOW work_mem;
SHOW maintenance_work_mem;

-- Recommended settings for small servers (2GB RAM):
-- shared_buffers = 256MB
-- work_mem = 4MB
-- maintenance_work_mem = 64MB
```

### 2. Connection Management
```javascript
// Always use connection pooling
const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 10,                    // Maximum connections
  idleTimeoutMillis: 30000,   // Close idle connections
  connectionTimeoutMillis: 2000,
});

// Always close connections
pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
  process.exit(-1);
});
```

### 3. Query Optimization
```sql
-- Monitor slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Kill long-running queries
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE state = 'active' 
AND now() - query_start > interval '5 minutes';
```

### 4. Disk Space Monitoring
```bash
# Check disk space
df -h

# Check PostgreSQL data directory size
du -sh /var/lib/postgresql/data

# Monitor WAL files
ls -la /var/lib/postgresql/data/pg_wal/
```

## Emergency Recovery Steps

### 1. Database Won't Start
```bash
# Check PostgreSQL logs
tail -f /var/log/postgresql/postgresql-*.log

# Start in single-user mode
postgres --single -D /var/lib/postgresql/data

# Check for corrupted indexes
REINDEX DATABASE your_database;
```

### 2. Out of Memory Crashes
```bash
# Check system memory
free -h
cat /proc/meminfo

# Reduce PostgreSQL memory usage
# Edit postgresql.conf:
shared_buffers = 128MB
work_mem = 2MB
```

### 3. Connection Issues
```sql
-- Check active connections
SELECT count(*) FROM pg_stat_activity;

-- Kill idle connections
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'idle'
AND now() - state_change > interval '1 hour';
```

## Monitoring Commands

### Real-time Monitoring
```sql
-- Active connections
SELECT pid, usename, application_name, client_addr, state, query_start
FROM pg_stat_activity
WHERE state != 'idle';

-- Database size
SELECT pg_database_size('your_database');

-- Table sizes
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(tablename::text))
FROM pg_tables
ORDER BY pg_total_relation_size(tablename::text) DESC;
```

### Performance Metrics
```sql
-- Cache hit ratio (should be > 95%)
SELECT 
  round(
    (blks_hit::float / (blks_hit + blks_read) * 100)::numeric, 2
  ) as cache_hit_ratio
FROM pg_stat_database
WHERE datname = current_database();

-- Index usage
SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_tup_read DESC;
```

## Application-Level Prevention

### 1. Connection Pool Configuration
```javascript
// Optimal pool settings for your app
const poolConfig = {
  max: 20,                    // Max connections
  min: 2,                     // Min connections
  acquire: 30000,             // Max time to acquire connection
  idle: 10000,                // Max time connection can be idle
  evict: 1000,                // Check for idle connections every second
};
```

### 2. Query Timeout Protection
```javascript
// Set query timeout
const client = await pool.connect();
try {
  client.query('SET statement_timeout = 30000'); // 30 seconds
  const result = await client.query(yourQuery);
  return result;
} finally {
  client.release();
}
```

### 3. Error Handling
```javascript
// Robust error handling
pool.on('error', (err, client) => {
  console.error('Unexpected error on idle client', err);
  // Don't exit process, just log and continue
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Closing database connections...');
  await pool.end();
  process.exit(0);
});
```

## Regular Maintenance Tasks

### Daily
```sql
-- Update statistics
ANALYZE;

-- Check for bloated tables
SELECT schemaname, tablename, n_dead_tup, n_live_tup
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000;
```

### Weekly
```sql
-- Vacuum databases
VACUUM ANALYZE;

-- Reindex if needed
REINDEX DATABASE your_database;
```

### Monthly
```bash
# Backup database
pg_dump your_database > backup_$(date +%Y%m%d).sql

# Check log files and rotate if large
logrotate /etc/logrotate.d/postgresql
```

## Quick Fixes for Common Issues

### Database Locked/Hanging
```sql
-- Find blocking queries
SELECT blocked_locks.pid AS blocked_pid,
       blocking_locks.pid AS blocking_pid,
       blocked_activity.query AS blocked_statement
FROM pg_catalog.pg_locks blocked_locks
JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
JOIN pg_catalog.pg_locks blocking_locks ON blocking_locks.locktype = blocked_locks.locktype
JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid
WHERE NOT blocked_locks.granted;

-- Kill blocking process
SELECT pg_terminate_backend(blocking_pid);
```

### High CPU Usage
```sql
-- Find expensive queries
SELECT query, total_time, mean_time, calls
FROM pg_stat_statements
ORDER BY total_time DESC
LIMIT 10;
```

### Memory Leaks
```javascript
// Check for connection leaks in Node.js
setInterval(() => {
  console.log('Pool size:', pool.totalCount);
  console.log('Idle connections:', pool.idleCount);
  console.log('Active connections:', pool.totalCount - pool.idleCount);
}, 30000);
```

## Emergency Contacts & Resources
- PostgreSQL Documentation: https://www.postgresql.org/docs/
- Performance Tuning: https://wiki.postgresql.org/wiki/Performance_Optimization
- Monitoring Tools: pg_stat_statements, pgBadger, pg_top