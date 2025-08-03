import { Pool } from 'pg';

const pool = new Pool({ 
  connectionString: 'postgresql://mydreamv50:123456@139.59.19.202:5432/mydreamv50',
  ssl: false
});

async function setupDatabase() {
  try {
    const client = await pool.connect();
    console.log('🔌 Connected to PostgreSQL database');

    // Check current user privileges
    const privilegesResult = await client.query(`
      SELECT 
        current_user as username,
        current_database() as database,
        current_schema() as schema
    `);
    
    console.log('Current user info:', privilegesResult.rows[0]);

    // Check if user is superuser or has CREATE privileges
    const userInfoResult = await client.query(`
      SELECT 
        rolname,
        rolsuper,
        rolcreaterole,
        rolcreatedb,
        rolcanlogin
      FROM pg_roles 
      WHERE rolname = current_user
    `);
    
    console.log('User privileges:', userInfoResult.rows[0]);

    // Try to create a simple test table to check permissions
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS test_permissions (
          id SERIAL PRIMARY KEY,
          test_data TEXT
        )
      `);
      console.log('✅ Can create tables');
      
      // Clean up test table
      await client.query('DROP TABLE IF EXISTS test_permissions');
    } catch (err) {
      console.log('❌ Cannot create tables:', err.message);
    }

    // Try to list all tables
    const tablesResult = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);
    
    console.log('Existing tables:');
    if (tablesResult.rows.length === 0) {
      console.log('- No tables found');
    } else {
      tablesResult.rows.forEach(row => {
        console.log('- ' + row.table_name);
      });
    }

    client.release();
  } catch (err) {
    console.log('❌ Database setup failed:', err.message);
  } finally {
    await pool.end();
  }
}

setupDatabase();