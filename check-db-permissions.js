import { Pool } from 'pg';

const pool = new Pool({ 
  connectionString: 'postgresql://mydreamv50:123456@139.59.19.202:5432/mydreamv50',
  ssl: false
});

async function checkDatabase() {
  try {
    const client = await pool.connect();
    
    // Check if tables exist
    const tablesResult = await client.query(`
      SELECT table_name, table_schema 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      ORDER BY table_name
    `);
    
    console.log('Tables in database:');
    tablesResult.rows.forEach(row => {
      console.log('-', row.table_name);
    });
    
    // Check permissions
    console.log('\nChecking permissions...');
    try {
      const permResult = await client.query(`
        SELECT grantee, table_name, privilege_type 
        FROM information_schema.table_privileges 
        WHERE table_schema = 'public' AND grantee = 'mydreamv50'
        ORDER BY table_name
      `);
      
      if (permResult.rows.length > 0) {
        console.log('User permissions:');
        permResult.rows.forEach(row => {
          console.log('-', row.table_name, ':', row.privilege_type);
        });
      } else {
        console.log('No specific permissions found for mydreamv50 user');
      }
    } catch (err) {
      console.log('Permission check error:', err.message);
    }
    
    client.release();
  } catch (err) {
    console.log('Database check failed:', err.message);
  } finally {
    await pool.end();
  }
}

checkDatabase();