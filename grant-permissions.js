import { Pool } from 'pg';

const pool = new Pool({ 
  connectionString: 'postgresql://mydreamv50:123456@139.59.19.202:5432/mydreamv50',
  ssl: false
});

async function grantPermissions() {
  try {
    const client = await pool.connect();
    console.log('🔑 Attempting to grant permissions...');

    // Get all tables
    const result = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);
    
    console.log('Found tables:', result.rows.map(r => r.table_name));
    
    // Try to grant permissions to each table
    for (const row of result.rows) {
      const tableName = row.table_name;
      
      try {
        // Try granting full permissions
        await client.query(`GRANT ALL PRIVILEGES ON TABLE "${tableName}" TO mydreamv50`);
        console.log(`✅ Granted ALL permissions on ${tableName}`);
      } catch (err) {
        console.log(`❌ Could not grant ALL permissions on ${tableName}: ${err.message}`);
        
        // Try basic SELECT, INSERT, UPDATE, DELETE permissions
        try {
          await client.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "${tableName}" TO mydreamv50`);
          console.log(`✅ Granted basic permissions on ${tableName}`);
        } catch (err2) {
          console.log(`❌ Could not grant basic permissions on ${tableName}: ${err2.message}`);
        }
      }
    }

    // Try to grant permissions on sequences (for SERIAL columns)
    const sequences = await client.query(`
      SELECT sequence_name 
      FROM information_schema.sequences 
      WHERE sequence_schema = 'public'
    `);
    
    for (const row of sequences.rows) {
      try {
        await client.query(`GRANT ALL ON SEQUENCE "${row.sequence_name}" TO mydreamv50`);
        console.log(`✅ Granted sequence permissions on ${row.sequence_name}`);
      } catch (err) {
        console.log(`❌ Could not grant sequence permissions on ${row.sequence_name}: ${err.message}`);
      }
    }
    
    client.release();
    console.log('\n🔍 Testing permissions...');
    
    // Test read access to important tables
    const testClient = await pool.connect();
    const tablesToTest = ['users', 'products', 'stores', 'categories'];
    
    for (const table of tablesToTest) {
      try {
        const testResult = await testClient.query(`SELECT COUNT(*) FROM ${table}`);
        console.log(`✅ Can read from ${table}: ${testResult.rows[0].count} rows`);
      } catch (err) {
        console.log(`❌ Cannot read from ${table}: ${err.message}`);
      }
    }
    
    testClient.release();
    
  } catch (err) {
    console.log('❌ Permission setup failed:', err.message);
  } finally {
    await pool.end();
  }
}

grantPermissions();