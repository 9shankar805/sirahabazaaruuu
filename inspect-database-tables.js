import { pool } from "./server/db.js";

async function inspectDatabaseTables() {
  console.log('🔍 Deep inspection of your DigitalOcean database...\n');
  
  try {
    // Get all tables with detailed info
    const result = await pool.query(`
      SELECT 
        t.table_name,
        t.table_type,
        (
          SELECT COUNT(*) 
          FROM information_schema.columns c 
          WHERE c.table_name = t.table_name 
          AND c.table_schema = 'public'
        ) as column_count
      FROM information_schema.tables t
      WHERE t.table_schema = 'public'
      ORDER BY t.table_name
    `);
    
    console.log('📋 All Tables in Your Database:');
    if (result.rows.length === 0) {
      console.log('   ⚠️  NO TABLES FOUND - Database appears to be completely empty');
      return;
    }
    
    for (const table of result.rows) {
      console.log(`   - ${table.table_name} (${table.column_count} columns)`);
    }
    console.log(`\n   Total: ${result.rows.length} tables found\n`);
    
    // Check for data in each table
    console.log('📊 Data Count in Each Table:');
    for (const table of result.rows) {
      try {
        const countResult = await pool.query(`SELECT COUNT(*) FROM "${table.table_name}"`);
        const count = parseInt(countResult.rows[0].count);
        console.log(`   ${table.table_name}: ${count} records`);
        
        // If table has data, show sample
        if (count > 0) {
          const sampleResult = await pool.query(`SELECT * FROM "${table.table_name}" LIMIT 2`);
          console.log(`      Sample data:`);
          sampleResult.rows.forEach((row, index) => {
            const keys = Object.keys(row).slice(0, 3); // Show first 3 columns
            const sample = keys.map(key => `${key}: ${row[key]}`).join(', ');
            console.log(`        Row ${index + 1}: ${sample}...`);
          });
        }
      } catch (error) {
        console.log(`   ${table.table_name}: Error reading data - ${error.message}`);
      }
    }
    
    // Check database size and connections
    const dbInfo = await pool.query(`
      SELECT 
        current_database() as db_name,
        pg_size_pretty(pg_database_size(current_database())) as db_size,
        (SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()) as active_connections
    `);
    
    console.log('\n📈 Database Information:');
    console.log(`   Database Name: ${dbInfo.rows[0].db_name}`);
    console.log(`   Database Size: ${dbInfo.rows[0].db_size}`);
    console.log(`   Active Connections: ${dbInfo.rows[0].active_connections}`);
    
    // Check for any sequences (auto-increment IDs)
    const sequences = await pool.query(`
      SELECT sequence_name 
      FROM information_schema.sequences 
      WHERE sequence_schema = 'public'
    `);
    
    if (sequences.rows.length > 0) {
      console.log('\n🔢 Database Sequences:');
      sequences.rows.forEach(seq => {
        console.log(`   - ${seq.sequence_name}`);
      });
    }
    
    console.log('\n✅ Database inspection completed!');
    
  } catch (error) {
    console.error('❌ Database inspection failed:', error.message);
    console.error('   Error code:', error.code);
    console.error('   Error detail:', error.detail);
  }
}

inspectDatabaseTables().catch(console.error);