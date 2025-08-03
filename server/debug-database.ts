import { pool } from "./db";

export async function inspectDatabase() {
  try {
    console.log('🔍 Inspecting DigitalOcean database...');
    
    // Get all tables
    const tablesQuery = await pool.query(`
      SELECT table_name, table_type
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);
    
    console.log(`Found ${tablesQuery.rows.length} tables:`);
    tablesQuery.rows.forEach(row => {
      console.log(`  - ${row.table_name} (${row.table_type})`);
    });
    
    // Check data in key tables
    const keyTables = ['users', 'stores', 'products', 'orders', 'categories'];
    
    for (const tableName of keyTables) {
      try {
        const countResult = await pool.query(`SELECT COUNT(*) FROM ${tableName}`);
        const count = parseInt(countResult.rows[0].count);
        console.log(`${tableName}: ${count} records`);
        
        if (count > 0) {
          const sampleResult = await pool.query(`SELECT * FROM ${tableName} LIMIT 1`);
          console.log(`  Sample: ${JSON.stringify(sampleResult.rows[0])}`);
        }
      } catch (error) {
        console.log(`${tableName}: Table doesn't exist or error - ${error.message}`);
      }
    }
    
    return {
      tables: tablesQuery.rows,
      success: true
    };
    
  } catch (error) {
    console.error('Database inspection failed:', error.message);
    return {
      error: error.message,
      success: false
    };
  }
}