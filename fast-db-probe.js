import { Client } from "pg";
import dotenv from "dotenv";

dotenv.config();

async function fastProbe() {
  const client = new Client({
    connectionString: process.env.DIGITALOCEAN_DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 5000,
    statement_timeout: 5000,
    query_timeout: 5000
  });

  try {
    console.log('⚡ Fast connection attempt...');
    await client.connect();
    console.log('✅ Connected!');
    
    // Single fast query
    const result = await client.query(`
      SELECT 
        (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public') as total_tables,
        current_database() as db_name
    `);
    
    console.log('Database:', result.rows[0].db_name);
    console.log('Tables:', result.rows[0].total_tables);
    
    // Try to count records in potential tables
    const tables = ['users', 'products', 'stores', 'orders'];
    for (const table of tables) {
      try {
        const count = await client.query(`SELECT COUNT(*) FROM ${table}`);
        console.log(`${table}: ${count.rows[0].count} records`);
      } catch (e) {
        console.log(`${table}: ${e.message.includes('does not exist') ? 'table missing' : 'error'}`);
      }
    }
    
  } catch (error) {
    console.log('❌ Failed:', error.message);
  } finally {
    try {
      await client.end();
    } catch (e) {}
  }
}

fastProbe().catch(console.error);