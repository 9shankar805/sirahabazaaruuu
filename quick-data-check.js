import { Pool } from "pg";
import dotenv from "dotenv";

dotenv.config();

async function quickDataCheck() {
  const pool = new Pool({
    connectionString: process.env.DIGITALOCEAN_DATABASE_URL,
    max: 1,
    connectionTimeoutMillis: 10000,
    statement_timeout: 10000,
    ssl: { rejectUnauthorized: false }
  });

  try {
    console.log('🔍 Quick data check...');
    
    // Very fast queries with timeout
    const queries = [
      "SELECT COUNT(*) as count FROM information_schema.tables WHERE table_schema = 'public'",
      "SELECT 'users' as table_name, COUNT(*) as count FROM users UNION ALL SELECT 'stores', COUNT(*) FROM stores UNION ALL SELECT 'products', COUNT(*) FROM products LIMIT 10"
    ];
    
    for (const query of queries) {
      try {
        const result = await Promise.race([
          pool.query(query),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Query timeout')), 8000))
        ]);
        
        console.log('Query result:', result.rows);
      } catch (error) {
        console.log(`Query failed: ${error.message}`);
        break;
      }
    }
    
  } catch (error) {
    console.log('Connection failed:', error.message);
  } finally {
    await pool.end();
  }
}

quickDataCheck();