import { Pool } from "pg";

// New Neon Database Configuration
const newDatabaseUrl = "postgresql://neondb_owner:npg_B14cMjkFUhuw@ep-wispy-paper-a1eejnp5-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require";

const pool = new Pool({
  connectionString: newDatabaseUrl,
  max: 2,
  ssl: { rejectUnauthorized: false }
});

async function testConnection() {
  try {
    console.log("🔌 Testing connection to new Neon database...");
    
    const client = await pool.connect();
    console.log("✅ Connected to Neon database successfully!");
    
    // Test basic query
    const result = await client.query('SELECT NOW() as current_time, version() as db_version');
    console.log("📅 Current time:", result.rows[0].current_time);
    console.log("🗄️  Database version:", result.rows[0].db_version.split(' ')[0]);
    
    // Check if any tables exist
    const tables = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);
    
    console.log(`📋 Found ${tables.rows.length} existing tables:`);
    tables.rows.forEach(row => {
      console.log(`   - ${row.table_name}`);
    });
    
    client.release();
    console.log("✅ Connection test successful!");
    
  } catch (error: any) {
    console.error("❌ Connection test failed:", error.message);
    throw error;
  } finally {
    await pool.end();
  }
}

// Run the test
testConnection()
  .then(() => process.exit(0))
  .catch(() => process.exit(1));