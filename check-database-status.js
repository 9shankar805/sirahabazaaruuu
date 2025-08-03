import { db } from "./server/db.js";
import * as schema from "./shared/schema.js";

async function checkDatabaseStatus() {
  console.log('🔍 Checking your DigitalOcean database status...\n');
  
  try {
    // Test basic connection
    const result = await db.execute(`SELECT current_database(), version()`);
    console.log('✅ Database Connection Success:');
    console.log(`   Database: ${result[0].current_database}`);
    console.log(`   Version: ${result[0].version.split(' ')[0]} ${result[0].version.split(' ')[1]}\n`);
    
    // Check tables
    const tables = await db.execute(`
      SELECT tablename 
      FROM pg_tables 
      WHERE schemaname = 'public' 
      ORDER BY tablename
    `);
    
    console.log('📋 Your Database Tables:');
    if (tables.length === 0) {
      console.log('   ⚠️  No tables found - fresh database ready for setup');
    } else {
      tables.forEach(row => {
        console.log(`   - ${row.tablename}`);
      });
    }
    console.log(`   Total: ${tables.length} tables\n`);
    
    // Check data counts
    const dataTables = [
      { name: 'users', table: schema.users },
      { name: 'stores', table: schema.stores },
      { name: 'products', table: schema.products },
      { name: 'orders', table: schema.orders },
      { name: 'categories', table: schema.categories }
    ];
    
    console.log('📊 Data Summary:');
    for (const tableInfo of dataTables) {
      try {
        const count = await db.select().from(tableInfo.table);
        console.log(`   ${tableInfo.name}: ${count.length} records`);
      } catch (error) {
        if (error.message.includes('does not exist')) {
          console.log(`   ${tableInfo.name}: Table needs to be created`);
        } else {
          console.log(`   ${tableInfo.name}: Error - ${error.message}`);
        }
      }
    }
    
    console.log('\n✅ Database status check completed!');
    
  } catch (error) {
    console.error('❌ Database check failed:', error.message);
  }
}

checkDatabaseStatus().catch(console.error);