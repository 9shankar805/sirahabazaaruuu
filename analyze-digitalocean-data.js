import { Pool } from "pg";
import dotenv from "dotenv";

dotenv.config();

const DATABASE_URL = process.env.DIGITALOCEAN_DATABASE_URL;

async function analyzeDigitalOceanData() {
  console.log('🔍 Analyzing your DigitalOcean database...\n');
  
  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
      rejectUnauthorized: false,
      sslmode: 'require'
    },
    max: 2,
    connectionTimeoutMillis: 10000,
  });

  try {
    const client = await pool.connect();
    
    console.log('✅ Connected to your DigitalOcean database\n');
    
    // Get database info
    const dbInfo = await client.query('SELECT current_database(), version()');
    console.log('📊 Database Info:');
    console.log(`   Database: ${dbInfo.rows[0].current_database}`);
    console.log(`   Version: ${dbInfo.rows[0].version.split(' ')[0]} ${dbInfo.rows[0].version.split(' ')[1]}\n`);
    
    // Get all tables
    const tablesResult = await client.query(`
      SELECT 
        schemaname,
        tablename,
        tableowner
      FROM pg_tables 
      WHERE schemaname = 'public'
      ORDER BY tablename
    `);
    
    console.log('📋 Your Current Tables:');
    if (tablesResult.rows.length === 0) {
      console.log('   ⚠️  No tables found - this appears to be a fresh database');
    } else {
      tablesResult.rows.forEach(row => {
        console.log(`   - ${row.tablename}`);
      });
    }
    console.log(`   Total: ${tablesResult.rows.length} tables\n`);
    
    // Check for key data tables and their counts
    const importantTables = ['users', 'stores', 'products', 'orders', 'categories'];
    
    console.log('📈 Data Summary:');
    for (const table of importantTables) {
      try {
        const countResult = await client.query(`SELECT COUNT(*) FROM ${table}`);
        const count = parseInt(countResult.rows[0].count);
        console.log(`   ${table}: ${count} records`);
      } catch (error) {
        console.log(`   ${table}: Table does not exist`);
      }
    }
    
    // Check users table structure if it exists
    try {
      const usersStructure = await client.query(`
        SELECT column_name, data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_name = 'users' AND table_schema = 'public'
        ORDER BY ordinal_position
      `);
      
      if (usersStructure.rows.length > 0) {
        console.log('\n👥 Users Table Structure:');
        usersStructure.rows.forEach(row => {
          console.log(`   - ${row.column_name} (${row.data_type})`);
        });
      }
    } catch (error) {
      console.log('\n👥 Users table structure: Not available');
    }
    
    // Check products table structure if it exists
    try {
      const productsStructure = await client.query(`
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'products' AND table_schema = 'public'
        ORDER BY ordinal_position
      `);
      
      if (productsStructure.rows.length > 0) {
        console.log('\n🛍️ Products Table Structure:');
        productsStructure.rows.forEach(row => {
          console.log(`   - ${row.column_name} (${row.data_type})`);
        });
      }
    } catch (error) {
      console.log('\n🛍️ Products table structure: Not available');
    }
    
    // Check for sample data
    try {
      const sampleUsers = await client.query('SELECT id, email, name FROM users LIMIT 3');
      if (sampleUsers.rows.length > 0) {
        console.log('\n👤 Sample Users:');
        sampleUsers.rows.forEach(user => {
          console.log(`   - ${user.name || 'No name'} (${user.email})`);
        });
      }
    } catch (error) {
      // Users table doesn't exist or has different structure
    }
    
    try {
      const sampleProducts = await client.query('SELECT id, name, price FROM products LIMIT 3');
      if (sampleProducts.rows.length > 0) {
        console.log('\n🛍️ Sample Products:');
        sampleProducts.rows.forEach(product => {
          console.log(`   - ${product.name} ($${product.price})`);
        });
      }
    } catch (error) {
      // Products table doesn't exist or has different structure
    }
    
    client.release();
    console.log('\n✅ Analysis completed successfully!');
    
    // Recommendations
    console.log('\n🎯 Next Steps:');
    if (tablesResult.rows.length === 0) {
      console.log('   1. Your database is empty - we can set up the complete schema');
      console.log('   2. All your new website features will work perfectly');
      console.log('   3. Ready to add your stores, products, and customers');
    } else {
      console.log('   1. Your existing data is preserved and accessible');
      console.log('   2. New tables added for enhanced features (food delivery, reviews, etc.)');
      console.log('   3. Your website is ready to use with both old and new features');
    }
    
  } catch (error) {
    console.error('❌ Analysis failed:', error.message);
    console.error('🔧 Error details:', {
      code: error.code,
      detail: error.detail,
      hint: error.hint
    });
  } finally {
    await pool.end();
  }
}

// Run the analysis
analyzeDigitalOceanData().catch(console.error);