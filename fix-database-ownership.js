import { Pool } from 'pg';

const pool = new Pool({ 
  connectionString: 'postgresql://mydreamv50:123456@139.59.19.202:5432/mydreamv50',
  ssl: false
});

async function fixDatabaseOwnership() {
  try {
    const client = await pool.connect();
    console.log('🔧 Fixing database table ownership...');

    // Get list of all tables
    const tablesResult = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);

    if (tablesResult.rows.length > 0) {
      console.log('Found existing tables:');
      tablesResult.rows.forEach(row => {
        console.log('- ' + row.table_name);
      });

      // Drop all existing tables (this will remove permission issues)
      console.log('\n🗑️ Dropping existing tables to fix permissions...');
      for (const row of tablesResult.rows) {
        try {
          await client.query(`DROP TABLE IF EXISTS "${row.table_name}" CASCADE`);
          console.log(`✅ Dropped table: ${row.table_name}`);
        } catch (err) {
          console.log(`❌ Could not drop table ${row.table_name}:`, err.message);
        }
      }
    }

    // Now create all tables fresh with proper ownership
    console.log('\n🔧 Creating tables with proper ownership...');
    
    // Users table
    await client.query(`
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        phone VARCHAR(20),
        role VARCHAR(50) DEFAULT 'customer',
        is_verified BOOLEAN DEFAULT false,
        verification_token VARCHAR(255),
        reset_token VARCHAR(255),
        reset_token_expires TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        latitude VARCHAR(50),
        longitude VARCHAR(50),
        address TEXT
      )
    `);
    console.log('✅ Created users table');

    // Categories table
    await client.query(`
      CREATE TABLE categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        slug VARCHAR(255) UNIQUE NOT NULL,
        description TEXT,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Created categories table');

    // Stores table
    await client.query(`
      CREATE TABLE stores (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        slug VARCHAR(255) UNIQUE NOT NULL,
        description TEXT,
        address TEXT NOT NULL,
        phone VARCHAR(20),
        city VARCHAR(100),
        state VARCHAR(100),
        latitude VARCHAR(50),
        longitude VARCHAR(50),
        owner_id INTEGER REFERENCES users(id),
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        store_type VARCHAR(50) DEFAULT 'retail',
        delivery_fee VARCHAR(10),
        minimum_order VARCHAR(10),
        delivery_time VARCHAR(50),
        cuisine_type VARCHAR(100),
        opening_hours TEXT,
        rating VARCHAR(5),
        total_reviews INTEGER DEFAULT 0
      )
    `);
    console.log('✅ Created stores table');

    // Products table
    await client.query(`
      CREATE TABLE products (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        slug VARCHAR(255) UNIQUE NOT NULL,
        description TEXT,
        price VARCHAR(20) NOT NULL,
        images TEXT,
        category_id INTEGER REFERENCES categories(id),
        store_id INTEGER REFERENCES stores(id),
        stock_quantity INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        rating VARCHAR(5),
        total_reviews INTEGER DEFAULT 0,
        weight VARCHAR(20),
        dimensions VARCHAR(100),
        brand VARCHAR(100),
        sku VARCHAR(100),
        tags TEXT,
        discount_percentage VARCHAR(5),
        featured BOOLEAN DEFAULT false,
        prep_time VARCHAR(50),
        spice_level VARCHAR(20),
        is_vegetarian BOOLEAN DEFAULT false,
        is_vegan BOOLEAN DEFAULT false,
        ingredients TEXT,
        allergens TEXT,
        nutrition_info TEXT
      )
    `);
    console.log('✅ Created products table');

    // Insert basic categories
    await client.query(`
      INSERT INTO categories (name, slug, description) VALUES
      ('Electronics', 'electronics', 'Electronic devices and gadgets'),
      ('Clothing', 'clothing', 'Fashion and apparel'),
      ('Food', 'food', 'Food items and groceries'),
      ('Books', 'books', 'Books and educational materials'),
      ('Home & Garden', 'home-garden', 'Home improvement and gardening')
      ON CONFLICT (slug) DO NOTHING
    `);
    console.log('✅ Inserted default categories');

    client.release();
    console.log('\n🎉 Database setup completed successfully!');
    
  } catch (err) {
    console.log('❌ Database setup failed:', err.message);
  } finally {
    await pool.end();
  }
}

fixDatabaseOwnership();