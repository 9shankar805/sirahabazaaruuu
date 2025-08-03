import { Pool } from 'pg';

const DATABASE_URL = process.env.DATABASE_URL || "postgresql://mydreamv50:123456@139.59.19.202:5432/postgres";

const pool = new Pool({ connectionString: DATABASE_URL });

async function createTables() {
  const client = await pool.connect();
  
  try {
    // Create essential tables for delivery partner system
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        full_name TEXT NOT NULL,
        phone TEXT,
        address TEXT,
        city TEXT,
        state TEXT,
        role TEXT NOT NULL DEFAULT 'customer',
        status TEXT NOT NULL DEFAULT 'active',
        approval_date TIMESTAMP,
        approved_by INTEGER,
        rejection_reason TEXT,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL,
        updated_at TIMESTAMP DEFAULT NOW() NOT NULL
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS admin_users (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT NOW() NOT NULL,
        is_active BOOLEAN DEFAULT true
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS delivery_partners (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) NOT NULL,
        vehicle_type TEXT NOT NULL,
        vehicle_number TEXT NOT NULL,
        driving_license TEXT NOT NULL,
        id_proof_type TEXT NOT NULL,
        id_proof_number TEXT NOT NULL,
        delivery_areas TEXT[] DEFAULT '{}',
        emergency_contact TEXT NOT NULL,
        bank_account_number TEXT NOT NULL,
        ifsc_code TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        approved_by INTEGER,
        approval_date TIMESTAMP,
        rejection_reason TEXT,
        is_available BOOLEAN DEFAULT true,
        current_location TEXT,
        total_deliveries INTEGER DEFAULT 0,
        rating DECIMAL(3,2) DEFAULT 0.00,
        total_earnings DECIMAL(10,2) DEFAULT 0.00,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS stores (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT NOT NULL UNIQUE,
        description TEXT,
        owner_id INTEGER REFERENCES users(id) NOT NULL,
        address TEXT NOT NULL,
        city TEXT,
        state TEXT,
        postal_code TEXT,
        country TEXT,
        latitude DECIMAL(10,8),
        longitude DECIMAL(11,8),
        phone TEXT,
        website TEXT,
        logo TEXT,
        cover_image TEXT,
        rating DECIMAL(3,2) DEFAULT 0.00,
        total_reviews INTEGER DEFAULT 0,
        featured BOOLEAN DEFAULT false,
        is_active BOOLEAN DEFAULT true,
        store_type TEXT NOT NULL DEFAULT 'retail',
        cuisine_type TEXT,
        delivery_time TEXT,
        minimum_order DECIMAL(10,2),
        delivery_fee DECIMAL(10,2),
        is_delivery_available BOOLEAN DEFAULT false,
        opening_hours TEXT,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL,
        updated_at TIMESTAMP DEFAULT NOW() NOT NULL
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES users(id) NOT NULL,
        store_id INTEGER REFERENCES stores(id) NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        total_amount DECIMAL(10,2) NOT NULL,
        delivery_fee DECIMAL(10,2) DEFAULT 0.00,
        tax_amount DECIMAL(10,2) DEFAULT 0.00,
        discount_amount DECIMAL(10,2) DEFAULT 0.00,
        shipping_address TEXT NOT NULL,
        billing_address TEXT,
        payment_method TEXT NOT NULL DEFAULT 'cash_on_delivery',
        payment_status TEXT NOT NULL DEFAULT 'pending',
        customer_name TEXT NOT NULL,
        phone TEXT,
        email TEXT,
        special_instructions TEXT,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL,
        updated_at TIMESTAMP DEFAULT NOW() NOT NULL
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS deliveries (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id) NOT NULL,
        delivery_partner_id INTEGER REFERENCES delivery_partners(id),
        status TEXT NOT NULL DEFAULT 'pending',
        assigned_at TIMESTAMP,
        picked_up_at TIMESTAMP,
        delivered_at TIMESTAMP,
        delivery_fee DECIMAL(10,2) NOT NULL,
        pickup_address TEXT NOT NULL,
        delivery_address TEXT NOT NULL,
        estimated_distance DECIMAL(8,2),
        estimated_time INTEGER,
        actual_time INTEGER,
        special_instructions TEXT,
        proof_of_delivery TEXT,
        customer_rating INTEGER,
        customer_feedback TEXT,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        slug TEXT NOT NULL UNIQUE,
        description TEXT,
        icon TEXT NOT NULL DEFAULT 'package',
        created_at TIMESTAMP DEFAULT NOW() NOT NULL,
        updated_at TIMESTAMP DEFAULT NOW() NOT NULL
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT NOT NULL UNIQUE,
        description TEXT,
        price DECIMAL(10,2) NOT NULL,
        original_price DECIMAL(10,2),
        category_id INTEGER REFERENCES categories(id),
        store_id INTEGER REFERENCES stores(id) NOT NULL,
        stock INTEGER DEFAULT 0,
        image_url TEXT NOT NULL DEFAULT '',
        images TEXT[] DEFAULT '{}',
        rating DECIMAL(3,2) DEFAULT 0.00,
        total_reviews INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT true,
        is_fast_sell BOOLEAN DEFAULT false,
        is_on_offer BOOLEAN DEFAULT false,
        offer_percentage INTEGER DEFAULT 0,
        offer_end_date TEXT,
        product_type TEXT NOT NULL DEFAULT 'retail',
        preparation_time TEXT,
        ingredients TEXT[] DEFAULT '{}',
        allergens TEXT[] DEFAULT '{}',
        spice_level TEXT,
        is_vegetarian BOOLEAN DEFAULT false,
        is_vegan BOOLEAN DEFAULT false,
        nutrition_info TEXT,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL,
        updated_at TIMESTAMP DEFAULT NOW() NOT NULL
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS order_items (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id) NOT NULL,
        product_id INTEGER REFERENCES products(id) NOT NULL,
        store_id INTEGER REFERENCES stores(id) NOT NULL,
        quantity INTEGER NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        total_price DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'info',
        is_read BOOLEAN DEFAULT false,
        order_id INTEGER REFERENCES orders(id),
        product_id INTEGER REFERENCES products(id),
        data TEXT,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      );
    `);

    console.log('✅ All tables created successfully');
    
    // Insert default admin if not exists
    const adminCheck = await client.query("SELECT id FROM admin_users WHERE email = 'admin@sirahbazaar.com'");
    if (adminCheck.rows.length === 0) {
      await client.query(`
        INSERT INTO admin_users (email, password, full_name) 
        VALUES ('admin@sirahbazaar.com', '$2b$10$rQ8K4Vn5mG7lP3jX9bS2.eR4hL6nM8oP1qT5wY3zC7vB9kE2fD4gH', 'System Admin')
      `);
      console.log('✅ Default admin created');
    }

  } catch (error) {
    console.error('Error creating tables:', error);
  } finally {
    client.release();
    await pool.end();
  }
}

createTables();