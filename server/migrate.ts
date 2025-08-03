import { db } from "./db";
import { sql } from "drizzle-orm";

export async function runMigrations() {
  try {
    console.log("Running database migrations...");

    // Create admin_users table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS admin_users (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT NOW() NOT NULL,
        is_active BOOLEAN DEFAULT true
      )
    `);

    // Add missing columns to users table
    await db.execute(sql`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT UNIQUE
    `);
    await db.execute(sql`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS city TEXT
    `);
    await db.execute(sql`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS state TEXT
    `);
    await db.execute(sql`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()
    `);

    // Add missing columns to stores table
    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS slug TEXT UNIQUE
    `);
    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS city TEXT
    `);
    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS state TEXT
    `);
    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS country TEXT
    `);
    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS postal_code TEXT
    `);
    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()
    `);

    // Fix city column constraint if it exists as NOT NULL
    await db.execute(sql`
      ALTER TABLE stores ALTER COLUMN city DROP NOT NULL
    `).catch(() => {
      // Ignore error if constraint doesn't exist
    });

    // Fix postal_code column constraint if it exists as NOT NULL
    await db.execute(sql`
      ALTER TABLE stores ALTER COLUMN postal_code DROP NOT NULL
    `).catch(() => {
      // Ignore error if constraint doesn't exist
    });

    // Add missing columns to products table
    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS slug TEXT UNIQUE
    `);
    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS image_url TEXT NOT NULL DEFAULT ''
    `);

    // Update stores table to ensure owner_id column exists
    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS owner_id INTEGER REFERENCES users(id) NOT NULL DEFAULT 1
    `);

    // Ensure stores have location fields
    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS address TEXT
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS location TEXT
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS phone TEXT
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS latitude DECIMAL(10,8)
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS longitude DECIMAL(11,8)
    `);

    // Create delivery_partners table with correct schema
    await db.execute(sql`
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
        approved_by INTEGER REFERENCES users(id),
        approval_date TIMESTAMP,
        rejection_reason TEXT,
        is_available BOOLEAN DEFAULT true,
        current_location TEXT,
        total_deliveries INTEGER DEFAULT 0,
        rating DECIMAL(3,2) DEFAULT 0.00,
        total_earnings DECIMAL(10,2) DEFAULT 0.00,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    // Create deliveries table with correct schema
    await db.execute(sql`
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
      )
    `);

    // Create notifications table if not exists
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'info',
        is_read BOOLEAN DEFAULT false,
        order_id INTEGER REFERENCES orders(id),
        product_id INTEGER,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    // Add icon column to categories table if missing
    await db.execute(sql`
      ALTER TABLE categories ADD COLUMN IF NOT EXISTS icon TEXT DEFAULT 'package'
    `);

    // Create website_visits table for analytics
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS website_visits (
        id SERIAL PRIMARY KEY,
        ip_address TEXT,
        user_agent TEXT,
        page TEXT NOT NULL,
        referrer TEXT,
        session_id TEXT,
        user_id INTEGER REFERENCES users(id),
        visited_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    // Create delivery tracking tables for HERE Maps integration
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS delivery_location_tracking (
        id SERIAL PRIMARY KEY,
        delivery_id INTEGER NOT NULL,
        delivery_partner_id INTEGER NOT NULL,
        current_latitude DECIMAL(10, 8) NOT NULL,
        current_longitude DECIMAL(11, 8) NOT NULL,
        heading DECIMAL(5, 2),
        speed DECIMAL(8, 2),
        accuracy DECIMAL(8, 2),
        timestamp TIMESTAMP DEFAULT NOW() NOT NULL,
        is_active BOOLEAN DEFAULT true
      )
    `);

    // Add missing columns to deliveries table for better tracking
    await db.execute(sql`
      ALTER TABLE deliveries ADD COLUMN pickup_latitude TEXT
    `).catch(() => {}); // Ignore if column already exists

    await db.execute(sql`
      ALTER TABLE deliveries ADD COLUMN pickup_longitude TEXT
    `).catch(() => {});

    await db.execute(sql`
      ALTER TABLE deliveries ADD COLUMN delivery_latitude TEXT
    `).catch(() => {});

    await db.execute(sql`
      ALTER TABLE deliveries ADD COLUMN delivery_longitude TEXT
    `).catch(() => {});

    await db.execute(sql`
      ALTER TABLE deliveries ADD COLUMN distance INTEGER
    `).catch(() => {});

    await db.execute(sql`
      ALTER TABLE deliveries ADD COLUMN estimated_duration INTEGER
    `).catch(() => {});

    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS delivery_routes (
        id SERIAL PRIMARY KEY,
        delivery_id INTEGER NOT NULL,
        pickup_latitude DECIMAL(10, 8) NOT NULL,
        pickup_longitude DECIMAL(11, 8) NOT NULL,
        delivery_latitude DECIMAL(10, 8) NOT NULL,
        delivery_longitude DECIMAL(11, 8) NOT NULL,
        route_geometry TEXT,
        distance_meters INTEGER NOT NULL,
        estimated_duration_seconds INTEGER NOT NULL,
        actual_duration_seconds INTEGER,
        traffic_info TEXT,
        here_route_id TEXT,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL,
        updated_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS delivery_status_history (
        id SERIAL PRIMARY KEY,
        delivery_id INTEGER NOT NULL,
        status TEXT NOT NULL,
        description TEXT,
        latitude DECIMAL(10, 8),
        longitude DECIMAL(11, 8),
        timestamp TIMESTAMP DEFAULT NOW() NOT NULL,
        updated_by INTEGER,
        metadata TEXT
      )
    `);

    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS websocket_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        session_id TEXT NOT NULL UNIQUE,
        user_type TEXT NOT NULL,
        connected_at TIMESTAMP DEFAULT NOW() NOT NULL,
        last_activity TIMESTAMP DEFAULT NOW(),
        is_active BOOLEAN DEFAULT true
      )
    `);

    // Create indexes for performance
    await db.execute(sql`
      CREATE INDEX IF NOT EXISTS idx_delivery_location_tracking_delivery_id 
      ON delivery_location_tracking(delivery_id)
    `);

    await db.execute(sql`
      CREATE INDEX IF NOT EXISTS idx_delivery_location_tracking_timestamp 
      ON delivery_location_tracking(timestamp DESC)
    `);

    await db.execute(sql`
      CREATE INDEX IF NOT EXISTS idx_delivery_routes_delivery_id 
      ON delivery_routes(delivery_id)
    `);

    await db.execute(sql`
      CREATE INDEX IF NOT EXISTS idx_delivery_status_history_delivery_id 
      ON delivery_status_history(delivery_id)
    `);

    await db.execute(sql`
      CREATE INDEX IF NOT EXISTS idx_websocket_sessions_user_id 
      ON websocket_sessions(user_id)
    `);

    console.log('✅ Delivery tracking tables created successfully');

    // Add description column to categories table if missing
    await db.execute(sql`
      ALTER TABLE categories ADD COLUMN IF NOT EXISTS description TEXT
    `);

    // Fix stores table - add missing columns
    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS website TEXT
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS rating DECIMAL(3,2) DEFAULT 0.00
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS total_reviews INTEGER DEFAULT 0
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS phone TEXT
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS logo TEXT
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS cover_image TEXT
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS featured BOOLEAN DEFAULT false
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS store_type TEXT DEFAULT 'retail'
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS cuisine_type TEXT
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS delivery_time TEXT
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS minimum_order DECIMAL(10,2)
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS delivery_fee DECIMAL(10,2)
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS is_delivery_available BOOLEAN DEFAULT false
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS opening_hours TEXT
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS latitude DECIMAL(10,8)
    `);

    await db.execute(sql`
      ALTER TABLE stores ADD COLUMN IF NOT EXISTS longitude DECIMAL(11,8)
    `);

    // Add missing timestamp columns to categories if needed
    await db.execute(sql`
      ALTER TABLE categories ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()
    `);

    await db.execute(sql`
      ALTER TABLE categories ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()
    `);

    // Fix products table - add missing columns
    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS category_id INTEGER REFERENCES categories(id)
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS store_id INTEGER REFERENCES stores(id) NOT NULL DEFAULT 1
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS original_price DECIMAL(10,2)
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS stock INTEGER DEFAULT 0
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS images TEXT[] DEFAULT '{}'
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS rating DECIMAL(3,2) DEFAULT 0.00
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS total_reviews INTEGER DEFAULT 0
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS is_fast_sell BOOLEAN DEFAULT false
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS is_on_offer BOOLEAN DEFAULT false
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS offer_percentage INTEGER DEFAULT 0
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS offer_end_date TEXT
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS product_type TEXT DEFAULT 'retail'
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS preparation_time TEXT
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS ingredients TEXT[] DEFAULT '{}'
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS allergens TEXT[] DEFAULT '{}'
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS spice_level TEXT
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS is_vegetarian BOOLEAN DEFAULT false
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS is_vegan BOOLEAN DEFAULT false
    `);

    await db.execute(sql`
      ALTER TABLE products ADD COLUMN IF NOT EXISTS nutrition_info TEXT
    `);

    // Fix orders table - ensure all columns exist
    await db.execute(sql`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_id INTEGER REFERENCES users(id) NOT NULL DEFAULT 1
    `);

    await db.execute(sql`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS total_amount DECIMAL(10,2) NOT NULL DEFAULT 0.00
    `);

    await db.execute(sql`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS shipping_address TEXT NOT NULL DEFAULT ''
    `);

    await db.execute(sql`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method TEXT NOT NULL DEFAULT 'cash'
    `);

    await db.execute(sql`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS phone TEXT NOT NULL DEFAULT ''
    `);

    await db.execute(sql`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_name TEXT NOT NULL DEFAULT ''
    `);

    await db.execute(sql`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS latitude DECIMAL(10,8)
    `);

    await db.execute(sql`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS longitude DECIMAL(11,8)
    `);

    await db.execute(sql`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending'
    `);

    // Fix users table - ensure all columns exist
    await db.execute(sql`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT
    `);

    await db.execute(sql`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT
    `);

    await db.execute(sql`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT
    `);

    await db.execute(sql`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
    `);

    await db.execute(sql`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'customer'
    `);

    await db.execute(sql`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS approval_date TIMESTAMP
    `);

    await db.execute(sql`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_by INTEGER REFERENCES users(id)
    `);

    await db.execute(sql`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS rejection_reason TEXT
    `);

    // Remove any enum constraints on role column to allow delivery_partner
    await db.execute(sql`
      ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
    `);

    // Also check for and remove any enum type constraints
    await db.execute(sql`
      DO $$ 
      BEGIN
        IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
          ALTER TABLE users ALTER COLUMN role TYPE TEXT;
          DROP TYPE user_role CASCADE;
        END IF;
      END $$;
    `);

    // Update existing users to have usernames based on email
    await db.execute(sql`
      UPDATE users SET username = SPLIT_PART(email, '@', 1) WHERE username IS NULL
    `);

    // Make username column NOT NULL after updating existing records
    await db.execute(sql`
      ALTER TABLE users ALTER COLUMN username SET NOT NULL
    `);

    // Fix orders table schema mismatch
    await db.execute(sql`
      ALTER TABLE orders DROP COLUMN IF EXISTS user_id
    `);

    await db.execute(sql`
      ALTER TABLE orders DROP COLUMN IF EXISTS address_id
    `);

    await db.execute(sql`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_id INTEGER REFERENCES users(id) NOT NULL DEFAULT 1
    `);

    await db.execute(sql`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS shipping_address TEXT NOT NULL DEFAULT '123 Main St'
    `);

    await db.execute(sql`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS phone TEXT NOT NULL DEFAULT '+1234567890'
    `);

    await db.execute(sql`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_name TEXT NOT NULL DEFAULT 'Default Customer'
    `);

    // Create cart_items table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS cart_items (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) NOT NULL,
        product_id INTEGER REFERENCES products(id) NOT NULL,
        quantity INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    // Create wishlist_items table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS wishlist_items (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) NOT NULL,
        product_id INTEGER REFERENCES products(id) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    // Create product_reviews table for rating system
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS product_reviews (
        id SERIAL PRIMARY KEY,
        product_id INTEGER NOT NULL REFERENCES products(id),
        customer_id INTEGER NOT NULL REFERENCES users(id),
        order_id INTEGER REFERENCES orders(id),
        rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
        title TEXT,
        comment TEXT,
        images TEXT[] DEFAULT '{}',
        is_verified_purchase BOOLEAN DEFAULT FALSE,
        is_approved BOOLEAN DEFAULT TRUE,
        helpful_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Create indexes for product_reviews table
    await db.execute(sql`
      CREATE INDEX IF NOT EXISTS idx_product_reviews_product_id ON product_reviews(product_id)
    `);

    await db.execute(sql`
      CREATE INDEX IF NOT EXISTS idx_product_reviews_customer_id ON product_reviews(customer_id)
    `);

    await db.execute(sql`
      CREATE INDEX IF NOT EXISTS idx_product_reviews_rating ON product_reviews(rating)
    `);

    // Create push_subscriptions table for mobile notifications
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        endpoint TEXT NOT NULL,
        p256dh TEXT NOT NULL,
        auth TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, endpoint)
      )
    `);

    // Create order_items table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS order_items (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id) NOT NULL,
        product_id INTEGER REFERENCES products(id) NOT NULL,
        quantity INTEGER NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        store_id INTEGER REFERENCES stores(id) NOT NULL
      )
    `);

    // Ensure store_id column exists in order_items table
    await db.execute(sql`
      ALTER TABLE order_items ADD COLUMN IF NOT EXISTS store_id INTEGER REFERENCES stores(id)
    `);

    // Create missing admin panel tables
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS coupons (
        id SERIAL PRIMARY KEY,
        code TEXT NOT NULL UNIQUE,
        discount_type TEXT NOT NULL DEFAULT 'percentage',
        discount_value DECIMAL(10,2) NOT NULL,
        minimum_order_amount DECIMAL(10,2) DEFAULT 0,
        maximum_discount DECIMAL(10,2),
        usage_limit INTEGER,
        used_count INTEGER DEFAULT 0,
        expires_at TIMESTAMP,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS banners (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        image_url TEXT NOT NULL,
        link_url TEXT,
        position TEXT NOT NULL DEFAULT 'homepage',
        is_active BOOLEAN DEFAULT true,
        display_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS support_tickets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        priority TEXT NOT NULL DEFAULT 'medium',
        category TEXT NOT NULL DEFAULT 'general',
        assigned_to INTEGER REFERENCES admin_users(id),
        created_at TIMESTAMP DEFAULT NOW() NOT NULL,
        updated_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS site_settings (
        id SERIAL PRIMARY KEY,
        setting_key TEXT NOT NULL UNIQUE,
        setting_value TEXT,
        setting_type TEXT NOT NULL DEFAULT 'string',
        description TEXT,
        is_public BOOLEAN DEFAULT false,
        updated_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS payment_transactions (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id) NOT NULL,
        transaction_id TEXT UNIQUE,
        payment_method TEXT NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        gateway_response TEXT,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS admin_logs (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER REFERENCES admin_users(id) NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT,
        target_id INTEGER,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS fraud_alerts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        order_id INTEGER REFERENCES orders(id),
        alert_type TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS vendor_verifications (
        id SERIAL PRIMARY KEY,
        store_id INTEGER REFERENCES stores(id) NOT NULL,
        document_type TEXT NOT NULL,
        document_url TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        reviewed_by INTEGER REFERENCES admin_users(id),
        reviewed_at TIMESTAMP,
        rejection_reason TEXT,
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS commissions (
        id SERIAL PRIMARY KEY,
        store_id INTEGER REFERENCES stores(id) NOT NULL,
        order_id INTEGER REFERENCES orders(id) NOT NULL,
        gross_amount DECIMAL(10,2) NOT NULL,
        commission_rate DECIMAL(5,2) NOT NULL,
        commission_amount DECIMAL(10,2) NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    // Create order_tracking table for order status tracking
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS order_tracking (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id) NOT NULL,
        status TEXT NOT NULL,
        description TEXT,
        location TEXT,
        updated_at TIMESTAMP DEFAULT NOW() NOT NULL
      )
    `);

    console.log("Database migrations completed successfully");
  } catch (error) {
    console.error("Migration error:", error);
    throw error;
  }
}