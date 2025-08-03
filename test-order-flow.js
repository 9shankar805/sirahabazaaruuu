import { pool } from './server/db.js';

async function createTestUsers() {
  const client = await pool.connect();
  
  try {
    console.log('🔧 Creating test users for order flow...');
    
    // Create test customer
    const customerResult = await client.query(`
      INSERT INTO users (username, email, password, full_name, phone, address, city, role, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (email) DO UPDATE SET 
        username = EXCLUDED.username,
        full_name = EXCLUDED.full_name,
        phone = EXCLUDED.phone,
        address = EXCLUDED.address,
        city = EXCLUDED.city,
        role = EXCLUDED.role,
        status = EXCLUDED.status
      RETURNING id, username, email, role, status
    `, [
      'testcustomer', 
      'customer@test.com', 
      '$2b$10$8K1p/a9UOWEzmHQVy6hR.OEzf/yziFGsKGTdNE6A3LZJTrY8mQw8G', // password: test123
      'Test Customer', 
      '+977-9876543210', 
      '123 Main Street, Siraha', 
      'Siraha', 
      'customer', 
      'active'
    ]);
    console.log('✅ Test customer created:', customerResult.rows[0]);
    
    // Create test shopkeeper
    const shopkeeperResult = await client.query(`
      INSERT INTO users (username, email, password, full_name, phone, address, city, role, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (email) DO UPDATE SET 
        username = EXCLUDED.username,
        full_name = EXCLUDED.full_name,
        phone = EXCLUDED.phone,
        address = EXCLUDED.address,
        city = EXCLUDED.city,
        role = EXCLUDED.role,
        status = EXCLUDED.status
      RETURNING id, username, email, role, status
    `, [
      'testshopkeeper', 
      'shopkeeper@test.com', 
      '$2b$10$8K1p/a9UOWEzmHQVy6hR.OEzf/yziFGsKGTdNE6A3LZJTrY8mQw8G', // password: test123
      'Test Shopkeeper', 
      '+977-9876543211', 
      '456 Market Road, Siraha', 
      'Siraha', 
      'shopkeeper', 
      'approved'
    ]);
    console.log('✅ Test shopkeeper created:', shopkeeperResult.rows[0]);
    
    // Create test delivery partner
    const deliveryPartnerResult = await client.query(`
      INSERT INTO users (username, email, password, full_name, phone, address, city, role, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (email) DO UPDATE SET 
        username = EXCLUDED.username,
        full_name = EXCLUDED.full_name,
        phone = EXCLUDED.phone,
        address = EXCLUDED.address,
        city = EXCLUDED.city,
        role = EXCLUDED.role,
        status = EXCLUDED.status
      RETURNING id, username, email, role, status
    `, [
      'testdelivery', 
      'delivery@test.com', 
      '$2b$10$8K1p/a9UOWEzmHQVy6hR.OEzf/yziFGsKGTdNE6A3LZJTrY8mQw8G', // password: test123
      'Test Delivery Partner', 
      '+977-9876543212', 
      '789 Delivery Street, Siraha', 
      'Siraha', 
      'delivery_partner', 
      'approved'
    ]);
    console.log('✅ Test delivery partner created:', deliveryPartnerResult.rows[0]);
    
    // Create delivery partner record
    await client.query(`
      INSERT INTO delivery_partners (
        user_id, vehicle_type, vehicle_number, driving_license_number, 
        availability_status, is_verified, rating, total_deliveries
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (user_id) DO UPDATE SET 
        vehicle_type = EXCLUDED.vehicle_type,
        vehicle_number = EXCLUDED.vehicle_number,
        driving_license_number = EXCLUDED.driving_license_number,
        availability_status = EXCLUDED.availability_status,
        is_verified = EXCLUDED.is_verified
    `, [
      deliveryPartnerResult.rows[0].id,
      'motorcycle',
      'BA-01-PA-1234',
      'DL123456789',
      'available',
      true,
      4.5,
      0
    ]);
    console.log('✅ Delivery partner record created');
    
    // Create test store for shopkeeper
    const storeResult = await client.query(`
      INSERT INTO stores (
        name, slug, description, owner_id, address, city, state, 
        latitude, longitude, phone, rating, is_active, store_type
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      ON CONFLICT (slug) DO UPDATE SET 
        name = EXCLUDED.name,
        description = EXCLUDED.description,
        owner_id = EXCLUDED.owner_id,
        address = EXCLUDED.address,
        city = EXCLUDED.city,
        state = EXCLUDED.state,
        latitude = EXCLUDED.latitude,
        longitude = EXCLUDED.longitude,
        phone = EXCLUDED.phone,
        is_active = EXCLUDED.is_active
      RETURNING id, name, slug, owner_id
    `, [
      'Test Electronics Store',
      'test-electronics-store',
      'A test store for order flow testing',
      shopkeeperResult.rows[0].id,
      '456 Market Road, Siraha',
      'Siraha',
      'Province 2',
      26.7674,
      86.5151,
      '+977-9876543211',
      4.5,
      true,
      'retail'
    ]);
    console.log('✅ Test store created:', storeResult.rows[0]);
    
    // Create test product for the store
    const productResult = await client.query(`
      INSERT INTO products (
        name, slug, description, price, original_price, category_id, store_id,
        stock_quantity, is_active, weight, dimensions, brand
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      ON CONFLICT (slug) DO UPDATE SET 
        name = EXCLUDED.name,
        description = EXCLUDED.description,
        price = EXCLUDED.price,
        original_price = EXCLUDED.original_price,
        category_id = EXCLUDED.category_id,
        store_id = EXCLUDED.store_id,
        stock_quantity = EXCLUDED.stock_quantity,
        is_active = EXCLUDED.is_active
      RETURNING id, name, slug, price, store_id
    `, [
      'Test Smartphone',
      'test-smartphone',
      'A test smartphone for order flow testing',
      25000.00,
      30000.00,
      1, // Electronics category
      storeResult.rows[0].id,
      10,
      true,
      '200g',
      '15x7x0.8 cm',
      'TestBrand'
    ]);
    console.log('✅ Test product created:', productResult.rows[0]);
    
    return {
      customer: customerResult.rows[0],
      shopkeeper: shopkeeperResult.rows[0],
      deliveryPartner: deliveryPartnerResult.rows[0],
      store: storeResult.rows[0],
      product: productResult.rows[0]
    };
    
  } finally {
    client.release();
  }
}

// Create the test users
createTestUsers()
  .then(result => {
    console.log('\n🎉 Test users created successfully!');
    console.log('Test data:', result);
    console.log('\n📝 Login credentials for all users:');
    console.log('- Email: customer@test.com, shopkeeper@test.com, delivery@test.com');
    console.log('- Password: test123');
    console.log('\n🛒 Ready to test order flow!');
    process.exit(0);
  })
  .catch(error => {
    console.error('❌ Error creating test users:', error);
    process.exit(1);
  });