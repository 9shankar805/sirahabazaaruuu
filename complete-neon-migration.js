#!/usr/bin/env node

import { Pool } from 'pg';
import bcrypt from 'bcrypt';

// Connect to Neon database
const pool = new Pool({
  connectionString: "postgresql://neondb_owner:npg_B14cMjkFUhuw@ep-wispy-paper-a1eejnp5-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require",
  ssl: { rejectUnauthorized: false }
});

async function completeDataMigration() {
  const client = await pool.connect();
  
  try {
    console.log("🚀 Completing Siraha Bazaar data migration to Neon database...\n");

    // 1. Create essential categories first
    console.log("📂 Creating categories...");
    const categories = [
      { name: "Electronics", slug: "electronics", icon: "smartphone", description: "Electronic devices and gadgets" },
      { name: "Fashion", slug: "fashion", icon: "shirt", description: "Clothing and accessories" },
      { name: "Food & Beverages", slug: "food-beverages", icon: "utensils", description: "Restaurant food and drinks" },
      { name: "Grocery", slug: "grocery", icon: "shopping-cart", description: "Daily essentials and food items" },
      { name: "Health", slug: "health", icon: "heart", description: "Health and medical products" },
      { name: "Beauty", slug: "beauty", icon: "sparkles", description: "Beauty and cosmetic products" },
      { name: "Books", slug: "books", icon: "book", description: "Books and educational materials" },
      { name: "Sports", slug: "sports", icon: "dumbbell", description: "Sports equipment and accessories" }
    ];
    
    for (const category of categories) {
      await client.query(`
        INSERT INTO categories (name, slug, icon, description, created_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        ON CONFLICT (name) DO NOTHING
      `, [category.name, category.slug, category.icon, category.description]);
    }
    
    // 2. Create approved shopkeeper users
    console.log("👤 Creating shopkeeper users...");
    const shopkeepers = [
      {
        username: "family_restaurant",
        email: "owner@familyrestaurant.com", 
        fullName: "Ram Bahadur Shrestha",
        phone: "+977-9876543211",
        address: "Main Street, Ward 5, Siraha Municipality",
        city: "Siraha",
        state: "Province 2"
      },
      {
        username: "siraha_electronics",
        email: "owner@sirahaelectronics.com",
        fullName: "Sita Kumari Sharma", 
        phone: "+977-9876543212",
        address: "Electronics Market, Ward 3, Siraha Municipality",
        city: "Siraha",
        state: "Province 2"
      },
      {
        username: "lahan_grocery",
        email: "owner@lahangrocery.com",
        fullName: "Krishna Prasad Yadav",
        phone: "+977-9876543213", 
        address: "Central Market, Ward 2, Lahan Municipality",
        city: "Lahan",
        state: "Province 2"
      },
      {
        username: "momo_palace",
        email: "owner@momopalace.com",
        fullName: "Binod Thapa Magar",
        phone: "+977-9876543214",
        address: "Food Street, Ward 1, Mirchaiya Municipality", 
        city: "Mirchaiya",
        state: "Province 2"
      }
    ];
    
    const hashedPassword = await bcrypt.hash("shop123", 10);
    const userIds = [];
    
    for (const shopkeeper of shopkeepers) {
      const result = await client.query(`
        INSERT INTO users (username, email, password, full_name, phone, address, city, state, role, status, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'shopkeeper', 'approved', NOW(), NOW())
        ON CONFLICT (email) DO UPDATE SET
          username = EXCLUDED.username,
          full_name = EXCLUDED.full_name,
          phone = EXCLUDED.phone,
          address = EXCLUDED.address,
          city = EXCLUDED.city,
          state = EXCLUDED.state,
          role = 'shopkeeper',
          status = 'approved'
        RETURNING id
      `, [shopkeeper.username, shopkeeper.email, hashedPassword, shopkeeper.fullName, shopkeeper.phone, shopkeeper.address, shopkeeper.city, shopkeeper.state]);
      
      userIds.push({...shopkeeper, id: result.rows[0].id});
    }

    // 3. Create stores
    console.log("🏪 Creating stores...");
    const stores = [
      {
        name: "Family Restaurant Siraha",
        slug: "family-restaurant-siraha",
        description: "Authentic Nepali and Indian cuisine served fresh daily with traditional flavors",
        ownerId: userIds.find(u => u.username === "family_restaurant").id,
        address: "Main Street, Ward 5, Siraha Municipality", 
        city: "Siraha",
        state: "Province 2",
        country: "Nepal",
        latitude: "26.6602",
        longitude: "86.2070", 
        phone: "+977-9876543211",
        storeType: "restaurant",
        cuisineType: "nepali-indian",
        deliveryTime: "25-35 mins",
        minimumOrder: "300.00",
        deliveryFee: "50.00",
        isDeliveryAvailable: true,
        rating: "4.5",
        totalReviews: 128,
        featured: true
      },
      {
        name: "Siraha Electronics Center",
        slug: "siraha-electronics-center",
        description: "Latest electronics, mobile phones, computers and accessories at competitive prices",
        ownerId: userIds.find(u => u.username === "siraha_electronics").id,
        address: "Electronics Market, Ward 3, Siraha Municipality",
        city: "Siraha", 
        state: "Province 2",
        country: "Nepal",
        latitude: "26.6615",
        longitude: "86.2085",
        phone: "+977-9876543212",
        storeType: "retail", 
        deliveryFee: "40.00",
        isDeliveryAvailable: true,
        rating: "4.2",
        totalReviews: 89,
        featured: true
      },
      {
        name: "Lahan Grocery Store",
        slug: "lahan-grocery-store", 
        description: "Fresh groceries, vegetables, and daily essentials for your household needs",
        ownerId: userIds.find(u => u.username === "lahan_grocery").id,
        address: "Central Market, Ward 2, Lahan Municipality",
        city: "Lahan",
        state: "Province 2",
        country: "Nepal", 
        latitude: "26.7191",
        longitude: "86.0951",
        phone: "+977-9876543213",
        storeType: "retail",
        deliveryFee: "30.00", 
        isDeliveryAvailable: true,
        rating: "4.3",
        totalReviews: 67
      },
      {
        name: "Momo Palace Restaurant",
        slug: "momo-palace-restaurant",
        description: "Delicious authentic momos and Tibetan cuisine in the heart of Mirchaiya",
        ownerId: userIds.find(u => u.username === "momo_palace").id,
        address: "Food Street, Ward 1, Mirchaiya Municipality",
        city: "Mirchaiya",
        state: "Province 2", 
        country: "Nepal",
        latitude: "26.7815",
        longitude: "86.4926",
        phone: "+977-9876543214",
        storeType: "restaurant",
        cuisineType: "tibetan-nepali",
        deliveryTime: "20-30 mins",
        minimumOrder: "250.00",
        deliveryFee: "45.00",
        isDeliveryAvailable: true,
        rating: "4.6", 
        totalReviews: 156
      }
    ];
    
    const storeIds = [];
    for (const store of stores) {
      const result = await client.query(`
        INSERT INTO stores (
          name, slug, description, owner_id, address, city, state, country, 
          latitude, longitude, phone, store_type, cuisine_type, delivery_time,
          minimum_order, delivery_fee, is_delivery_available, rating, total_reviews,
          featured, is_active, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, true, NOW(), NOW())
        ON CONFLICT (slug) DO UPDATE SET
          name = EXCLUDED.name,
          description = EXCLUDED.description,
          address = EXCLUDED.address,
          phone = EXCLUDED.phone,
          rating = EXCLUDED.rating,
          total_reviews = EXCLUDED.total_reviews
        RETURNING id
      `, [
        store.name, store.slug, store.description, store.ownerId, store.address, 
        store.city, store.state, store.country, store.latitude, store.longitude,
        store.phone, store.storeType, store.cuisineType || null, store.deliveryTime || null,
        store.minimumOrder || null, store.deliveryFee, store.isDeliveryAvailable,
        store.rating, store.totalReviews, store.featured || false
      ]);
      
      storeIds.push({...store, id: result.rows[0].id});
    }

    // 4. Get category IDs
    const categoriesResult = await client.query('SELECT * FROM categories');
    const categoryMap = {};
    categoriesResult.rows.forEach(cat => {
      categoryMap[cat.name] = cat.id;
    });

    // 5. Create products
    console.log("🛍️ Creating products...");
    
    const products = [
      // Family Restaurant Products
      {
        name: "Dal Bhat Set",
        slug: "dal-bhat-set-family",
        description: "Traditional Nepali meal with dal, bhat, vegetables, pickle and papad",
        price: "350.00",
        originalPrice: "400.00", 
        categoryId: categoryMap["Food & Beverages"],
        storeId: storeIds.find(s => s.slug === "family-restaurant-siraha").id,
        stock: 50,
        imageUrl: "https://images.unsplash.com/photo-1606491956689-2ea866880c84?w=400&h=300&fit=crop",
        rating: "4.6",
        totalReviews: 45,
        productType: "food",
        preparationTime: "15-20 mins", 
        ingredients: ["Rice", "Lentils", "Vegetables", "Spices"],
        isVegetarian: true,
        spiceLevel: "mild",
        isOnOffer: true,
        offerPercentage: 12
      },
      {
        name: "Chicken Momo (10 pcs)",
        slug: "chicken-momo-family",
        description: "Steamed chicken dumplings served with spicy tomato chutney",
        price: "280.00",
        categoryId: categoryMap["Food & Beverages"],
        storeId: storeIds.find(s => s.slug === "family-restaurant-siraha").id, 
        stock: 30,
        imageUrl: "https://images.unsplash.com/photo-1601050690597-df0568f70950?w=400&h=300&fit=crop",
        rating: "4.8",
        totalReviews: 67,
        productType: "food",
        preparationTime: "20-25 mins",
        ingredients: ["Chicken", "Flour", "Spices", "Vegetables"],
        spiceLevel: "medium",
        isVegetarian: false
      },
      {
        name: "Paneer Butter Masala",
        slug: "paneer-butter-masala-family", 
        description: "Rich and creamy paneer curry with butter and aromatic spices",
        price: "320.00",
        categoryId: categoryMap["Food & Beverages"],
        storeId: storeIds.find(s => s.slug === "family-restaurant-siraha").id,
        stock: 25,
        imageUrl: "https://images.unsplash.com/photo-1631452180519-c014fe946bc7?w=400&h=300&fit=crop",
        rating: "4.4", 
        totalReviews: 38,
        productType: "food",
        preparationTime: "18-22 mins",
        ingredients: ["Paneer", "Tomatoes", "Cream", "Spices"],
        spiceLevel: "mild",
        isVegetarian: true
      },
      // Electronics Store Products
      {
        name: "Samsung Galaxy A54 5G",
        slug: "samsung-galaxy-a54",
        description: "Latest Samsung smartphone with excellent camera, 5G connectivity and long battery life",
        price: "45000.00",
        originalPrice: "48000.00",
        categoryId: categoryMap["Electronics"],
        storeId: storeIds.find(s => s.slug === "siraha-electronics-center").id,
        stock: 15, 
        imageUrl: "https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=400&h=300&fit=crop",
        rating: "4.4",
        totalReviews: 23,
        isOnOffer: true,
        offerPercentage: 6
      },
      {
        name: "Wireless Bluetooth Headphones",
        slug: "wireless-bluetooth-headphones",
        description: "High-quality wireless headphones with active noise cancellation and 30hr battery",
        price: "3500.00",
        categoryId: categoryMap["Electronics"],
        storeId: storeIds.find(s => s.slug === "siraha-electronics-center").id,
        stock: 25,
        imageUrl: "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=400&h=300&fit=crop",
        rating: "4.1",
        totalReviews: 18
      },
      {
        name: "Laptop Lenovo ThinkPad",
        slug: "laptop-lenovo-thinkpad",
        description: "Professional laptop with Intel i5 processor, 8GB RAM, and 256GB SSD storage",
        price: "85000.00",
        categoryId: categoryMap["Electronics"], 
        storeId: storeIds.find(s => s.slug === "siraha-electronics-center").id,
        stock: 8,
        imageUrl: "https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=400&h=300&fit=crop",
        rating: "4.5",
        totalReviews: 12
      },
      // Grocery Store Products
      {
        name: "Organic Basmati Rice (5kg)",
        slug: "organic-basmati-rice-5kg",
        description: "Premium quality organic basmati rice, perfect for daily meals and special occasions",
        price: "750.00",
        categoryId: categoryMap["Grocery"],
        storeId: storeIds.find(s => s.slug === "lahan-grocery-store").id,
        stock: 40,
        imageUrl: "https://images.unsplash.com/photo-1586201375761-83865001e31c?w=400&h=300&fit=crop", 
        rating: "4.5",
        totalReviews: 34
      },
      {
        name: "Fresh Vegetables Mix (1kg)",
        slug: "fresh-vegetables-mix", 
        description: "Assorted fresh seasonal vegetables including potato, onion, tomato, and green vegetables",
        price: "120.00",
        categoryId: categoryMap["Grocery"],
        storeId: storeIds.find(s => s.slug === "lahan-grocery-store").id,
        stock: 60,
        imageUrl: "https://images.unsplash.com/photo-1610348725531-843dff563e2c?w=400&h=300&fit=crop",
        rating: "4.3",
        totalReviews: 28
      },
      {
        name: "Pure Mustard Oil (1L)",
        slug: "pure-mustard-oil-1l",
        description: "Cold-pressed pure mustard oil, ideal for cooking and traditional use",
        price: "320.00",
        categoryId: categoryMap["Grocery"],
        storeId: storeIds.find(s => s.slug === "lahan-grocery-store").id,
        stock: 35,
        imageUrl: "https://images.unsplash.com/photo-1474979266404-7eaacbcd87c5?w=400&h=300&fit=crop",
        rating: "4.2",
        totalReviews: 19
      },
      // Momo Palace Products
      {
        name: "Chicken Momo (12 pcs)",
        slug: "chicken-momo-palace",
        description: "Signature steamed chicken momos with special spicy sauce", 
        price: "320.00",
        categoryId: categoryMap["Food & Beverages"],
        storeId: storeIds.find(s => s.slug === "momo-palace-restaurant").id,
        stock: 50,
        imageUrl: "https://images.unsplash.com/photo-1601050690597-df0568f70950?w=400&h=300&fit=crop",
        rating: "4.8",
        totalReviews: 89,
        productType: "food",
        preparationTime: "18-22 mins",
        ingredients: ["Chicken", "Flour", "Ginger", "Garlic", "Spices"],
        spiceLevel: "medium",
        isVegetarian: false
      },
      {
        name: "Veg Momo (12 pcs)",
        slug: "veg-momo-palace", 
        description: "Delicious vegetable momos filled with fresh cabbage, carrot and spices",
        price: "250.00",
        categoryId: categoryMap["Food & Beverages"],
        storeId: storeIds.find(s => s.slug === "momo-palace-restaurant").id,
        stock: 50,
        imageUrl: "https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=400&h=300&fit=crop",
        rating: "4.6",
        totalReviews: 67,
        productType: "food", 
        preparationTime: "15-20 mins",
        ingredients: ["Cabbage", "Carrot", "Flour", "Spices"],
        spiceLevel: "mild",
        isVegetarian: true
      },
      {
        name: "Thukpa (Tibetan Noodle Soup)",
        slug: "thukpa-tibetan-soup",
        description: "Traditional Tibetan noodle soup with vegetables and aromatic broth",
        price: "280.00",
        categoryId: categoryMap["Food & Beverages"],
        storeId: storeIds.find(s => s.slug === "momo-palace-restaurant").id,
        stock: 30,
        imageUrl: "https://images.unsplash.com/photo-1569718212165-3a8278d5f624?w=400&h=300&fit=crop",
        rating: "4.4",
        totalReviews: 42,
        productType: "food",
        preparationTime: "20-25 mins", 
        ingredients: ["Noodles", "Vegetables", "Broth", "Spices"],
        spiceLevel: "mild",
        isVegetarian: true
      }
    ];

    for (const product of products) {
      await client.query(`
        INSERT INTO products (
          name, slug, description, price, original_price, category_id, store_id, stock,
          image_url, rating, total_reviews, is_active, is_fast_sell, is_on_offer,
          offer_percentage, product_type, preparation_time, ingredients, allergens,
          spice_level, is_vegetarian, is_vegan, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, true, false, $12, $13, $14, $15, $16, $17, $18, $19, false, NOW())
        ON CONFLICT (slug) DO NOTHING
      `, [
        product.name, product.slug, product.description, product.price, product.originalPrice || null,
        product.categoryId, product.storeId, product.stock, product.imageUrl, product.rating,
        product.totalReviews, product.isOnOffer || false, product.offerPercentage || 0,
        product.productType || 'retail', product.preparationTime || null, 
        product.ingredients || null, product.allergens || null, product.spiceLevel || null,
        product.isVegetarian || false
      ]);
    }

    // 6. Create delivery zones
    console.log("🚚 Creating delivery zones...");
    const deliveryZones = [
      { name: "Siraha Local (0-5km)", minDistance: "0.0", maxDistance: "5.0", baseFee: "30.00", perKmRate: "8.00" },
      { name: "Siraha Extended (5-15km)", minDistance: "5.0", maxDistance: "15.0", baseFee: "50.00", perKmRate: "12.00" },
      { name: "Inter-City (15-50km)", minDistance: "15.0", maxDistance: "50.0", baseFee: "80.00", perKmRate: "15.00" }
    ];
    
    for (const zone of deliveryZones) {
      await client.query(`
        INSERT INTO delivery_zones (name, min_distance, max_distance, base_fee, per_km_rate, is_active, created_at)
        VALUES ($1, $2, $3, $4, $5, true, NOW())
        ON CONFLICT (name) DO NOTHING
      `, [zone.name, zone.minDistance, zone.maxDistance, zone.baseFee, zone.perKmRate]);
    }

    // Final summary
    const finalCounts = await Promise.all([
      client.query('SELECT COUNT(*) FROM users WHERE role = \'shopkeeper\''),
      client.query('SELECT COUNT(*) FROM stores'),
      client.query('SELECT COUNT(*) FROM products'),
      client.query('SELECT COUNT(*) FROM categories'),
      client.query('SELECT COUNT(*) FROM delivery_zones')
    ]);
    
    console.log("\n✅ Migration completed successfully!");
    console.log("📊 FINAL DATABASE SUMMARY:");
    console.log(`   👤 Shopkeepers: ${finalCounts[0].rows[0].count}`);
    console.log(`   🏪 Stores: ${finalCounts[1].rows[0].count}`); 
    console.log(`   🛍️ Products: ${finalCounts[2].rows[0].count}`);
    console.log(`   📂 Categories: ${finalCounts[3].rows[0].count}`);
    console.log(`   🚚 Delivery Zones: ${finalCounts[4].rows[0].count}`);
    console.log("   🌍 Locations: Siraha, Lahan, Mirchaiya (Nepal)");
    console.log("\n🎉 Siraha Bazaar is ready for business on the new Neon database!");
    
  } catch (error) {
    console.error("❌ Migration failed:", error.message);
    throw error;
  } finally {
    client.release();
  }
}

completeDataMigration()
  .then(() => {
    console.log("\n✨ Database migration completed successfully!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("\n💥 Migration failed:", error.message); 
    process.exit(1);
  });