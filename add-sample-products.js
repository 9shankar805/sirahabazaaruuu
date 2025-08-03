#!/usr/bin/env node

import fetch from 'node-fetch';

const API_BASE = 'http://localhost:5000/api';

async function addSampleData() {
  console.log('🚀 Adding stores and products...');

  // 1. Create Stores first
  const stores = [
    {
      name: 'Siraha Electronics Hub',
      ownerId: 4,
      description: 'Latest electronics and gadgets for all your tech needs',
      address: 'Electronics Market, Siraha, Nepal',
      city: 'Siraha',
      state: 'Province 2',
      phone: '+977-9801234570',
      storeType: 'retail',
      latitude: 26.6603,
      longitude: 86.2064
    },
    {
      name: 'Fashion Palace Lahan',
      ownerId: 5,
      description: 'Latest fashion trends and traditional wear collection',
      address: 'Fashion Street, Lahan, Nepal',
      city: 'Lahan',
      state: 'Province 2',
      phone: '+977-9801234571',
      storeType: 'retail',
      latitude: 26.7201,
      longitude: 86.4928
    },
    {
      name: 'Mirchaiya Spice Kitchen',
      ownerId: 6,
      description: 'Authentic Nepali cuisine and delicious food',
      address: 'Food Court, Mirchaiya, Nepal',
      city: 'Mirchaiya',
      state: 'Province 2',
      phone: '+977-9801234572',
      storeType: 'restaurant',
      cuisineType: 'Nepali',
      deliveryTime: '25-35 mins',
      minimumOrder: 200,
      deliveryFee: 50,
      latitude: 26.7815,
      longitude: 86.4926
    }
  ];

  console.log('\n🏪 Creating stores...');
  for (const store of stores) {
    try {
      const response = await fetch(`${API_BASE}/stores`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(store)
      });
      
      if (response.ok) {
        const result = await response.json();
        console.log(`✅ Store created: ${store.name} (ID: ${result.id})`);
      } else {
        const error = await response.text();
        console.log(`⚠️ Store ${store.name}: ${error}`);
      }
    } catch (error) {
      console.log(`❌ Error creating store ${store.name}:`, error.message);
    }
  }

  // Wait for stores to be created
  await new Promise(resolve => setTimeout(resolve, 2000));

  // 2. Create Products
  const products = [
    // Electronics (Store ID 1)
    {
      name: 'Samsung Galaxy A54 5G',
      description: 'Latest 5G smartphone with excellent camera and performance',
      price: 45000,
      originalPrice: 50000,
      categoryId: 1,
      storeId: 1,
      stock: 25,
      imageUrl: 'https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=400'
    },
    {
      name: 'Sony WH-1000XM4 Headphones',
      description: 'Industry-leading noise cancelling wireless headphones',
      price: 28000,
      originalPrice: 32000,
      categoryId: 1,
      storeId: 1,
      stock: 15,
      imageUrl: 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=400'
    },
    {
      name: 'Dell Laptop Inspiron 15',
      description: 'High performance laptop for work and gaming',
      price: 65000,
      originalPrice: 70000,
      categoryId: 1,
      storeId: 1,
      stock: 8,
      imageUrl: 'https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=400'
    },
    // Fashion (Store ID 2)
    {
      name: 'Men\'s Cotton T-Shirt',
      description: 'Comfortable cotton t-shirt for daily wear',
      price: 850,
      originalPrice: 1000,
      categoryId: 2,
      storeId: 2,
      stock: 50,
      imageUrl: 'https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=400'
    },
    {
      name: 'Women\'s Kurta Set',
      description: 'Traditional ethnic wear with beautiful embroidery',
      price: 2500,
      originalPrice: 3000,
      categoryId: 2,
      storeId: 2,
      stock: 30,
      imageUrl: 'https://images.unsplash.com/photo-1583391733956-6c78276477e2?w=400'
    },
    {
      name: 'Denim Jeans',
      description: 'Classic blue denim jeans for casual wear',
      price: 2200,
      originalPrice: 2500,
      categoryId: 2,
      storeId: 2,
      stock: 40,
      imageUrl: 'https://images.unsplash.com/photo-1542272604-787c3835535d?w=400'
    },
    // Food (Store ID 3)
    {
      name: 'Chicken Momo (10 pcs)',
      description: 'Delicious steamed chicken dumplings with special sauce',
      price: 180,
      categoryId: 3,
      storeId: 3,
      stock: 100,
      imageUrl: 'https://images.unsplash.com/photo-1496116218417-1a781b1c416c?w=400',
      preparationTime: '15-20 mins',
      isVegetarian: false
    },
    {
      name: 'Dal Bhat Set',
      description: 'Traditional Nepali meal with rice, lentils, and vegetables',
      price: 220,
      categoryId: 3,
      storeId: 3,
      stock: 50,
      imageUrl: 'https://images.unsplash.com/photo-1585937421612-70a008356fbe?w=400',
      preparationTime: '20-25 mins',
      isVegetarian: true
    },
    {
      name: 'Chicken Chow Mein',
      description: 'Stir-fried noodles with chicken and vegetables',
      price: 200,
      categoryId: 3,
      storeId: 3,
      stock: 75,
      imageUrl: 'https://images.unsplash.com/photo-1612929633738-8fe44f7ec841?w=400',
      preparationTime: '18-22 mins',
      isVegetarian: false
    }
  ];

  console.log('\n🛍️ Creating products...');
  for (const product of products) {
    try {
      const response = await fetch(`${API_BASE}/products`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(product)
      });
      
      if (response.ok) {
        const result = await response.json();
        console.log(`✅ Product created: ${product.name} (ID: ${result.id})`);
      } else {
        const error = await response.text();
        console.log(`⚠️ Product ${product.name}: ${error}`);
      }
    } catch (error) {
      console.log(`❌ Error creating product ${product.name}:`, error.message);
    }
  }

  console.log('\n🎉 Sample data creation complete!');
  
  // Verify data was created
  console.log('\n🔍 Verifying data...');
  try {
    const storesResponse = await fetch(`${API_BASE}/stores`);
    const productsResponse = await fetch(`${API_BASE}/products`);
    
    const stores = await storesResponse.json();
    const products = await productsResponse.json();
    
    console.log(`✅ Stores in database: ${stores.length}`);
    console.log(`✅ Products in database: ${products.length}`);
    
    if (stores.length > 0) {
      console.log('📋 Stores:');
      stores.forEach(store => console.log(`  - ${store.name}`));
    }
    
    if (products.length > 0) {
      console.log('📋 Products:');
      products.forEach(product => console.log(`  - ${product.name} (₹${product.price})`));
    }
    
  } catch (error) {
    console.log('⚠️ Error verifying data:', error.message);
  }
}

addSampleData();