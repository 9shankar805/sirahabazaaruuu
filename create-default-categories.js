#!/usr/bin/env node

import fetch from 'node-fetch';

const API_BASE = 'http://localhost:5000/api';

async function createDefaultCategories() {
  console.log('📂 Creating default categories...');
  
  const categories = [
    {
      name: 'Electronics',
      description: 'Electronics products and gadgets',
      icon: 'smartphone'
    },
    {
      name: 'Fashion',
      description: 'Fashion and clothing items',
      icon: 'shirt'
    },
    {
      name: 'Food & Beverages',
      description: 'Food and beverage items',
      icon: 'utensils'
    },
    {
      name: 'Health & Beauty',
      description: 'Health and beauty products',
      icon: 'heart'
    },
    {
      name: 'Sports & Fitness',
      description: 'Sports and fitness equipment',
      icon: 'dumbbell'
    },
    {
      name: 'Books & Education',
      description: 'Books and educational materials',
      icon: 'book'
    },
    {
      name: 'Home & Garden',
      description: 'Home and garden items',
      icon: 'home'
    },
    {
      name: 'Grocery',
      description: 'Grocery and daily essentials',
      icon: 'shopping-cart'
    }
  ];

  for (const category of categories) {
    try {
      const response = await fetch(`${API_BASE}/admin/categories`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(category)
      });
      
      if (response.ok) {
        console.log(`✅ Created category: ${category.name}`);
      } else {
        console.log(`⚠️ Category ${category.name} might already exist`);
      }
    } catch (error) {
      console.log(`⚠️ Error creating category ${category.name}`);
    }
  }

  console.log('✅ Categories creation completed');
}

createDefaultCategories();