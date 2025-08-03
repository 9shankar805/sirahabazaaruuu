import { neon } from "@neondatabase/serverless";
import dotenv from "dotenv";
dotenv.config();

const sql = neon(process.env.DATABASE_URL!);

// Sample data for retailers and restaurants
const locations = [
  { city: "Siraha", latitude: "26.6603", longitude: "86.2064" },
  { city: "Lahan", latitude: "26.7201", longitude: "86.4928" },
  { city: "Mirchaiya", latitude: "26.7815", longitude: "86.4926" },
  { city: "Golbazar", latitude: "26.7542", longitude: "86.5028" }
];

const retailStores = [
  {
    name: "Siraha Electronics Hub",
    description: "Complete range of electronics and gadgets for all your needs",
    address: "Main Market Road, Siraha",
    phone: "+977-9841234567",
    website: "https://sirahaelectronics.com",
    storeType: "retail",
    category: "Electronics"
  },
  {
    name: "Fashion Palace Lahan",
    description: "Latest fashion trends and traditional wear collection",
    address: "Bazar Line, Lahan",
    phone: "+977-9812345678",
    website: "https://fashionpalace.com",
    storeType: "retail",
    category: "Fashion"
  },
  {
    name: "Mirchaiya Book Store",
    description: "Academic books, novels, and stationery items",
    address: "Education Quarter, Mirchaiya",
    phone: "+977-9823456789",
    website: "https://mirchaiyabooks.com",
    storeType: "retail",
    category: "Books"
  },
  {
    name: "Golbazar Pharmacy",
    description: "Medicines, health supplements, and medical equipment",
    address: "Hospital Road, Golbazar",
    phone: "+977-9834567890",
    website: "https://golbazarpharmacy.com",
    storeType: "retail",
    category: "Health"
  },
  {
    name: "Siraha Sports Center",
    description: "Sports equipment, fitness gear, and outdoor accessories",
    address: "Stadium Area, Siraha",
    phone: "+977-9845678901",
    website: "https://sirahasports.com",
    storeType: "retail",
    category: "Sports"
  },
  {
    name: "Lahan Mobile Shop",
    description: "Latest smartphones, accessories, and repair services",
    address: "Technology Hub, Lahan",
    phone: "+977-9856789012",
    website: "https://lahanmobile.com",
    storeType: "retail",
    category: "Electronics"
  },
  {
    name: "Mirchaiya Grocery Store",
    description: "Fresh vegetables, groceries, and daily essentials",
    address: "Central Market, Mirchaiya",
    phone: "+977-9867890123",
    website: "https://mirchaiyagrocery.com",
    storeType: "retail",
    category: "Grocery"
  },
  {
    name: "Golbazar Hardware Store",
    description: "Construction materials, tools, and hardware supplies",
    address: "Industrial Area, Golbazar",
    phone: "+977-9878901234",
    website: "https://golbazarhardware.com",
    storeType: "retail",
    category: "Hardware"
  },
  {
    name: "Siraha Beauty Parlor",
    description: "Beauty products, cosmetics, and personal care items",
    address: "Women's Market, Siraha",
    phone: "+977-9889012345",
    website: "https://sirahabeauty.com",
    storeType: "retail",
    category: "Beauty"
  },
  {
    name: "Lahan Textile House",
    description: "Quality fabrics, clothing materials, and tailoring services",
    address: "Textile Market, Lahan",
    phone: "+977-9890123456",
    website: "https://lahantextile.com",
    storeType: "retail",
    category: "Textile"
  },
  {
    name: "Mirchaiya Computer Center",
    description: "Computers, laptops, software, and IT services",
    address: "IT Park, Mirchaiya",
    phone: "+977-9801234567",
    website: "https://mirchaiyacomputer.com",
    storeType: "retail",
    category: "Electronics"
  },
  {
    name: "Golbazar Gift Shop",
    description: "Gifts, decorative items, and party supplies",
    address: "Shopping Complex, Golbazar",
    phone: "+977-9812345679",
    website: "https://golbazargifts.com",
    storeType: "retail",
    category: "Gifts"
  },
  {
    name: "Siraha Furniture Mart",
    description: "Home and office furniture, interior decoration items",
    address: "Furniture Street, Siraha",
    phone: "+977-9823456780",
    website: "https://sirahafurniture.com",
    storeType: "retail",
    category: "Furniture"
  },
  {
    name: "Lahan Shoe Store",
    description: "Footwear for all ages, from casual to formal shoes",
    address: "Footwear Market, Lahan",
    phone: "+977-9834567891",
    website: "https://lahanshoes.com",
    storeType: "retail",
    category: "Footwear"
  },
  {
    name: "Mirchaiya Stationary Hub",
    description: "Office supplies, art materials, and printing services",
    address: "Business District, Mirchaiya",
    phone: "+977-9845678902",
    website: "https://mirchaiyastationary.com",
    storeType: "retail",
    category: "Stationary"
  },
  {
    name: "Golbazar Auto Parts",
    description: "Vehicle spare parts, accessories, and automotive supplies",
    address: "Auto Market, Golbazar",
    phone: "+977-9856789013",
    website: "https://golbazarauto.com",
    storeType: "retail",
    category: "Automotive"
  },
  {
    name: "Siraha Kitchenware Store",
    description: "Kitchen appliances, utensils, and cooking equipment",
    address: "Kitchen Market, Siraha",
    phone: "+977-9867890124",
    website: "https://sirahakitchen.com",
    storeType: "retail",
    category: "Kitchen"
  },
  {
    name: "Lahan Music Center",
    description: "Musical instruments, audio equipment, and music accessories",
    address: "Cultural Center, Lahan",
    phone: "+977-9878901235",
    website: "https://lahanmusic.com",
    storeType: "retail",
    category: "Music"
  },
  {
    name: "Mirchaiya Toy Store",
    description: "Educational toys, games, and children's entertainment",
    address: "Children's Market, Mirchaiya",
    phone: "+977-9889012346",
    website: "https://mirchaiyatoys.com",
    storeType: "retail",
    category: "Toys"
  },
  {
    name: "Golbazar Watch Shop",
    description: "Watches, clocks, jewelry, and repair services",
    address: "Jewelry Street, Golbazar",
    phone: "+977-9890123457",
    website: "https://golbazarwatch.com",
    storeType: "retail",
    category: "Jewelry"
  }
];

const restaurants = [
  {
    name: "Siraha Spice Kitchen",
    description: "Authentic Nepali cuisine with traditional flavors and spices",
    address: "Food Street, Siraha",
    phone: "+977-9841234568",
    website: "https://sirahaspice.com",
    storeType: "restaurant",
    cuisineType: "Nepali",
    deliveryTime: "25-35 mins",
    minimumOrder: "200",
    deliveryFee: "50"
  },
  {
    name: "Lahan Momo Palace",
    description: "Delicious momos and Tibetan cuisine specialties",
    address: "Momo Corner, Lahan",
    phone: "+977-9812345679",
    website: "https://lahanmomo.com",
    storeType: "restaurant",
    cuisineType: "Tibetan",
    deliveryTime: "20-30 mins",
    minimumOrder: "150",
    deliveryFee: "40"
  },
  {
    name: "Mirchaiya Biryani House",
    description: "Aromatic biryanis and North Indian delicacies",
    address: "Biryani Street, Mirchaiya",
    phone: "+977-9823456780",
    website: "https://mirchaiyabiryani.com",
    storeType: "restaurant",
    cuisineType: "Indian",
    deliveryTime: "30-40 mins",
    minimumOrder: "300",
    deliveryFee: "60"
  },
  {
    name: "Golbazar Chinese Corner",
    description: "Authentic Chinese dishes and Indo-Chinese fusion",
    address: "China Town, Golbazar",
    phone: "+977-9834567891",
    website: "https://golbazarchinese.com",
    storeType: "restaurant",
    cuisineType: "Chinese",
    deliveryTime: "25-35 mins",
    minimumOrder: "250",
    deliveryFee: "50"
  },
  {
    name: "Siraha Pizza Hub",
    description: "Wood-fired pizzas and Italian cuisine favorites",
    address: "Pizza Square, Siraha",
    phone: "+977-9845678902",
    website: "https://sirahapizza.com",
    storeType: "restaurant",
    cuisineType: "Italian",
    deliveryTime: "20-30 mins",
    minimumOrder: "400",
    deliveryFee: "70"
  },
  {
    name: "Lahan Burger Joint",
    description: "Gourmet burgers, fries, and fast food favorites",
    address: "Fast Food Lane, Lahan",
    phone: "+977-9856789013",
    website: "https://lahanburger.com",
    storeType: "restaurant",
    cuisineType: "Fast Food",
    deliveryTime: "15-25 mins",
    minimumOrder: "200",
    deliveryFee: "40"
  },
  {
    name: "Mirchaiya Thali House",
    description: "Traditional dal bhat and complete meal sets",
    address: "Traditional Food Center, Mirchaiya",
    phone: "+977-9867890124",
    website: "https://mirchaiyathali.com",
    storeType: "restaurant",
    cuisineType: "Nepali",
    deliveryTime: "30-40 mins",
    minimumOrder: "180",
    deliveryFee: "45"
  },
  {
    name: "Golbazar BBQ Grill",
    description: "Grilled meats, barbecue, and continental dishes",
    address: "Grill Station, Golbazar",
    phone: "+977-9878901235",
    website: "https://golbazarbbq.com",
    storeType: "restaurant",
    cuisineType: "Continental",
    deliveryTime: "35-45 mins",
    minimumOrder: "500",
    deliveryFee: "80"
  },
  {
    name: "Siraha Sweet House",
    description: "Traditional sweets, desserts, and mithai varieties",
    address: "Sweet Market, Siraha",
    phone: "+977-9889012346",
    website: "https://sirahasweets.com",
    storeType: "restaurant",
    cuisineType: "Sweets",
    deliveryTime: "15-20 mins",
    minimumOrder: "100",
    deliveryFee: "30"
  },
  {
    name: "Lahan Coffee House",
    description: "Freshly brewed coffee, tea, and light snacks",
    address: "Coffee Street, Lahan",
    phone: "+977-9890123457",
    website: "https://lahancoffee.com",
    storeType: "restaurant",
    cuisineType: "Cafe",
    deliveryTime: "10-15 mins",
    minimumOrder: "120",
    deliveryFee: "25"
  },
  {
    name: "Mirchaiya Seafood Palace",
    description: "Fresh fish, prawns, and coastal cuisine specialties",
    address: "Seafood Market, Mirchaiya",
    phone: "+977-9801234568",
    website: "https://mirchaiyaseafood.com",
    storeType: "restaurant",
    cuisineType: "Seafood",
    deliveryTime: "40-50 mins",
    minimumOrder: "600",
    deliveryFee: "90"
  },
  {
    name: "Golbazar Vegan Delight",
    description: "Plant-based cuisine and healthy vegan options",
    address: "Health Food Zone, Golbazar",
    phone: "+977-9812345680",
    website: "https://golbazarvegan.com",
    storeType: "restaurant",
    cuisineType: "Vegan",
    deliveryTime: "25-35 mins",
    minimumOrder: "300",
    deliveryFee: "55"
  },
  {
    name: "Siraha Chowmein Center",
    description: "Variety of noodles, chowmein, and Asian stir-fries",
    address: "Noodle Street, Siraha",
    phone: "+977-9823456781",
    website: "https://sirahachowmein.com",
    storeType: "restaurant",
    cuisineType: "Asian",
    deliveryTime: "20-30 mins",
    minimumOrder: "180",
    deliveryFee: "40"
  },
  {
    name: "Lahan Tiffin Service",
    description: "Home-style meals and healthy tiffin delivery",
    address: "Home Food Center, Lahan",
    phone: "+977-9834567892",
    website: "https://lahantiffin.com",
    storeType: "restaurant",
    cuisineType: "Home Food",
    deliveryTime: "45-60 mins",
    minimumOrder: "250",
    deliveryFee: "35"
  },
  {
    name: "Mirchaiya Ice Cream Parlor",
    description: "Handmade ice creams, sundaes, and frozen desserts",
    address: "Dessert Lane, Mirchaiya",
    phone: "+977-9845678903",
    website: "https://mirchaiyaicecream.com",
    storeType: "restaurant",
    cuisineType: "Desserts",
    deliveryTime: "15-20 mins",
    minimumOrder: "150",
    deliveryFee: "30"
  },
  {
    name: "Golbazar Sandwich Shop",
    description: "Fresh sandwiches, wraps, and healthy quick bites",
    address: "Quick Bite Corner, Golbazar",
    phone: "+977-9856789014",
    website: "https://golbazarsandwich.com",
    storeType: "restaurant",
    cuisineType: "Fast Food",
    deliveryTime: "12-18 mins",
    minimumOrder: "120",
    deliveryFee: "25"
  },
  {
    name: "Siraha Traditional Kitchen",
    description: "Authentic traditional recipes and local specialties",
    address: "Heritage Food Area, Siraha",
    phone: "+977-9867890125",
    website: "https://sirahatraditional.com",
    storeType: "restaurant",
    cuisineType: "Traditional",
    deliveryTime: "35-45 mins",
    minimumOrder: "220",
    deliveryFee: "50"
  },
  {
    name: "Lahan Juice Bar",
    description: "Fresh fruit juices, smoothies, and healthy drinks",
    address: "Health Drink Zone, Lahan",
    phone: "+977-9878901236",
    website: "https://lahanjuice.com",
    storeType: "restaurant",
    cuisineType: "Beverages",
    deliveryTime: "10-15 mins",
    minimumOrder: "80",
    deliveryFee: "20"
  },
  {
    name: "Mirchaiya Breakfast Corner",
    description: "Early morning breakfast and healthy start options",
    address: "Morning Market, Mirchaiya",
    phone: "+977-9889012347",
    website: "https://mirchaiyabreakfast.com",
    storeType: "restaurant",
    cuisineType: "Breakfast",
    deliveryTime: "15-25 mins",
    minimumOrder: "100",
    deliveryFee: "25"
  },
  {
    name: "Golbazar Night Diner",
    description: "Late-night food, snacks, and 24-hour dining",
    address: "Night Food Street, Golbazar",
    phone: "+977-9890123458",
    website: "https://golbazarnight.com",
    storeType: "restaurant",
    cuisineType: "Multi-cuisine",
    deliveryTime: "25-35 mins",
    minimumOrder: "200",
    deliveryFee: "60"
  }
];

async function createSampleUsers() {
  console.log("Creating sample store owners...");
  
  // Create 40 users (owners for 20 retailers + 20 restaurants)
  const users = [];
  let userIndex = 1;
  
  // Create users for retailers
  for (let i = 0; i < 20; i++) {
    const location = locations[i % locations.length];
    users.push({
      email: `retailer${userIndex}@siraha.com`,
      fullName: `Store Owner ${userIndex}`,
      phone: `+977-98${String(userIndex).padStart(8, '0')}`,
      address: `${retailStores[i].address}, ${location.city}`,
      city: location.city,
      role: 'shopkeeper',
      status: 'active'
    });
    userIndex++;
  }
  
  // Create users for restaurants
  for (let i = 0; i < 20; i++) {
    const location = locations[i % locations.length];
    users.push({
      email: `restaurant${userIndex-20}@siraha.com`,
      fullName: `Restaurant Owner ${userIndex-20}`,
      phone: `+977-98${String(userIndex).padStart(8, '0')}`,
      address: `${restaurants[i].address}, ${location.city}`,
      city: location.city,
      role: 'shopkeeper',
      status: 'active'
    });
    userIndex++;
  }
  
  // Insert users
  for (const user of users) {
    try {
      await sql`
        INSERT INTO users (email, full_name, phone, address, city, role, status, password)
        VALUES (${user.email}, ${user.fullName}, ${user.phone}, ${user.address}, ${user.city}, ${user.role}, ${user.status}, 'hashed_password_123')
        ON CONFLICT (email) DO NOTHING
      `;
    } catch (error) {
      console.error(`Error creating user ${user.email}:`, error);
    }
  }
  
  console.log("Sample users created successfully!");
}

async function createSampleStores() {
  console.log("Creating sample stores...");
  
  // Get created users
  const users = await sql`SELECT id, email FROM users WHERE role = 'shopkeeper' ORDER BY id`;
  
  if (users.length < 40) {
    console.error("Not enough users found. Please ensure users are created first.");
    return;
  }
  
  // Create retail stores
  for (let i = 0; i < 20; i++) {
    const store = retailStores[i];
    const location = locations[i % locations.length];
    const user = users[i];
    
    const slug = store.name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
    
    try {
      await sql`
        INSERT INTO stores (
          name, slug, description, owner_id, address, city, latitude, longitude,
          phone, website, store_type, is_active, featured,
          rating, total_reviews, is_delivery_available
        )
        VALUES (
          ${store.name}, ${slug}, ${store.description}, ${user.id}, 
          ${store.address + ', ' + location.city}, ${location.city}, 
          ${location.latitude}, ${location.longitude}, ${store.phone}, ${store.website},
          ${store.storeType}, true, ${Math.random() > 0.7},
          ${(Math.random() * 2 + 3).toFixed(1)}, ${Math.floor(Math.random() * 100) + 10},
          ${Math.random() > 0.3}
        )
        ON CONFLICT (slug) DO NOTHING
      `;
    } catch (error) {
      console.error(`Error creating store ${store.name}:`, error);
    }
  }
  
  // Create restaurants
  for (let i = 0; i < 20; i++) {
    const restaurant = restaurants[i];
    const location = locations[i % locations.length];
    const user = users[i + 20]; // Restaurant owners start from index 20
    
    const slug = restaurant.name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
    
    try {
      await sql`
        INSERT INTO stores (
          name, slug, description, owner_id, address, city, latitude, longitude,
          phone, website, store_type, cuisine_type, delivery_time, minimum_order,
          delivery_fee, is_delivery_available, is_active, featured,
          rating, total_reviews
        )
        VALUES (
          ${restaurant.name}, ${slug}, ${restaurant.description}, ${user.id},
          ${restaurant.address + ', ' + location.city}, ${location.city}, 
          ${location.latitude}, ${location.longitude}, ${restaurant.phone}, ${restaurant.website},
          ${restaurant.storeType}, ${restaurant.cuisineType}, ${restaurant.deliveryTime},
          ${restaurant.minimumOrder}, ${restaurant.deliveryFee}, true, true, ${Math.random() > 0.6},
          ${(Math.random() * 2 + 3).toFixed(1)}, ${Math.floor(Math.random() * 200) + 20}
        )
        ON CONFLICT (slug) DO NOTHING
      `;
    } catch (error) {
      console.error(`Error creating restaurant ${restaurant.name}:`, error);
    }
  }
  
  console.log("Sample stores created successfully!");
}

async function createSampleCategories() {
  console.log("Creating sample categories...");
  
  const categories = [
    { name: "Electronics", slug: "electronics", icon: "smartphone" },
    { name: "Fashion", slug: "fashion", icon: "shirt" },
    { name: "Books", slug: "books", icon: "book" },
    { name: "Health", slug: "health", icon: "heart" },
    { name: "Sports", slug: "sports", icon: "dumbbell" },
    { name: "Grocery", slug: "grocery", icon: "shopping-basket" },
    { name: "Hardware", slug: "hardware", icon: "wrench" },
    { name: "Beauty", slug: "beauty", icon: "sparkles" },
    { name: "Textile", slug: "textile", icon: "shirt" },
    { name: "Gifts", slug: "gifts", icon: "gift" },
    { name: "Furniture", slug: "furniture", icon: "sofa" },
    { name: "Footwear", slug: "footwear", icon: "footprints" },
    { name: "Stationary", slug: "stationary", icon: "pen-tool" },
    { name: "Automotive", slug: "automotive", icon: "car" },
    { name: "Kitchen", slug: "kitchen", icon: "chef-hat" },
    { name: "Music", slug: "music", icon: "music" },
    { name: "Toys", slug: "toys", icon: "gamepad-2" },
    { name: "Jewelry", slug: "jewelry", icon: "gem" },
    { name: "Food & Beverages", slug: "food-beverages", icon: "utensils" }
  ];
  
  for (const category of categories) {
    try {
      await sql`
        INSERT INTO categories (name, slug, icon)
        VALUES (${category.name}, ${category.slug}, ${category.icon})
        ON CONFLICT (slug) DO NOTHING
      `;
    } catch (error) {
      console.error(`Error creating category ${category.name}:`, error);
    }
  }
  
  console.log("Sample categories created successfully!");
}

async function main() {
  try {
    console.log("Starting data seeding process...");
    
    await createSampleCategories();
    await createSampleUsers();
    await createSampleStores();
    
    console.log("✅ All sample data created successfully!");
    console.log("📊 Summary:");
    console.log("- 40 Store owners created");
    console.log("- 20 Retail stores created");
    console.log("- 20 Restaurants created");
    console.log("- Stores distributed across Siraha, Lahan, Mirchaiya, and Golbazar");
    
  } catch (error) {
    console.error("❌ Error during data seeding:", error);
  }
}

main();