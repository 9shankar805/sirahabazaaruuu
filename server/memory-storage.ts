import type { 
  User, InsertUser, Store, InsertStore, Category, InsertCategory, 
  Product, InsertProduct, Order, InsertOrder, OrderItem, InsertOrderItem,
  CartItem, InsertCartItem, WishlistItem, InsertWishlistItem
} from "@shared/schema";
import { IStorage } from "./storage";

// Simple in-memory storage for development/fallback
export class MemoryStorage implements IStorage {
  private users: User[] = [];
  private stores: Store[] = [];
  private categories: Category[] = [];
  private products: Product[] = [];
  private orders: Order[] = [];
  private orderItems: OrderItem[] = [];
  private cartItems: CartItem[] = [];
  private wishlistItems: WishlistItem[] = [];
  private nextId = 1;

  constructor() {
    // Data initialization disabled - database will be empty by default
    // this.initializeDefaultData();
  }

  private initializeDefaultData() {
    // Initialize with sample categories
    const categories = [
      { name: "Electronics", icon: "smartphone" },
      { name: "Fashion", icon: "shirt" },
      { name: "Food & Beverages", icon: "utensils" },
      { name: "Health", icon: "heart" },
      { name: "Sports", icon: "dumbbell" }
    ];

    categories.forEach(cat => {
      this.categories.push({
        id: this.nextId++,
        name: cat.name,
        slug: cat.name.toLowerCase().replace(/\s+/g, '-'),
        description: `${cat.name} products and services`,
        icon: cat.icon,
        createdAt: new Date(),
        updatedAt: new Date()
      });
    });

    // Create sample users (store owners)
    const locations = [
      { city: "Siraha", latitude: "26.6603", longitude: "86.2064" },
      { city: "Lahan", latitude: "26.7201", longitude: "86.4928" },
      { city: "Mirchaiya", latitude: "26.7815", longitude: "86.4926" },
      { city: "Golbazar", latitude: "26.7542", longitude: "86.5028" }
    ];

    // Create 20 retail stores with unique images
    const retailStores = [
      { name: "Siraha Electronics Hub", logo: "https://images.unsplash.com/photo-1560472354-b33ff0c44a43?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1441986300917-64674bd600d8?w=800&h=400&fit=crop" },
      { name: "Fashion Palace Lahan", logo: "https://images.unsplash.com/photo-1445205170230-053b83016050?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1441984904996-e0b6ba687e04?w=800&h=400&fit=crop" },
      { name: "Mirchaiya Book Store", logo: "https://images.unsplash.com/photo-1481627834876-b7833e8f5570?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=800&h=400&fit=crop" },
      { name: "Golbazar Pharmacy", logo: "https://images.unsplash.com/photo-1576602976047-174e57a47881?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1586105251261-72a756497a11?w=800&h=400&fit=crop" },
      { name: "Siraha Sports Center", logo: "https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=800&h=400&fit=crop" },
      { name: "Lahan Mobile Shop", logo: "https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1607853202273-797f1c22a38e?w=800&h=400&fit=crop" },
      { name: "Mirchaiya Grocery Store", logo: "https://images.unsplash.com/photo-1578916171728-46686eac8d58?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1542838132-92c53300491e?w=800&h=400&fit=crop" },
      { name: "Golbazar Hardware Store", logo: "https://images.unsplash.com/photo-1504917595217-d4dc5ebe6122?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=800&h=400&fit=crop" },
      { name: "Siraha Beauty Parlor", logo: "https://images.unsplash.com/photo-1560066984-138dadb4c035?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1522337360788-8b13dee7a37e?w=800&h=400&fit=crop" },
      { name: "Lahan Textile House", logo: "https://images.unsplash.com/photo-1567401893414-76b7b1e5a7a5?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1558769132-cb1aea458c5e?w=800&h=400&fit=crop" },
      { name: "Mirchaiya Computer Center", logo: "https://images.unsplash.com/photo-1518717758536-85ae29035b6d?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1541746972996-4e0b0f93e586?w=800&h=400&fit=crop" },
      { name: "Golbazar Gift Shop", logo: "https://images.unsplash.com/photo-1513475382585-d06e58bcb0e0?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1549465220-1a8b9238cd48?w=800&h=400&fit=crop" },
      { name: "Siraha Furniture Mart", logo: "https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=800&h=400&fit=crop" },
      { name: "Lahan Shoe Store", logo: "https://images.unsplash.com/photo-1549298916-b41d501d3772?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1441906363819-8094026a7c3d?w=800&h=400&fit=crop" },
      { name: "Mirchaiya Stationary Hub", logo: "https://images.unsplash.com/photo-1513475382585-d06e58bcb0e0?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1481627834876-b7833e8f5570?w=800&h=400&fit=crop" },
      { name: "Golbazar Auto Parts", logo: "https://images.unsplash.com/photo-1485291571150-772bcfc10da5?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1543335973-dbaba6d4fb57?w=800&h=400&fit=crop" },
      { name: "Siraha Kitchenware Store", logo: "https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1584622650111-993a426fbf0a?w=800&h=400&fit=crop" },
      { name: "Lahan Music Center", logo: "https://images.unsplash.com/photo-1493225457124-a3eb161ffa5f?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1471478331149-c72f17e33c73?w=800&h=400&fit=crop" },
      { name: "Mirchaiya Toy Store", logo: "https://images.unsplash.com/photo-1596461404969-9ae70f2830c1?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1558060370-d644479cb6f7?w=800&h=400&fit=crop" },
      { name: "Golbazar Watch Shop", logo: "https://images.unsplash.com/photo-1524592094714-0f0654e20314?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1594534475808-b18fc33b045e?w=800&h=400&fit=crop" }
    ];

    for (let i = 0; i < 20; i++) {
      const location = locations[i % locations.length];
      const userId = this.nextId++;
      const storeData = retailStores[i];
      
      // Create user
      this.users.push({
        id: userId,
        username: `retail${i + 1}`,
        email: `retail${i + 1}@siraha.com`,
        password: 'hashed_password',
        firebaseUid: null,
        fullName: `${storeData.name} Owner`,
        phone: `+977-98${String(i + 1).padStart(8, '0')}`,
        address: `${location.city} Main Market`,
        city: location.city,
        state: "Province 1",
        role: "shopkeeper",
        status: "active",
        approvalDate: new Date(),
        approvedBy: null,
        rejectionReason: null,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      // Create store
      this.stores.push({
        id: this.nextId++,
        name: storeData.name,
        slug: storeData.name.toLowerCase().replace(/\s+/g, '-'),
        description: `Quality products and services in ${location.city}`,
        ownerId: userId,
        address: `${location.city} Main Market, Ward ${i + 1}`,
        city: location.city,
        state: "Province 1",
        postalCode: "56700",
        country: "Nepal",
        latitude: location.latitude,
        longitude: location.longitude,
        phone: `+977-98${String(i + 1).padStart(8, '0')}`,
        website: `https://${storeData.name.toLowerCase().replace(/\s+/g, '')}.com`,
        logo: storeData.logo,
        coverImage: storeData.cover,
        rating: "4.2",
        totalReviews: Math.floor(Math.random() * 100) + 10,
        featured: Math.random() > 0.7,
        isActive: true,
        storeType: "retail",
        cuisineType: null,
        deliveryTime: null,
        minimumOrder: null,
        deliveryFee: null,
        isDeliveryAvailable: Math.random() > 0.3,
        openingHours: "9:00 AM - 8:00 PM",
        createdAt: new Date(),
        updatedAt: new Date()
      });
    }

    // Create 20 restaurants with unique images
    const restaurants = [
      { name: "Siraha Spice Kitchen", cuisine: "Nepali", logo: "https://images.unsplash.com/photo-1571091718767-18b5b1457add?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1517248135467-4c7edcad34c4?w=800&h=400&fit=crop" },
      { name: "Lahan Momo Palace", cuisine: "Nepali", logo: "https://images.unsplash.com/photo-1534422298391-e4f8c172dddb?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1552566626-52f8b828add9?w=800&h=400&fit=crop" },
      { name: "Mirchaiya Biryani House", cuisine: "Indian", logo: "https://images.unsplash.com/photo-1563379091339-03246963d96c?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1551218808-94e220e084d2?w=800&h=400&fit=crop" },
      { name: "Golbazar Chinese Corner", cuisine: "Chinese", logo: "https://images.unsplash.com/photo-1596797038530-2c107229654b?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1555396273-367ea4eb4db5?w=800&h=400&fit=crop" },
      { name: "Siraha Pizza Hub", cuisine: "Italian", logo: "https://images.unsplash.com/photo-1565299624946-b28f40a0ca4b?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1513104890138-7c749659a591?w=800&h=400&fit=crop" },
      { name: "Lahan Burger Joint", cuisine: "Fast Food", logo: "https://images.unsplash.com/photo-1571091655789-405eb7a3a3a8?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1550317138-10000687a72b?w=800&h=400&fit=crop" },
      { name: "Mirchaiya Thali House", cuisine: "Indian", logo: "https://images.unsplash.com/photo-1546833999-b9f581a1996d?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1606491956689-2ea866880c84?w=800&h=400&fit=crop" },
      { name: "Golbazar BBQ Grill", cuisine: "Continental", logo: "https://images.unsplash.com/photo-1558030006-450675393462?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1544025162-d76694265947?w=800&h=400&fit=crop" },
      { name: "Siraha Sweet House", cuisine: "Indian", logo: "https://images.unsplash.com/photo-1578985545062-69928b1d9587?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1571115764595-644a1f56a55c?w=800&h=400&fit=crop" },
      { name: "Lahan Coffee House", cuisine: "Continental", logo: "https://images.unsplash.com/photo-1501339847302-ac426a4a7cbb?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1554118811-1e0d58224f24?w=800&h=400&fit=crop" },
      { name: "Mirchaiya Seafood Palace", cuisine: "Continental", logo: "https://images.unsplash.com/photo-1565958011703-44f9829ba187?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1559339352-11d035aa65de?w=800&h=400&fit=crop" },
      { name: "Golbazar Vegan Delight", cuisine: "Continental", logo: "https://images.unsplash.com/photo-1512621776951-a57141f2eefd?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1490645935967-10de6ba17061?w=800&h=400&fit=crop" },
      { name: "Siraha Chowmein Center", cuisine: "Chinese", logo: "https://images.unsplash.com/photo-1603133872878-684f208fb84b?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1569718212165-3a8278d5f624?w=800&h=400&fit=crop" },
      { name: "Lahan Tiffin Service", cuisine: "Nepali", logo: "https://images.unsplash.com/photo-1585937421612-70a008356fbe?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1606787366850-de6ba128da6c?w=800&h=400&fit=crop" },
      { name: "Mirchaiya Ice Cream Parlor", cuisine: "Fast Food", logo: "https://images.unsplash.com/photo-1570197788417-0e82375c9371?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1497034825429-c343d7c6a68f?w=800&h=400&fit=crop" },
      { name: "Golbazar Sandwich Shop", cuisine: "Fast Food", logo: "https://images.unsplash.com/photo-1571091655789-405eb7a3a3a8?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1539252554453-80ab65ce3586?w=800&h=400&fit=crop" },
      { name: "Siraha Traditional Kitchen", cuisine: "Nepali", logo: "https://images.unsplash.com/photo-1504113888839-1c8eb50233d3?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1571091718767-18b5b1457add?w=800&h=400&fit=crop" },
      { name: "Lahan Juice Bar", cuisine: "Continental", logo: "https://images.unsplash.com/photo-1546173159-315724a31696?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1519708227418-c8947a927c40?w=800&h=400&fit=crop" },
      { name: "Mirchaiya Breakfast Corner", cuisine: "Continental", logo: "https://images.unsplash.com/photo-1506084868230-bb9d95c24759?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1533089860892-a7c6f0a88666?w=800&h=400&fit=crop" },
      { name: "Golbazar Night Diner", cuisine: "Fast Food", logo: "https://images.unsplash.com/photo-1414235077428-338989a2e8c0?w=200&h=200&fit=crop", cover: "https://images.unsplash.com/photo-1517248135467-4c7edcad34c4?w=800&h=400&fit=crop" }
    ];

    for (let i = 0; i < 20; i++) {
      const location = locations[i % locations.length];
      const userId = this.nextId++;
      const restaurantData = restaurants[i];
      
      // Create user
      this.users.push({
        id: userId,
        username: `restaurant${i + 1}`,
        email: `restaurant${i + 1}@siraha.com`,
        password: 'hashed_password',
        firebaseUid: null,
        fullName: `${restaurantData.name} Owner`,
        phone: `+977-97${String(i + 1).padStart(8, '0')}`,
        address: `${location.city} Food Street`,
        city: location.city,
        state: "Province 1",
        role: "shopkeeper",
        status: "active",
        approvalDate: new Date(),
        approvedBy: null,
        rejectionReason: null,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      // Create restaurant
      this.stores.push({
        id: this.nextId++,
        name: restaurantData.name,
        slug: restaurantData.name.toLowerCase().replace(/\s+/g, '-'),
        description: `Delicious food and dining experience in ${location.city}`,
        ownerId: userId,
        address: `${location.city} Food Street, Block ${i + 1}`,
        city: location.city,
        state: "Province 1",
        postalCode: "56700",
        country: "Nepal",
        latitude: location.latitude,
        longitude: location.longitude,
        phone: `+977-97${String(i + 1).padStart(8, '0')}`,
        website: `https://${restaurantData.name.toLowerCase().replace(/\s+/g, '')}.com`,
        logo: restaurantData.logo,
        coverImage: restaurantData.cover,
        rating: (Math.random() * 2 + 3).toFixed(1),
        totalReviews: Math.floor(Math.random() * 200) + 20,
        featured: Math.random() > 0.6,
        isActive: true,
        storeType: "restaurant",
        cuisineType: restaurantData.cuisine,
        deliveryTime: `${20 + (i % 3) * 10}-${30 + (i % 3) * 10} mins`,
        minimumOrder: String(100 + (i % 5) * 50),
        deliveryFee: String(30 + (i % 4) * 20),
        isDeliveryAvailable: true,
        openingHours: "10:00 AM - 10:00 PM",
        createdAt: new Date(),
        updatedAt: new Date()
      });
    }

    // Add products to each store
    this.createSampleProducts();
  }

  private createSampleProducts() {
    // Define store-specific product catalogs based on store names
    const storeProductCatalogs: { [storeName: string]: any[] } = {
      // Electronics stores
      "Siraha Electronics Hub": [
        { name: "Samsung Galaxy A54", category: "Electronics", price: "35000", description: "Latest smartphone with great camera", image: "https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=400&h=400&fit=crop&auto=format" },
        { name: "Sony Headphones WH-1000XM4", category: "Electronics", price: "25000", description: "Noise cancelling wireless headphones", image: "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=400&h=400&fit=crop&auto=format" },
        { name: "Dell Laptop Inspiron 15", category: "Electronics", price: "65000", description: "High performance laptop for work", image: "https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=400&h=400&fit=crop&auto=format" },
        { name: "iPhone 13", category: "Electronics", price: "85000", description: "Apple iPhone with advanced features", image: "https://images.unsplash.com/photo-1592750475338-74b7b21085ab?w=400&h=400&fit=crop&auto=format" },
        { name: "Gaming Mouse Logitech", category: "Electronics", price: "3500", description: "Professional gaming mouse", image: "https://images.unsplash.com/photo-1527814050087-3793815479db?w=400&h=400&fit=crop&auto=format" },
        { name: "Bluetooth Speaker JBL", category: "Electronics", price: "8000", description: "Portable wireless speaker", image: "https://images.unsplash.com/photo-1545454675-3531b543be5d?w=400&h=400&fit=crop&auto=format" },
        { name: "Smart Watch Apple", category: "Electronics", price: "45000", description: "Fitness tracking smartwatch", image: "https://images.unsplash.com/photo-1551816230-ef5deaed4a26?w=400&h=400&fit=crop&auto=format" },
        { name: "USB-C Cable", category: "Electronics", price: "500", description: "Fast charging cable", image: "https://images.unsplash.com/photo-1572569511254-d8f925fe2cbb?w=400&h=400&fit=crop&auto=format" },
        { name: "Power Bank 20000mAh", category: "Electronics", price: "2500", description: "High capacity portable charger", image: "https://images.unsplash.com/photo-1609592439674-37c0e2df3c8b?w=400&h=400&fit=crop&auto=format" },
        { name: "Wireless Charger", category: "Electronics", price: "1800", description: "Qi wireless charging pad", image: "https://images.unsplash.com/photo-1585776245991-cf89dd7fc73a?w=400&h=400&fit=crop&auto=format" }
      ],
      
      // Fashion stores
      "Fashion Palace Lahan": [
        { name: "Men's Cotton T-Shirt", category: "Fashion", price: "800", description: "Comfortable casual wear", image: "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=400&h=400&fit=crop&auto=format" },
        { name: "Women's Kurta Set", category: "Fashion", price: "2500", description: "Traditional ethnic wear", image: "https://images.unsplash.com/photo-1583391733956-6c78276477e2?w=400&h=400&fit=crop&auto=format" },
        { name: "Denim Jeans", category: "Fashion", price: "2200", description: "Classic blue jeans", image: "https://images.unsplash.com/photo-1542272604-787c3835535d?w=400&h=400&fit=crop&auto=format" },
        { name: "Formal Shirt", category: "Fashion", price: "1500", description: "Office wear shirt", image: "https://images.unsplash.com/photo-1603252109303-2751441dd157?w=400&h=400&fit=crop&auto=format" },
        { name: "Winter Jacket", category: "Fashion", price: "4500", description: "Warm winter clothing", image: "https://images.unsplash.com/photo-1544966503-7cc5ac882d5f?w=400&h=400&fit=crop&auto=format" },
        { name: "Silk Saree", category: "Fashion", price: "5500", description: "Traditional silk saree", image: "https://images.unsplash.com/photo-1610030469983-98e550d6193c?w=400&h=400&fit=crop&auto=format" },
        { name: "Designer Lehenga", category: "Fashion", price: "8500", description: "Wedding wear lehenga", image: "https://images.unsplash.com/photo-1594633312681-425c7b97ccd1?w=400&h=400&fit=crop&auto=format" },
        { name: "Party Dress", category: "Fashion", price: "3200", description: "Elegant party wear", image: "https://images.unsplash.com/photo-1515372039744-b8f02a3ae446?w=400&h=400&fit=crop&auto=format" },
        { name: "Cotton Palazzo", category: "Fashion", price: "1200", description: "Comfortable palazzo pants", image: "https://images.unsplash.com/photo-1594633312681-425c7b97ccd1?w=400&h=400&fit=crop&auto=format" },
        { name: "Ethnic Dupatta", category: "Fashion", price: "800", description: "Traditional dupatta", image: "https://images.unsplash.com/photo-1583391733956-6c78276477e2?w=400&h=400&fit=crop&auto=format" }
      ],

      // Furniture stores
      "Siraha Furniture Mart": [
        { name: "Wooden Dining Table", category: "Home", price: "15000", description: "Solid wood dining table for 6 people", image: "https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=400&h=400&fit=crop&auto=format" },
        { name: "Leather Sofa Set", category: "Home", price: "45000", description: "3+2+1 leather sofa set", image: "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=400&h=400&fit=crop&auto=format" },
        { name: "Queen Size Bed", category: "Home", price: "25000", description: "Wooden queen size bed with storage", image: "https://images.unsplash.com/photo-1505693416388-ac5ce068fe85?w=400&h=400&fit=crop&auto=format" },
        { name: "Study Table", category: "Home", price: "8000", description: "Computer study table with drawers", image: "https://images.unsplash.com/photo-1611269154421-4e27233ac5c7?w=400&h=400&fit=crop&auto=format" },
        { name: "Wardrobe 3 Door", category: "Home", price: "35000", description: "Spacious 3-door wardrobe", image: "https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=400&h=400&fit=crop&auto=format" },
        { name: "Coffee Table", category: "Home", price: "5500", description: "Glass top coffee table", image: "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=400&h=400&fit=crop&auto=format" },
        { name: "Bookshelf", category: "Home", price: "12000", description: "5-tier wooden bookshelf", image: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=400&h=400&fit=crop&auto=format" },
        { name: "Office Chair", category: "Home", price: "6500", description: "Ergonomic office chair", image: "https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=400&h=400&fit=crop&auto=format" },
        { name: "TV Stand", category: "Home", price: "8500", description: "Modern TV entertainment unit", image: "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=400&h=400&fit=crop&auto=format" },
        { name: "Dining Chairs Set", category: "Home", price: "7200", description: "Set of 4 dining chairs", image: "https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=400&h=400&fit=crop&auto=format" }
      ],

      // Textile stores
      "Lahan Textile House": [
        { name: "Cotton Fabric", category: "Fashion", price: "180", description: "Premium cotton fabric per meter", image: "https://images.unsplash.com/photo-1558769132-cb1aea458c5e?w=400&h=400&fit=crop&auto=format" },
        { name: "Silk Fabric", category: "Fashion", price: "450", description: "Pure silk fabric per meter", image: "https://images.unsplash.com/photo-1567401893414-76b7b1e5a7a5?w=400&h=400&fit=crop&auto=format" },
        { name: "Linen Fabric", category: "Fashion", price: "320", description: "Natural linen fabric per meter", image: "https://images.unsplash.com/photo-1558769132-cb1aea458c5e?w=400&h=400&fit=crop&auto=format" },
        { name: "Wool Fabric", category: "Fashion", price: "380", description: "Warm wool fabric per meter", image: "https://images.unsplash.com/photo-1567401893414-76b7b1e5a7a5?w=400&h=400&fit=crop&auto=format" },
        { name: "Embroidered Cloth", category: "Fashion", price: "650", description: "Traditional embroidered fabric", image: "https://images.unsplash.com/photo-1558769132-cb1aea458c5e?w=400&h=400&fit=crop&auto=format" },
        { name: "Printed Cotton", category: "Fashion", price: "220", description: "Colorful printed cotton fabric", image: "https://images.unsplash.com/photo-1567401893414-76b7b1e5a7a5?w=400&h=400&fit=crop&auto=format" },
        { name: "Curtain Fabric", category: "Home", price: "280", description: "Heavy curtain fabric per meter", image: "https://images.unsplash.com/photo-1558769132-cb1aea458c5e?w=400&h=400&fit=crop&auto=format" },
        { name: "Bedsheet Fabric", category: "Home", price: "200", description: "Soft bedsheet fabric per meter", image: "https://images.unsplash.com/photo-1567401893414-76b7b1e5a7a5?w=400&h=400&fit=crop&auto=format" },
        { name: "Suit Fabric", category: "Fashion", price: "520", description: "Formal suit fabric per meter", image: "https://images.unsplash.com/photo-1558769132-cb1aea458c5e?w=400&h=400&fit=crop&auto=format" },
        { name: "Dupatta Fabric", category: "Fashion", price: "350", description: "Light dupatta fabric per meter", image: "https://images.unsplash.com/photo-1567401893414-76b7b1e5a7a5?w=400&h=400&fit=crop&auto=format" }
      ],

      // Grocery stores
      "Mirchaiya Grocery Store": [
        { name: "Basmati Rice", category: "Groceries", price: "120", description: "Premium basmati rice per kg", image: "https://images.unsplash.com/photo-1586201375761-83865001e31c?w=400&h=400&fit=crop&auto=format" },
        { name: "Mustard Oil", category: "Groceries", price: "180", description: "Pure mustard oil 1 liter", image: "https://images.unsplash.com/photo-1474979266404-7eaacbcd87c5?w=400&h=400&fit=crop&auto=format" },
        { name: "Lentils (Dal)", category: "Groceries", price: "85", description: "Mixed lentils per kg", image: "https://images.unsplash.com/photo-1599909392803-6c5b2b21cf6b?w=400&h=400&fit=crop&auto=format" },
        { name: "Red Onions", category: "Groceries", price: "45", description: "Fresh red onions per kg", image: "https://images.unsplash.com/photo-1518977676601-b53f82aba655?w=400&h=400&fit=crop&auto=format" },
        { name: "Tomatoes", category: "Groceries", price: "60", description: "Fresh tomatoes per kg", image: "https://images.unsplash.com/photo-1592924357228-91a4daadcfea?w=400&h=400&fit=crop&auto=format" },
        { name: "Potatoes", category: "Groceries", price: "35", description: "Fresh potatoes per kg", image: "https://images.unsplash.com/photo-1518977676601-b53f82aba655?w=400&h=400&fit=crop&auto=format" },
        { name: "Turmeric Powder", category: "Groceries", price: "150", description: "Pure turmeric powder 200g", image: "https://images.unsplash.com/photo-1599050751795-e8c83c8455f8?w=400&h=400&fit=crop&auto=format" },
        { name: "Cumin Seeds", category: "Groceries", price: "120", description: "Whole cumin seeds 100g", image: "https://images.unsplash.com/photo-1599050751795-e8c83c8455f8?w=400&h=400&fit=crop&auto=format" },
        { name: "Green Tea", category: "Groceries", price: "95", description: "Premium green tea leaves", image: "https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=400&h=400&fit=crop&auto=format" },
        { name: "Milk Powder", category: "Groceries", price: "280", description: "Full cream milk powder 500g", image: "https://images.unsplash.com/photo-1563636619-e9143da7973b?w=400&h=400&fit=crop&auto=format" }
      ]
    };

    // Default products for other store types
    const defaultProducts = {
      "book": [
        { name: "Nepali Literature Book", category: "Education", price: "450", description: "Classic Nepali literature collection", image: "https://images.unsplash.com/photo-1481627834876-b7833e8f5570?w=400&h=400&fit=crop&auto=format" },
        { name: "English Grammar Book", category: "Education", price: "380", description: "Complete English grammar guide", image: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=400&h=400&fit=crop&auto=format" },
        { name: "Mathematics Textbook", category: "Education", price: "520", description: "Higher secondary mathematics", image: "https://images.unsplash.com/photo-1481627834876-b7833e8f5570?w=400&h=400&fit=crop&auto=format" },
        { name: "Science Encyclopedia", category: "Education", price: "850", description: "Complete science reference book", image: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=400&h=400&fit=crop&auto=format" },
        { name: "History of Nepal", category: "Education", price: "420", description: "Comprehensive Nepal history book", image: "https://images.unsplash.com/photo-1481627834876-b7833e8f5570?w=400&h=400&fit=crop&auto=format" },
        { name: "Children's Story Book", category: "Education", price: "280", description: "Illustrated children's stories", image: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=400&h=400&fit=crop&auto=format" },
        { name: "Dictionary", category: "Education", price: "650", description: "English-Nepali dictionary", image: "https://images.unsplash.com/photo-1481627834876-b7833e8f5570?w=400&h=400&fit=crop&auto=format" },
        { name: "Computer Programming", category: "Education", price: "720", description: "Learn programming basics", image: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=400&h=400&fit=crop&auto=format" },
        { name: "Art & Craft Book", category: "Education", price: "350", description: "Creative art and craft guide", image: "https://images.unsplash.com/photo-1481627834876-b7833e8f5570?w=400&h=400&fit=crop&auto=format" },
        { name: "Poetry Collection", category: "Education", price: "320", description: "Modern Nepali poetry collection", image: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=400&h=400&fit=crop&auto=format" }
      ]
    };

    // Food items for restaurants
    const restaurantFoodItems = [
      { name: "Dal Bhat Tarkari", category: "Food & Beverages", price: "250", description: "Traditional Nepali meal with lentils, rice, and vegetables", image: "https://images.unsplash.com/photo-1585937421612-70a008356fbe?w=400&h=400&fit=crop&auto=format" },
      { name: "Chicken Momo", category: "Food & Beverages", price: "180", description: "Steamed dumplings with chicken filling", image: "https://images.unsplash.com/photo-1534422298391-e4f8c172dddb?w=400&h=400&fit=crop&auto=format" },
      { name: "Buff Sekuwa", category: "Food & Beverages", price: "320", description: "Grilled buffalo meat with spices", image: "https://images.unsplash.com/photo-1558030006-450675393462?w=400&h=400&fit=crop&auto=format" },
      { name: "Newari Khaja Set", category: "Food & Beverages", price: "400", description: "Traditional Newari snack platter", image: "https://images.unsplash.com/photo-1504113888839-1c8eb50233d3?w=400&h=400&fit=crop&auto=format" },
      { name: "Gundruk Soup", category: "Food & Beverages", price: "120", description: "Fermented leafy vegetable soup", image: "https://images.unsplash.com/photo-1547592180-85f173990554?w=400&h=400&fit=crop&auto=format" },
      { name: "Chicken Biryani", category: "Food & Beverages", price: "350", description: "Fragrant rice dish with spiced chicken", image: "https://images.unsplash.com/photo-1563379091339-03246963d96c?w=400&h=400&fit=crop&auto=format" },
      { name: "Mutton Curry", category: "Food & Beverages", price: "450", description: "Spicy goat meat curry", image: "https://images.unsplash.com/photo-1565299624946-b28f40a0ca4b?w=400&h=400&fit=crop&auto=format" },
      { name: "Vegetable Fried Rice", category: "Food & Beverages", price: "200", description: "Stir-fried rice with mixed vegetables", image: "https://images.unsplash.com/photo-1603133872878-684f208fb84b?w=400&h=400&fit=crop&auto=format" },
      { name: "Sel Roti", category: "Food & Beverages", price: "80", description: "Traditional ring-shaped rice bread", image: "https://images.unsplash.com/photo-1578985545062-69928b1d9587?w=400&h=400&fit=crop&auto=format" },
      { name: "Lassi", category: "Food & Beverages", price: "100", description: "Refreshing yogurt-based drink", image: "https://images.unsplash.com/photo-1570197788417-0e82375c9371?w=400&h=400&fit=crop&auto=format" }
    ];

    // Add products to each store based on store type
    this.stores.forEach(store => {
      if (store.storeType === 'retail') {
        let productList;
        
        // Get store-specific products or fall back to general categories
        if (storeProductCatalogs[store.name]) {
          productList = storeProductCatalogs[store.name];
        } else if (store.name.toLowerCase().includes('book')) {
          productList = defaultProducts.book;
        } else if (store.name.toLowerCase().includes('grocery') || store.name.toLowerCase().includes('general')) {
          // Use grocery items for grocery stores
          productList = [
            { name: "Rice", category: "Groceries", price: "100", description: "Premium rice per kg", image: "https://images.unsplash.com/photo-1586201375761-83865001e31c?w=400&h=400&fit=crop&auto=format" },
            { name: "Cooking Oil", category: "Groceries", price: "150", description: "Pure cooking oil 1 liter", image: "https://images.unsplash.com/photo-1474979266404-7eaacbcd87c5?w=400&h=400&fit=crop&auto=format" },
            { name: "Wheat Flour", category: "Groceries", price: "60", description: "Fresh wheat flour per kg", image: "https://images.unsplash.com/photo-1574323347407-f5e1ad6d020b?w=400&h=400&fit=crop&auto=format" },
            { name: "Sugar", category: "Groceries", price: "80", description: "Pure white sugar per kg", image: "https://images.unsplash.com/photo-1559181567-c3190ca9959b?w=400&h=400&fit=crop&auto=format" },
            { name: "Tea", category: "Groceries", price: "120", description: "Premium tea leaves", image: "https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=400&h=400&fit=crop&auto=format" },
            { name: "Salt", category: "Groceries", price: "25", description: "Refined table salt per kg", image: "https://images.unsplash.com/photo-1518977676601-b53f82aba655?w=400&h=400&fit=crop&auto=format" },
            { name: "Spices Mix", category: "Groceries", price: "90", description: "Traditional spice mixture", image: "https://images.unsplash.com/photo-1599050751795-e8c83c8455f8?w=400&h=400&fit=crop&auto=format" },
            { name: "Biscuits", category: "Groceries", price: "45", description: "Assorted biscuits pack", image: "https://images.unsplash.com/photo-1558961363-fa8fdf82db35?w=400&h=400&fit=crop&auto=format" },
            { name: "Soap", category: "Groceries", price: "35", description: "Bath soap bar", image: "https://images.unsplash.com/photo-1585435557343-3b092031a831?w=400&h=400&fit=crop&auto=format" },
            { name: "Toothpaste", category: "Groceries", price: "85", description: "Herbal toothpaste", image: "https://images.unsplash.com/photo-1571781926291-c477ebfd024b?w=400&h=400&fit=crop&auto=format" }
          ];
        } else if (store.name.toLowerCase().includes('electronic') || store.name.toLowerCase().includes('mobile')) {
          // Use electronics for electronic stores
          productList = [
            { name: "Mobile Phone", category: "Electronics", price: "25000", description: "Latest smartphone model", image: "https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=400&h=400&fit=crop&auto=format" },
            { name: "Bluetooth Headset", category: "Electronics", price: "3500", description: "Wireless bluetooth headset", image: "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=400&h=400&fit=crop&auto=format" },
            { name: "Power Adapter", category: "Electronics", price: "1500", description: "Universal power adapter", image: "https://images.unsplash.com/photo-1572569511254-d8f925fe2cbb?w=400&h=400&fit=crop&auto=format" },
            { name: "Memory Card", category: "Electronics", price: "800", description: "High-speed memory card", image: "https://images.unsplash.com/photo-1609592439674-37c0e2df3c8b?w=400&h=400&fit=crop&auto=format" },
            { name: "Phone Case", category: "Electronics", price: "650", description: "Protective phone case", image: "https://images.unsplash.com/photo-1585776245991-cf89dd7fc73a?w=400&h=400&fit=crop&auto=format" },
            { name: "USB Cable", category: "Electronics", price: "250", description: "Fast charging USB cable", image: "https://images.unsplash.com/photo-1572569511254-d8f925fe2cbb?w=400&h=400&fit=crop&auto=format" },
            { name: "Earphones", category: "Electronics", price: "1200", description: "Wired earphones", image: "https://images.unsplash.com/photo-1590658268037-6bf12165a8df?w=400&h=400&fit=crop&auto=format" },
            { name: "Power Bank", category: "Electronics", price: "2500", description: "Portable power bank", image: "https://images.unsplash.com/photo-1609592439674-37c0e2df3c8b?w=400&h=400&fit=crop&auto=format" },
            { name: "Screen Guard", category: "Electronics", price: "350", description: "Mobile screen protector", image: "https://images.unsplash.com/photo-1585776245991-cf89dd7fc73a?w=400&h=400&fit=crop&auto=format" },
            { name: "Bluetooth Speaker", category: "Electronics", price: "4500", description: "Portable bluetooth speaker", image: "https://images.unsplash.com/photo-1545454675-3531b543be5d?w=400&h=400&fit=crop&auto=format" }
          ];
        } else if (store.name.toLowerCase().includes('pharmacy') || store.name.toLowerCase().includes('medical')) {
          // Use pharmacy items for pharmacy stores
          productList = [
            { name: "Paracetamol", category: "Health", price: "45", description: "Pain relief tablets", image: "https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?w=400&h=400&fit=crop&auto=format" },
            { name: "Vitamin D3", category: "Health", price: "180", description: "Vitamin D3 supplements", image: "https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=400&h=400&fit=crop&auto=format" },
            { name: "Cough Syrup", category: "Health", price: "95", description: "Herbal cough syrup", image: "https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?w=400&h=400&fit=crop&auto=format" },
            { name: "Antiseptic Liquid", category: "Health", price: "85", description: "Wound cleaning antiseptic", image: "https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=400&h=400&fit=crop&auto=format" },
            { name: "Thermometer", category: "Health", price: "450", description: "Digital thermometer", image: "https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?w=400&h=400&fit=crop&auto=format" },
            { name: "Band-Aid", category: "Health", price: "35", description: "Adhesive bandages pack", image: "https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=400&h=400&fit=crop&auto=format" },
            { name: "Face Mask", category: "Health", price: "25", description: "Surgical face masks", image: "https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?w=400&h=400&fit=crop&auto=format" },
            { name: "Hand Sanitizer", category: "Health", price: "65", description: "Alcohol-based sanitizer", image: "https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=400&h=400&fit=crop&auto=format" },
            { name: "Calcium Tablets", category: "Health", price: "120", description: "Calcium supplement tablets", image: "https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?w=400&h=400&fit=crop&auto=format" },
            { name: "Multivitamin", category: "Health", price: "250", description: "Daily multivitamin capsules", image: "https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=400&h=400&fit=crop&auto=format" }
          ];
        } else if (store.name.toLowerCase().includes('sports') || store.name.toLowerCase().includes('fitness')) {
          // Use sports items for sports stores
          productList = [
            { name: "Cricket Bat", category: "Sports", price: "2500", description: "Professional cricket bat", image: "https://images.unsplash.com/photo-1540747913346-19e32dc3e97e?w=400&h=400&fit=crop&auto=format" },
            { name: "Football", category: "Sports", price: "850", description: "Official size football", image: "https://images.unsplash.com/photo-1551698618-1dfe5d97d256?w=400&h=400&fit=crop&auto=format" },
            { name: "Tennis Racket", category: "Sports", price: "3200", description: "Professional tennis racket", image: "https://images.unsplash.com/photo-1551698618-1dfe5d97d256?w=400&h=400&fit=crop&auto=format" },
            { name: "Running Shoes", category: "Sports", price: "4500", description: "Sports running shoes", image: "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=400&h=400&fit=crop&auto=format" },
            { name: "Gym Weights", category: "Sports", price: "1200", description: "Adjustable dumbbells", image: "https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=400&h=400&fit=crop&auto=format" },
            { name: "Yoga Mat", category: "Sports", price: "650", description: "Non-slip yoga mat", image: "https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=400&h=400&fit=crop&auto=format" },
            { name: "Sports T-Shirt", category: "Sports", price: "850", description: "Breathable sports t-shirt", image: "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=400&h=400&fit=crop&auto=format" },
            { name: "Water Bottle", category: "Sports", price: "350", description: "Sports water bottle", image: "https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=400&h=400&fit=crop&auto=format" },
            { name: "Badminton Racket", category: "Sports", price: "1800", description: "Lightweight badminton racket", image: "https://images.unsplash.com/photo-1551698618-1dfe5d97d256?w=400&h=400&fit=crop&auto=format" },
            { name: "Sports Bag", category: "Sports", price: "1500", description: "Durable sports gym bag", image: "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=400&h=400&fit=crop&auto=format" }
          ];
        } else if (store.name.toLowerCase().includes('furniture') || store.name.toLowerCase().includes('home')) {
          // Use furniture items for furniture stores  
          productList = [
            { name: "Sofa Set", category: "Home", price: "15000", description: "3-seater sofa set", image: "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=400&h=400&fit=crop&auto=format" },
            { name: "Dining Table", category: "Home", price: "8500", description: "6-seater dining table", image: "https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=400&h=400&fit=crop&auto=format" },
            { name: "Bed Frame", category: "Home", price: "12000", description: "Queen size bed frame", image: "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=400&h=400&fit=crop&auto=format" },
            { name: "Wardrobe", category: "Home", price: "18000", description: "3-door wooden wardrobe", image: "https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=400&h=400&fit=crop&auto=format" },
            { name: "Study Table", category: "Home", price: "4500", description: "Computer study table", image: "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=400&h=400&fit=crop&auto=format" },
            { name: "Bookshelf", category: "Home", price: "6500", description: "5-tier wooden bookshelf", image: "https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=400&h=400&fit=crop&auto=format" },
            { name: "Office Chair", category: "Home", price: "3500", description: "Ergonomic office chair", image: "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=400&h=400&fit=crop&auto=format" },
            { name: "Side Table", category: "Home", price: "2200", description: "Wooden side table", image: "https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=400&h=400&fit=crop&auto=format" },
            { name: "Mirror", category: "Home", price: "1800", description: "Large wall mirror", image: "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=400&h=400&fit=crop&auto=format" },
            { name: "TV Stand", category: "Home", price: "5500", description: "Modern TV entertainment unit", image: "https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=400&h=400&fit=crop&auto=format" }
          ];
        } else {
          // For other stores, use general mix
          productList = [
            { name: "Digital Watch", category: "Fashion", price: "4500", description: "Smart digital watch", image: "https://images.unsplash.com/photo-1524592094714-0f0654e20314?w=400&h=400&fit=crop&auto=format" },
            { name: "Casual Shirt", category: "Fashion", price: "1200", description: "Comfortable casual shirt", image: "https://images.unsplash.com/photo-1603252109303-2751441dd157?w=400&h=400&fit=crop&auto=format" },
            { name: "Sports Cap", category: "Fashion", price: "800", description: "Stylish sports cap", image: "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=400&h=400&fit=crop&auto=format" },
            { name: "Sunglasses", category: "Fashion", price: "2200", description: "UV protection sunglasses", image: "https://images.unsplash.com/photo-1572635196237-14b3f281503f?w=400&h=400&fit=crop&auto=format" },
            { name: "Keychain", category: "Fashion", price: "150", description: "Decorative keychain", image: "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=400&h=400&fit=crop&auto=format" },
            { name: "Wallet", category: "Fashion", price: "850", description: "Leather wallet", image: "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=400&h=400&fit=crop&auto=format" },
            { name: "Belt", category: "Fashion", price: "650", description: "Leather belt", image: "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=400&h=400&fit=crop&auto=format" },
            { name: "Backpack", category: "Fashion", price: "1500", description: "Travel backpack", image: "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=400&h=400&fit=crop&auto=format" },
            { name: "Notebook", category: "Education", price: "120", description: "Spiral notebook", image: "https://images.unsplash.com/photo-1481627834876-b7833e8f5570?w=400&h=400&fit=crop&auto=format" },
            { name: "Pen Set", category: "Education", price: "180", description: "Ball pen set", image: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=400&h=400&fit=crop&auto=format" }
          ];
        }
        
        // Add 10 products to each retail store
        for (let i = 0; i < 10; i++) {
          const productTemplate = productList[i % productList.length];
          this.products.push({
            id: this.nextId++,
            name: productTemplate.name,
            slug: `${productTemplate.name.toLowerCase().replace(/\s+/g, '-')}-${store.id}`,
            description: productTemplate.description,
            price: productTemplate.price,
            originalPrice: (parseInt(productTemplate.price) * 1.2).toString(),
            categoryId: this.categories.find(c => c.name === productTemplate.category)?.id || 1,
            storeId: store.id,
            stock: Math.floor(Math.random() * 50) + 10,
            imageUrl: productTemplate.image,
            images: [productTemplate.image],
            rating: (Math.random() * 2 + 3).toFixed(1),
            totalReviews: Math.floor(Math.random() * 100) + 5,
            isActive: true,
            isFastSell: Math.random() > 0.8,
            isOnOffer: Math.random() > 0.7,
            offerPercentage: Math.random() > 0.7 ? Math.floor(Math.random() * 30) + 5 : 0,
            offerEndDate: Math.random() > 0.7 ? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() : null,
            productType: "retail",
            preparationTime: null,
            ingredients: [],
            allergens: [],
            spiceLevel: null,
            isVegetarian: Math.random() > 0.5,
            isVegan: Math.random() > 0.7,
            nutritionInfo: null,
            createdAt: new Date()
          });
        }
      } else if (store.storeType === 'restaurant') {
        // Add 10 food items to each restaurant
        for (let i = 0; i < 10; i++) {
          const foodTemplate = restaurantFoodItems[i % restaurantFoodItems.length];
          const spiceLevels = ['mild', 'medium', 'hot'];
          this.products.push({
            id: this.nextId++,
            name: foodTemplate.name,
            slug: `${foodTemplate.name.toLowerCase().replace(/\s+/g, '-')}-${store.id}`,
            description: foodTemplate.description,
            price: foodTemplate.price,
            originalPrice: (parseInt(foodTemplate.price) * 1.15).toString(),
            categoryId: this.categories.find(c => c.name === 'Food & Beverages')?.id || 3,
            storeId: store.id,
            stock: 999,
            imageUrl: foodTemplate.image,
            images: [foodTemplate.image],
            rating: (Math.random() * 2 + 3).toFixed(1),
            totalReviews: Math.floor(Math.random() * 150) + 10,
            isActive: true,
            isFastSell: Math.random() > 0.6,
            isOnOffer: Math.random() > 0.8,
            offerPercentage: Math.random() > 0.8 ? Math.floor(Math.random() * 25) + 5 : 0,
            offerEndDate: Math.random() > 0.8 ? new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toISOString() : null,
            productType: "food",
            preparationTime: `${Math.floor(Math.random() * 20) + 10}-${Math.floor(Math.random() * 10) + 25} mins`,
            ingredients: foodTemplate.name.includes('Chicken') ? ['chicken', 'spices', 'onion'] : 
                        foodTemplate.name.includes('Vegetable') ? ['mixed vegetables', 'rice', 'spices'] :
                        ['traditional ingredients', 'spices'],
            allergens: foodTemplate.name.includes('dairy') ? ['dairy'] : [],
            spiceLevel: spiceLevels[Math.floor(Math.random() * spiceLevels.length)],
            isVegetarian: !foodTemplate.name.toLowerCase().includes('chicken') && !foodTemplate.name.toLowerCase().includes('mutton') && !foodTemplate.name.toLowerCase().includes('buff'),
            isVegan: foodTemplate.name.includes('Dal') || foodTemplate.name.includes('Vegetable'),
            nutritionInfo: `{"calories": ${Math.floor(Math.random() * 300) + 200}, "protein": "${Math.floor(Math.random() * 20) + 5}g"}`,
            createdAt: new Date()
          });
        }
      }
    });

    console.log(`✅ Created ${this.products.length} products across all stores`);
  }

  async getUser(id: number): Promise<User | undefined> {
    return this.users.find(u => u.id === id);
  }

  async getAllUsers(): Promise<User[]> {
    return this.users;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    return this.users.find(u => u.email === email);
  }

  async getUserByPhone(phone: string): Promise<User | undefined> {
    return this.users.find(u => u.phone === phone);
  }

  async createUser(user: InsertUser): Promise<User> {
    const newUser: User = {
      id: this.nextId++,
      username: user.username || null,
      email: user.email,
      password: user.password || null,
      firebaseUid: user.firebaseUid || null,
      fullName: user.fullName,
      phone: user.phone || null,
      address: user.address || null,
      city: user.city || null,
      state: user.state || null,
      role: user.role,
      status: user.status || "active",
      approvalDate: user.approvalDate || null,
      approvedBy: user.approvedBy || null,
      rejectionReason: user.rejectionReason || null,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    this.users.push(newUser);
    return newUser;
  }

  async updateUser(id: number, updates: Partial<InsertUser>): Promise<User | undefined> {
    const userIndex = this.users.findIndex(u => u.id === id);
    if (userIndex === -1) return undefined;
    
    this.users[userIndex] = { ...this.users[userIndex], ...updates, updatedAt: new Date() };
    return this.users[userIndex];
  }

  async deleteUserAccount(userId: number): Promise<void> {
    const userIndex = this.users.findIndex(u => u.id === userId);
    if (userIndex !== -1) {
      this.users.splice(userIndex, 1);
    }
  }

  // Store operations
  async getStore(id: number): Promise<Store | undefined> {
    return this.stores.find(s => s.id === id);
  }

  async getStoresByOwnerId(ownerId: number): Promise<Store[]> {
    return this.stores.filter(s => s.ownerId === ownerId);
  }

  async getAllStores(): Promise<Store[]> {
    return this.stores;
  }

  async createStore(store: InsertStore): Promise<Store> {
    const newStore: Store = {
      id: this.nextId++,
      name: store.name,
      slug: store.slug,
      description: store.description || null,
      ownerId: store.ownerId,
      address: store.address,
      city: store.city || null,
      state: store.state || null,
      postalCode: store.postalCode || null,
      country: store.country || null,
      latitude: store.latitude || null,
      longitude: store.longitude || null,
      phone: store.phone || null,
      website: store.website || null,
      logo: store.logo || null,
      coverImage: store.coverImage || null,
      rating: store.rating || "0.00",
      totalReviews: store.totalReviews || 0,
      featured: store.featured || false,
      isActive: store.isActive ?? true,
      storeType: store.storeType,
      cuisineType: store.cuisineType || null,
      deliveryTime: store.deliveryTime || null,
      minimumOrder: store.minimumOrder || null,
      deliveryFee: store.deliveryFee || null,
      isDeliveryAvailable: store.isDeliveryAvailable || false,
      openingHours: store.openingHours || null,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    this.stores.push(newStore);
    return newStore;
  }

  async updateStore(id: number, updates: Partial<InsertStore>): Promise<Store | undefined> {
    const storeIndex = this.stores.findIndex(s => s.id === id);
    if (storeIndex === -1) return undefined;
    
    this.stores[storeIndex] = { ...this.stores[storeIndex], ...updates, updatedAt: new Date() };
    return this.stores[storeIndex];
  }

  // Category operations
  async getAllCategories(): Promise<Category[]> {
    return this.categories;
  }

  async getCategory(id: number): Promise<Category | undefined> {
    return this.categories.find(c => c.id === id);
  }

  async createCategory(category: InsertCategory): Promise<Category> {
    const newCategory: Category = {
      id: this.nextId++,
      name: category.name,
      slug: category.slug,
      description: category.description || null,
      icon: category.icon,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    this.categories.push(newCategory);
    return newCategory;
  }

  async updateCategory(id: number, updates: Partial<InsertCategory>): Promise<Category | undefined> {
    const categoryIndex = this.categories.findIndex(c => c.id === id);
    if (categoryIndex === -1) return undefined;
    
    this.categories[categoryIndex] = { ...this.categories[categoryIndex], ...updates, updatedAt: new Date() };
    return this.categories[categoryIndex];
  }

  async deleteCategory(id: number): Promise<boolean> {
    const categoryIndex = this.categories.findIndex(c => c.id === id);
    if (categoryIndex === -1) return false;
    
    this.categories.splice(categoryIndex, 1);
    return true;
  }

  // Product operations
  async getProduct(id: number): Promise<Product | undefined> {
    return this.products.find(p => p.id === id);
  }

  async getProductsByStoreId(storeId: number): Promise<Product[]> {
    return this.products.filter(p => p.storeId === storeId);
  }

  async getAllProducts(): Promise<Product[]> {
    return this.products;
  }

  async createProduct(product: InsertProduct): Promise<Product> {
    const newProduct: Product = {
      id: this.nextId++,
      name: product.name,
      slug: product.slug,
      description: product.description || null,
      price: product.price,
      originalPrice: product.originalPrice || null,
      categoryId: product.categoryId || null,
      storeId: product.storeId,
      stock: product.stock || 0,
      imageUrl: product.imageUrl,
      images: product.images || [],
      rating: product.rating || "0.00",
      totalReviews: product.totalReviews || 0,
      isActive: product.isActive ?? true,
      isFastSell: product.isFastSell || false,
      isOnOffer: product.isOnOffer || false,
      offerPercentage: product.offerPercentage || 0,
      offerEndDate: product.offerEndDate || null,
      productType: product.productType,
      preparationTime: product.preparationTime || null,
      ingredients: product.ingredients || [],
      allergens: product.allergens || [],
      spiceLevel: product.spiceLevel || null,
      isVegetarian: product.isVegetarian || false,
      isVegan: product.isVegan || false,
      nutritionInfo: product.nutritionInfo || null,
      createdAt: new Date()
    };
    this.products.push(newProduct);
    return newProduct;
  }

  async updateProduct(id: number, updates: Partial<InsertProduct>): Promise<Product | undefined> {
    const productIndex = this.products.findIndex(p => p.id === id);
    if (productIndex === -1) return undefined;
    
    this.products[productIndex] = { ...this.products[productIndex], ...updates };
    return this.products[productIndex];
  }

  async deleteProduct(id: number): Promise<boolean> {
    const productIndex = this.products.findIndex(p => p.id === id);
    if (productIndex === -1) return false;
    
    this.products.splice(productIndex, 1);
    return true;
  }

  // User approval operations
  async getPendingUsers(): Promise<User[]> { 
    return this.users.filter(user => user.status === 'pending');
  }
  
  async approveUser(userId: number, adminId: number): Promise<User | undefined> {
    const userIndex = this.users.findIndex(user => user.id === userId);
    if (userIndex === -1) return undefined;
    
    this.users[userIndex] = {
      ...this.users[userIndex],
      status: 'active',
      approvalDate: new Date(),
      approvedBy: adminId,
      updatedAt: new Date()
    };
    
    return this.users[userIndex];
  }
  
  async rejectUser(userId: number, adminId: number): Promise<User | undefined> {
    const userIndex = this.users.findIndex(user => user.id === userId);
    if (userIndex === -1) return undefined;
    
    this.users[userIndex] = {
      ...this.users[userIndex],
      status: 'rejected',
      approvalDate: new Date(),
      approvedBy: adminId,
      updatedAt: new Date()
    };
    
    return this.users[userIndex];
  }
  async getAllUsersWithStatus(): Promise<User[]> { return this.users; }
  async getAdminUser(): Promise<any> { return undefined; }
  async getAdminUserByEmail(): Promise<any> { return undefined; }
  async createAdminUser(): Promise<any> { return undefined; }
  async getAdminUsers(): Promise<any[]> { return []; }
  async storePasswordResetToken(): Promise<void> {}
  async getPasswordResetToken(): Promise<any> { return undefined; }
  async deletePasswordResetToken(): Promise<boolean> { return false; }
  async updateUserPassword(): Promise<void> {}
  async getOrder(): Promise<any> { return undefined; }
  async getOrdersByCustomerId(): Promise<any[]> { return []; }
  async getOrdersByStoreId(): Promise<any[]> { return []; }
  async getAllOrders(): Promise<any[]> { return []; }
  async createOrder(): Promise<any> { return undefined; }
  async updateOrder(): Promise<any> { return undefined; }
  async getOrderItems(): Promise<any[]> { return []; }
  async createOrderItem(): Promise<any> { return undefined; }
  async getCartItems(userId: number): Promise<CartItem[]> { 
    return this.cartItems.filter(item => item.userId === userId);
  }
  
  async addToCart(cartItem: InsertCartItem): Promise<CartItem> {
    // Check if item already exists in cart
    const existingItemIndex = this.cartItems.findIndex(
      item => item.userId === cartItem.userId && item.productId === cartItem.productId
    );

    if (existingItemIndex !== -1) {
      // Update quantity of existing item
      this.cartItems[existingItemIndex].quantity += cartItem.quantity;
      return this.cartItems[existingItemIndex];
    } else {
      // Add new item to cart
      const newCartItem: CartItem = {
        id: this.nextId++,
        userId: cartItem.userId,
        productId: cartItem.productId,
        quantity: cartItem.quantity,
        createdAt: new Date()
      };
      this.cartItems.push(newCartItem);
      return newCartItem;
    }
  }
  
  async updateCartItem(id: number, quantity: number): Promise<CartItem | undefined> {
    const itemIndex = this.cartItems.findIndex(item => item.id === id);
    if (itemIndex === -1) return undefined;
    
    this.cartItems[itemIndex].quantity = quantity;
    return this.cartItems[itemIndex];
  }
  
  async removeFromCart(id: number): Promise<boolean> {
    const itemIndex = this.cartItems.findIndex(item => item.id === id);
    if (itemIndex === -1) return false;
    
    this.cartItems.splice(itemIndex, 1);
    return true;
  }
  
  async clearCart(userId: number): Promise<void> {
    this.cartItems = this.cartItems.filter(item => item.userId !== userId);
  }
  async getWishlistItems(): Promise<any[]> { return []; }
  async addToWishlist(): Promise<any> { return undefined; }
  async removeFromWishlist(): Promise<boolean> { return false; }
  async isInWishlist(): Promise<boolean> { return false; }

  // Admin methods
  private adminUsers: any[] = [
    {
      id: 1,
      email: 'admin@sirahbazaar.com',
      password: 'admin123',
      fullName: 'System Administrator',
      role: 'super_admin',
      isActive: true,
      createdAt: new Date()
    }
  ];

  async authenticateAdmin(email: string, password: string): Promise<any | null> {
    const admin = this.adminUsers.find(a => a.email === email && a.password === password && a.isActive);
    return admin || null;
  }

  async createDefaultAdmin(): Promise<any | null> {
    const existing = this.adminUsers.find(a => a.email === 'admin@sirahbazaar.com');
    if (existing) {
      console.log('✅ Default admin account already exists');
      return existing;
    }
    
    const admin = {
      id: this.nextId++,
      email: 'admin@sirahbazaar.com',
      password: 'admin123',
      fullName: 'System Administrator',
      role: 'super_admin',
      isActive: true,
      createdAt: new Date()
    };
    
    this.adminUsers.push(admin);
    console.log('✅ Default admin account created: admin@sirahbazaar.com / admin123');
    return admin;
  }

  // Additional stub methods for missing interface methods
  async getAdmin(): Promise<any> { return undefined; }
  async getAdminByEmail(): Promise<any> { return undefined; }
  async createAdmin(): Promise<any> { return undefined; }
  async recordVisit(): Promise<any> { return undefined; }
  async getVisitStats(): Promise<any> { return {}; }
  async getPageViews(): Promise<any[]> { return []; }
  async createNotification(): Promise<any> { return undefined; }
  async getUserNotifications(): Promise<any[]> { return []; }
  async getNotificationsByUserId(): Promise<any[]> { return []; }
  async getNotificationsByType(): Promise<any[]> { return []; }
  async markNotificationAsRead(): Promise<any> { return undefined; }
  async markAllNotificationsAsRead(): Promise<boolean> { return false; }
  async createOrderTracking(): Promise<any> { return undefined; }
  async getOrderTracking(): Promise<any[]> { return []; }
  async updateOrderTracking(): Promise<any> { return undefined; }
  async createReturnPolicy(): Promise<any> { return undefined; }
  async getReturnPolicy(): Promise<any> { return undefined; }
  async updateReturnPolicy(): Promise<any> { return undefined; }
  async createReturn(): Promise<any> { return undefined; }
  async getReturn(): Promise<any> { return undefined; }
  async getReturnsByCustomer(): Promise<any[]> { return []; }
  async getReturnsByStore(): Promise<any[]> { return []; }
  async updateReturnStatus(): Promise<any> { return undefined; }
  async calculateDistance(): number { return 0; }
  async getStoresWithDistance(): Promise<any[]> { return []; }
  async getSellerAnalytics(): Promise<any> { return {}; }
  async getProductReviewsByProductId(): Promise<any[]> { return []; }
  async getProductReviews(productId: number): Promise<any[]> { return []; }
  async createProductReview(): Promise<any> { return undefined; }
  async updateProductReview(): Promise<any> { return undefined; }
  async deleteProductReview(): Promise<boolean> { return false; }
  async updateProductRating(): Promise<void> {}
  async getReviewLikes(): Promise<any[]> { return []; }
  async createReviewLike(): Promise<any> { return undefined; }
  async deleteReviewLike(): Promise<boolean> { return false; }
  async hasUserLikedReview(): Promise<boolean> { return false; }
  async getStoreReviewsByStoreId(): Promise<any[]> { return []; }
  async createStoreReview(): Promise<any> { return undefined; }
  async updateStoreReview(): Promise<any> { return undefined; }
  async deleteStoreReview(): Promise<boolean> { return false; }
  async updateStoreRating(): Promise<void> {}
  async getStoreReviewLikes(): Promise<any[]> { return []; }
  async createStoreReviewLike(): Promise<any> { return undefined; }
  async deleteStoreReviewLike(): Promise<boolean> { return false; }
  async hasUserLikedStoreReview(): Promise<boolean> { return false; }
  async getStoreSettlements(): Promise<any[]> { return []; }
  async createSettlement(): Promise<any> { return undefined; }
  async updateSettlement(): Promise<any> { return undefined; }
  async getInventoryLogs(): Promise<any[]> { return []; }
  async createInventoryLog(): Promise<any> { return undefined; }
  async updateProductStock(): Promise<boolean> { return false; }
  async getAllFlashSales(): Promise<any[]> { return []; }
  async getActiveFlashSales(): Promise<any[]> { return []; }
  async getFlashSale(): Promise<any> { return undefined; }
  async createFlashSale(): Promise<any> { return undefined; }
  async updateFlashSale(): Promise<any> { return undefined; }
  async deleteFlashSale(): Promise<boolean> { return false; }
  async getFlashSaleProducts(): Promise<any[]> { return []; }
  async getAllTransactions(): Promise<any[]> { return []; }
  async getAllCoupons(): Promise<any[]> { return []; }
  async createCoupon(): Promise<any> { return undefined; }
  async updateCoupon(): Promise<any> { return undefined; }
  async deleteCoupon(): Promise<boolean> { return false; }
  async getAllBanners(): Promise<any[]> { return []; }
  async createBanner(): Promise<any> { return undefined; }
  async updateBanner(): Promise<any> { return undefined; }
  async deleteBanner(): Promise<boolean> { return false; }
  async getAllSupportTickets(): Promise<any[]> { return []; }
  async createSupportTicket(): Promise<any> { return undefined; }
  async updateSupportTicket(): Promise<any> { return undefined; }
  async getAllSiteSettings(): Promise<any[]> { return []; }
  async updateSiteSetting(): Promise<any> { return undefined; }
  async getDashboardStats(): Promise<any> { return {}; }
  async getAllVendorVerifications(): Promise<any[]> { return []; }
  async updateVendorVerification(): Promise<any> { return undefined; }
  async approveVendorVerification(): Promise<any> { return undefined; }
  async rejectVendorVerification(): Promise<any> { return undefined; }
  async getAllFraudAlerts(): Promise<any[]> { return []; }
  async createFraudAlert(): Promise<any> { return undefined; }
  async updateFraudAlert(): Promise<any> { return undefined; }
  async updateFraudAlertStatus(): Promise<any> { return undefined; }
  async getAllCommissions(): Promise<any[]> { return []; }
  async createCommission(): Promise<any> { return undefined; }
  async updateCommission(): Promise<any> { return undefined; }
  async getCommissions(): Promise<any[]> { return []; }
  async updateCommissionStatus(): Promise<any> { return undefined; }
  async getTotalUsersCount(): Promise<number> { return this.users.length; }
  async getTotalStoresCount(): Promise<number> { return this.stores.length; }
  async getTotalOrdersCount(): Promise<number> { return this.orders.length; }
  async getTotalRevenue(): Promise<number> { return 0; }
  async getPendingOrdersCount(): Promise<number> { return 0; }
  async getActiveUsersCount(): Promise<number> { return this.users.length; }
  async getPendingVendorVerificationsCount(): Promise<number> { return 0; }
  async getOpenFraudAlertsCount(): Promise<number> { return 0; }
  async getProductAttributes(): Promise<any[]> { return []; }
  async createProductAttribute(): Promise<any> { return undefined; }
  async deleteProductAttribute(): Promise<boolean> { return false; }
  async logAdminAction(): Promise<any> { return undefined; }
  async getAdminLogs(): Promise<any[]> { return []; }
  async bulkUpdateProductStatus(): Promise<boolean> { return false; }
  async getOrdersWithDetails(): Promise<any[]> { return []; }
  async getRevenueAnalytics(): Promise<any> { return {}; }
  async getUsersAnalytics(): Promise<any> { return {}; }
  async getInventoryAlerts(): Promise<any[]> { return []; }
  async getDeliveryPartner(): Promise<any> { return undefined; }
  async getDeliveryPartnerByUserId(): Promise<any> { return undefined; }
  async getAllDeliveryPartners(): Promise<any[]> { return []; }
  async getPendingDeliveryPartners(): Promise<any[]> { return []; }
  async createDeliveryPartner(): Promise<any> { return undefined; }
  async updateDeliveryPartner(): Promise<any> { return undefined; }
  async approveDeliveryPartner(): Promise<any> { return undefined; }
  async rejectDeliveryPartner(): Promise<any> { return undefined; }
  async getDelivery(): Promise<any> { return undefined; }
  async getDeliveriesByPartnerId(): Promise<any[]> { return []; }
  async getDeliveriesByOrderId(): Promise<any[]> { return []; }
  async getPendingDeliveries(): Promise<any[]> { return []; }
  async getActiveDeliveries(): Promise<any[]> { return []; }
  async createDelivery(): Promise<any> { return undefined; }
  async updateDeliveryStatus(): Promise<any> { return undefined; }
  async assignDeliveryToPartner(): Promise<any> { return undefined; }
  async getActiveDeliveriesForStore(): Promise<any[]> { return []; }
  async getDeliveryTrackingData(): Promise<any> { return {}; }
  async updateDeliveryLocation(): Promise<void> {}
  async createDeliveryZone(): Promise<any> { return undefined; }
  async getDeliveryZones(): Promise<any[]> { return []; }
  async getAllDeliveryZones(): Promise<any[]> { return []; }
  async updateDeliveryZone(): Promise<any> { return undefined; }
  async deleteDeliveryZone(): Promise<void> {}
  async calculateDeliveryFee(): Promise<any> { return { fee: 0, zone: null }; }
  async saveDeviceToken(): Promise<boolean> { return false; }
  async removeDeviceToken(): Promise<boolean> { return false; }
  async getDeviceTokensByUserId(): Promise<string[]> { return []; }
  async getDeviceTokensByUserIds(): Promise<string[]> { return []; }
  async getDeviceTokensByRole(): Promise<string[]> { return []; }
  async getDeviceTokensByUser(): Promise<any[]> { return []; }
  async createDeviceToken(): Promise<any> { return undefined; }
  async getAdminProfile(): Promise<any> { return undefined; }
  async updateAdminProfile(): Promise<any> { return undefined; }
  async verifyAdminPassword(): Promise<boolean> { return false; }
  async changeAdminPassword(): Promise<boolean> { return false; }
  async updateOrderStatus(): Promise<any> { return undefined; }
  async searchProducts(): Promise<Product[]> { return this.products; }
  async getProductsByCategory(): Promise<Product[]> { return this.products; }
}