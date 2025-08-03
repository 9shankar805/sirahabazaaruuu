import { 
  users, adminUsers, stores, categories, products, orders, orderItems, cartItems, wishlistItems,
  admins, websiteVisits, notifications, orderTracking, returnPolicies, returns,
  promotions, advertisements, productReviews, reviewLikes, storeReviews, storeReviewLikes, settlements, storeAnalytics, inventoryLogs,
  paymentTransactions, coupons, banners, supportTickets, siteSettings, deliveryPartners, deliveries,
  vendorVerifications, fraudAlerts, commissions, productAttributes, adminLogs, deliveryZones, flashSales,
  pushNotificationTokens, passwordResetTokens, deliveryLocationTracking,
  type User, type InsertUser, type AdminUser, type InsertAdminUser, type Store, type InsertStore, 
  type Category, type InsertCategory, type Product, type InsertProduct,
  type Order, type InsertOrder, type OrderItem, type InsertOrderItem,
  type CartItem, type InsertCartItem, type WishlistItem, type InsertWishlistItem,
  type Admin, type InsertAdmin, type WebsiteVisit, type InsertWebsiteVisit,
  type Notification, type InsertNotification, type OrderTracking, type InsertOrderTracking,
  type ReturnPolicy, type InsertReturnPolicy, type Return, type InsertReturn,
  type Promotion, type InsertPromotion, type Advertisement, type InsertAdvertisement,
  type ProductReview, type InsertProductReview, type ReviewLike, type InsertReviewLike, 
  type StoreReview, type InsertStoreReview, type StoreReviewLike, type InsertStoreReviewLike,
  type Settlement, type InsertSettlement,
  type StoreAnalytics, type InsertStoreAnalytics, type InventoryLog, type InsertInventoryLog,
  type DeliveryPartner, type InsertDeliveryPartner, type Delivery, type InsertDelivery, type DeliveryZone, type InsertDeliveryZone,
  type PaymentTransaction, type Coupon, type InsertCoupon, type Banner, type InsertBanner,
  type SupportTicket, type InsertSupportTicket, type SiteSetting, type FlashSale, type InsertFlashSale,
  type VendorVerification, type InsertVendorVerification, type FraudAlert, type InsertFraudAlert,
  type Commission, type InsertCommission, type ProductAttribute, type InsertProductAttribute,
  type AdminLog, type InsertAdminLog, type PasswordResetToken, type InsertPasswordResetToken
} from "@shared/schema";
import { db } from "./db";
import { eq, and, ilike, or, desc, count, sql, gte, gt, lt, lte, inArray } from "drizzle-orm";

export interface IStorage {
  // User operations
  getUser(id: number): Promise<User | undefined>;
  getAllUsers(): Promise<User[]>;
  getUserByEmail(email: string): Promise<User | undefined>;
  getUserByPhone(phone: string): Promise<User | undefined>;
  getUserByFirebaseUid(firebaseUid: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUser(id: number, updates: Partial<InsertUser>): Promise<User | undefined>;
  deleteUserAccount(userId: number): Promise<void>;

  // Admin user operations
  getAdminUser(id: number): Promise<AdminUser | undefined>;
  getAdminUserByEmail(email: string): Promise<AdminUser | undefined>;
  createAdminUser(adminUser: InsertAdminUser): Promise<AdminUser>;
  getAdminUsers(): Promise<AdminUser[]>;

  // Password reset operations
  storePasswordResetToken(userId: number, token: string, expiresAt: Date): Promise<void>;
  getPasswordResetToken(token: string): Promise<{ userId: number; expiresAt: Date } | undefined>;
  deletePasswordResetToken(token: string): Promise<boolean>;
  updateUserPassword(userId: number, newPassword: string): Promise<void>;

  // User approval operations
  getPendingUsers(): Promise<User[]>;
  approveUser(userId: number, adminId: number): Promise<User | undefined>;
  rejectUser(userId: number, adminId: number): Promise<User | undefined>;
  getAllUsersWithStatus(): Promise<User[]>;

  // Store operations
  getStore(id: number): Promise<Store | undefined>;
  getStoresByOwnerId(ownerId: number): Promise<Store[]>;
  getAllStores(): Promise<Store[]>;
  createStore(store: InsertStore): Promise<Store>;
  updateStore(id: number, updates: Partial<InsertStore>): Promise<Store | undefined>;

  // Category operations
  getAllCategories(): Promise<Category[]>;
  getCategory(id: number): Promise<Category | undefined>;
  createCategory(category: InsertCategory): Promise<Category>;
  updateCategory(id: number, updates: Partial<InsertCategory>): Promise<Category | undefined>;
  deleteCategory(id: number): Promise<boolean>;

  // Product operations
  getProduct(id: number): Promise<Product | undefined>;
  getProductsByStoreId(storeId: number): Promise<Product[]>;
  getAllProducts(): Promise<Product[]>;
  getProductsByCategory(categoryId: number): Promise<Product[]>;
  searchProducts(query: string): Promise<Product[]>;
  createProduct(product: InsertProduct): Promise<Product>;
  updateProduct(id: number, updates: Partial<InsertProduct>): Promise<Product | undefined>;
  deleteProduct(id: number): Promise<boolean>;

  // Order operations
  getOrder(id: number): Promise<Order | undefined>;
  getOrdersByCustomerId(customerId: number): Promise<Order[]>;
  getOrdersByStoreId(storeId: number): Promise<Order[]>;
  createOrder(order: InsertOrder): Promise<Order>;
  updateOrderStatus(id: number, status: string): Promise<Order | undefined>;

  // Order item operations
  getOrderItems(orderId: number): Promise<OrderItem[]>;
  createOrderItem(orderItem: InsertOrderItem): Promise<OrderItem>;

  // Cart operations
  getCartItems(userId: number): Promise<CartItem[]>;
  addToCart(cartItem: InsertCartItem): Promise<CartItem>;
  updateCartItem(id: number, quantity: number): Promise<CartItem | undefined>;
  removeFromCart(id: number): Promise<boolean>;
  clearCart(userId: number): Promise<boolean>;

  // Wishlist operations
  getWishlistItems(userId: number): Promise<WishlistItem[]>;
  addToWishlist(wishlistItem: InsertWishlistItem): Promise<WishlistItem>;
  removeFromWishlist(id: number): Promise<boolean>;
  isInWishlist(userId: number, productId: number): Promise<boolean>;

  // Admin operations
  getAdmin(id: number): Promise<Admin | undefined>;
  getAdminByEmail(email: string): Promise<Admin | undefined>;
  createAdmin(admin: InsertAdmin): Promise<Admin>;

  // Website visit tracking
  recordVisit(visit: InsertWebsiteVisit): Promise<WebsiteVisit>;
  getVisitStats(days?: number): Promise<any>;
  getPageViews(page?: string): Promise<WebsiteVisit[]>;

  // Notifications
  createNotification(notification: InsertNotification): Promise<Notification>;
  getUserNotifications(userId: number): Promise<Notification[]>;
  getNotificationsByUserId(userId: number): Promise<Notification[]>;
  getNotificationsByType(type: string): Promise<Notification[]>;
  markNotificationAsRead(id: number): Promise<Notification>;
  markAllNotificationsAsRead(userId: number): Promise<boolean>;

  // Order tracking
  createOrderTracking(tracking: InsertOrderTracking): Promise<OrderTracking>;
  getOrderTracking(orderId: number): Promise<OrderTracking[]>;
  updateOrderTracking(orderId: number, status: string, description?: string, location?: string): Promise<OrderTracking>;

  // Return policy
  createReturnPolicy(policy: InsertReturnPolicy): Promise<ReturnPolicy>;
  getReturnPolicy(storeId: number): Promise<ReturnPolicy | undefined>;
  updateReturnPolicy(storeId: number, updates: Partial<InsertReturnPolicy>): Promise<ReturnPolicy | undefined>;

  // Returns
  createReturn(returnItem: InsertReturn): Promise<Return>;
  getReturn(id: number): Promise<Return | undefined>;
  getReturnsByCustomer(customerId: number): Promise<Return[]>;
  getReturnsByStore(storeId: number): Promise<Return[]>;
  updateReturnStatus(id: number, status: string): Promise<Return | undefined>;

  // Distance calculation between stores and user location
  calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number;
  getStoresWithDistance(userLat: number, userLon: number, storeType?: string): Promise<(Store & { distance: number })[]>;
  
  // Food-specific methods with 10km radius filtering like modern apps
  getFoodStoresWithinRadius(userLat: number, userLon: number, radiusKm?: number): Promise<(Store & { distance: number })[]>;
  getFoodItemsWithinRadius(userLat: number, userLon: number, radiusKm?: number): Promise<(Product & { distance: number; storeName: string; storeAddress: string; deliveryTime?: string })[]>;

  // Seller hub analytics
  getSellerDashboardStats(storeId: number): Promise<{
    totalProducts: number;
    totalOrders: number;
    totalRevenue: number;
    pendingOrders: number;
    averageRating: number;
    totalReviews: number;
  }>;
  getStoreAnalytics(storeId: number, days?: number): Promise<StoreAnalytics[]>;
  updateStoreAnalytics(data: InsertStoreAnalytics): Promise<StoreAnalytics>;

  // Promotions
  getStorePromotions(storeId: number): Promise<Promotion[]>;
  createPromotion(promotion: InsertPromotion): Promise<Promotion>;
  updatePromotion(id: number, updates: Partial<InsertPromotion>): Promise<Promotion | undefined>;
  deletePromotion(id: number): Promise<boolean>;

  // Advertisements
  getStoreAdvertisements(storeId: number): Promise<Advertisement[]>;
  createAdvertisement(ad: InsertAdvertisement): Promise<Advertisement>;
  updateAdvertisement(id: number, updates: Partial<InsertAdvertisement>): Promise<Advertisement | undefined>;
  deleteAdvertisement(id: number): Promise<boolean>;

  // Product reviews
  getProductReviews(productId: number): Promise<ProductReview[]>;
  getStoreReviews(storeId: number): Promise<ProductReview[]>;
  createProductReview(review: InsertProductReview): Promise<ProductReview>;
  updateProductReview(id: number, updates: Partial<InsertProductReview>): Promise<ProductReview | undefined>;
  deleteProductReview(id: number): Promise<boolean>;

  // Store reviews
  getStoreReviewsByStoreId(storeId: number): Promise<StoreReview[]>;
  createStoreReview(review: InsertStoreReview): Promise<StoreReview>;
  updateStoreReview(id: number, updates: Partial<InsertStoreReview>): Promise<StoreReview | undefined>;
  deleteStoreReview(id: number): Promise<boolean>;
  updateStoreRating(storeId: number): Promise<void>;

  // Store review likes
  getStoreReviewLikes(reviewId: number): Promise<StoreReviewLike[]>;
  createStoreReviewLike(like: InsertStoreReviewLike): Promise<StoreReviewLike>;
  deleteStoreReviewLike(reviewId: number, userId: number): Promise<boolean>;
  hasUserLikedStoreReview(reviewId: number, userId: number): Promise<boolean>;

  // Settlements
  getStoreSettlements(storeId: number): Promise<Settlement[]>;
  createSettlement(settlement: InsertSettlement): Promise<Settlement>;
  updateSettlement(id: number, updates: Partial<InsertSettlement>): Promise<Settlement | undefined>;

  // Inventory management
  getInventoryLogs(storeId: number, productId?: number): Promise<InventoryLog[]>;
  createInventoryLog(log: InsertInventoryLog): Promise<InventoryLog>;
  updateProductStock(productId: number, quantity: number, type: string, reason?: string): Promise<boolean>;

  // Flash Sales operations
  getAllFlashSales(): Promise<FlashSale[]>;
  getActiveFlashSales(): Promise<FlashSale[]>;
  getFlashSale(id: number): Promise<FlashSale | undefined>;
  createFlashSale(flashSale: InsertFlashSale): Promise<FlashSale>;
  updateFlashSale(id: number, updates: Partial<InsertFlashSale>): Promise<FlashSale | undefined>;
  deleteFlashSale(id: number): Promise<boolean>;
  getFlashSaleProducts(flashSaleId: number): Promise<Product[]>;

  // Enhanced admin management methods
  getAllOrders(): Promise<Order[]>;
  getAllTransactions(): Promise<PaymentTransaction[]>;
  getAllCoupons(): Promise<Coupon[]>;
  createCoupon(coupon: InsertCoupon): Promise<Coupon>;
  updateCoupon(id: number, updates: Partial<InsertCoupon>): Promise<Coupon | undefined>;
  deleteCoupon(id: number): Promise<boolean>;
  getAllBanners(): Promise<Banner[]>;
  createBanner(banner: InsertBanner): Promise<Banner>;
  updateBanner(id: number, updates: Partial<InsertBanner>): Promise<Banner | undefined>;
  deleteBanner(id: number): Promise<boolean>;
  getAllSupportTickets(): Promise<SupportTicket[]>;
  createSupportTicket(ticket: InsertSupportTicket): Promise<SupportTicket>;
  updateSupportTicket(id: number, updates: Partial<InsertSupportTicket>): Promise<SupportTicket | undefined>;
  getAllSiteSettings(): Promise<SiteSetting[]>;
  updateSiteSetting(key: string, value: string): Promise<SiteSetting | undefined>;

  // Enhanced admin features
  getDashboardStats(): Promise<any>;
  getAllVendorVerifications(): Promise<VendorVerification[]>;
  updateVendorVerification(id: number, updates: Partial<InsertVendorVerification>): Promise<VendorVerification | undefined>;
  approveVendorVerification(id: number, adminId: number): Promise<VendorVerification | undefined>;
  rejectVendorVerification(id: number, adminId: number, reason: string): Promise<VendorVerification | undefined>;
  getAllFraudAlerts(): Promise<FraudAlert[]>;
  createFraudAlert(alert: InsertFraudAlert): Promise<FraudAlert>;
  updateFraudAlert(id: number, updates: Partial<InsertFraudAlert>): Promise<FraudAlert | undefined>;
  updateFraudAlertStatus(id: number, status: string): Promise<FraudAlert | undefined>;
  getAllCommissions(): Promise<Commission[]>;
  createCommission(commission: InsertCommission): Promise<Commission>;
  updateCommission(id: number, updates: Partial<InsertCommission>): Promise<Commission | undefined>;
  getCommissions(status?: string): Promise<Commission[]>;
  updateCommissionStatus(id: number, status: string): Promise<Commission | undefined>;

  // Dashboard stats methods
  getTotalUsersCount(): Promise<number>;
  getTotalStoresCount(): Promise<number>;
  getTotalOrdersCount(): Promise<number>;
  getTotalRevenue(): Promise<number>;
  getPendingOrdersCount(): Promise<number>;
  getActiveUsersCount(): Promise<number>;
  getPendingVendorVerificationsCount(): Promise<number>;
  getOpenFraudAlertsCount(): Promise<number>;
  getProductAttributes(productId: number): Promise<ProductAttribute[]>;
  createProductAttribute(attribute: InsertProductAttribute): Promise<ProductAttribute>;
  deleteProductAttribute(id: number): Promise<boolean>;
  logAdminAction(log: InsertAdminLog): Promise<AdminLog>;
  getAdminLogs(adminId?: number): Promise<AdminLog[]>;
  bulkUpdateProductStatus(productIds: number[], status: boolean): Promise<boolean>;
  getOrdersWithDetails(): Promise<any[]>;
  getRevenueAnalytics(days?: number): Promise<any>;
  getUsersAnalytics(): Promise<any>;
  getInventoryAlerts(): Promise<any[]>;

  // Delivery partner operations
  getDeliveryPartner(id: number): Promise<DeliveryPartner | undefined>;
  getDeliveryPartnerByUserId(userId: number): Promise<DeliveryPartner | undefined>;
  getAllDeliveryPartners(): Promise<DeliveryPartner[]>;
  getPendingDeliveryPartners(): Promise<DeliveryPartner[]>;
  createDeliveryPartner(deliveryPartner: InsertDeliveryPartner): Promise<DeliveryPartner>;
  updateDeliveryPartner(id: number, updates: Partial<InsertDeliveryPartner>): Promise<DeliveryPartner | undefined>;
  approveDeliveryPartner(id: number, adminId: number): Promise<DeliveryPartner | undefined>;
  rejectDeliveryPartner(id: number, adminId: number, reason: string): Promise<DeliveryPartner | undefined>;

  // Delivery operations
  getDelivery(id: number): Promise<Delivery | undefined>;
  getDeliveriesByPartnerId(partnerId: number): Promise<Delivery[]>;
  getDeliveriesByOrderId(orderId: number): Promise<Delivery[]>;
  getPendingDeliveries(): Promise<Delivery[]>;
  getActiveDeliveries(partnerId: number): Promise<Delivery[]>;
  createDelivery(delivery: InsertDelivery): Promise<Delivery>;
  updateDeliveryStatus(id: number, status: string, partnerId?: number): Promise<Delivery | undefined>;
  assignDeliveryToPartner(deliveryId: number, partnerId: number): Promise<Delivery | undefined>;
  getActiveDeliveriesForStore(storeId: number): Promise<any[]>;

  // Delivery tracking
  getDeliveryTrackingData(deliveryId: number): Promise<any>;
  updateDeliveryLocation(deliveryId: number, latitude: number, longitude: number): Promise<void>;
  updateDeliveryStatus(deliveryId: number, status: string, description?: string): Promise<void>;

  // Delivery Zone methods
  createDeliveryZone(data: InsertDeliveryZone): Promise<DeliveryZone>;
  getDeliveryZones(): Promise<DeliveryZone[]>;
  getAllDeliveryZones(): Promise<DeliveryZone[]>;
  updateDeliveryZone(id: number, data: Partial<InsertDeliveryZone>): Promise<DeliveryZone>;
  deleteDeliveryZone(id: number): Promise<void>;
  calculateDeliveryFee(distance: number): Promise<{ fee: number; zone: DeliveryZone | null }>;

  // Admin authentication methods
  authenticateAdmin(email: string, password: string): Promise<AdminUser | null>;
  createDefaultAdmin(): Promise<AdminUser | null>;
  
  // Device token management for Firebase FCM
  saveDeviceToken(userId: number, token: string, deviceType: string): Promise<boolean>;
  removeDeviceToken(userId: number, token: string): Promise<boolean>;
  getDeviceTokensByUserId(userId: number): Promise<string[]>;
  getDeviceTokensByUserIds(userIds: number[]): Promise<string[]>;
  getDeviceTokensByRole(role: string): Promise<string[]>;
  getDeviceTokensByUser(userId: number, deviceType?: string): Promise<any[]>;
  createDeviceToken(tokenData: any): Promise<any>;
  
  // Admin profile management methods
  getAdminProfile(adminId: number): Promise<any>;
  updateAdminProfile(adminId: number, updates: any): Promise<any>;
  verifyAdminPassword(adminId: number, password: string): Promise<boolean>;
  changeAdminPassword(adminId: number, currentPassword: string, newPassword: string): Promise<boolean>;

  // Delivery zone management methods
  getAllDeliveryZones(): Promise<any[]>;
  createDeliveryZone(zoneData: any): Promise<any>;
  updateDeliveryZone(id: number, updateData: any): Promise<any>;
  deleteDeliveryZone(id: number): Promise<boolean>;
}

export class DatabaseStorage implements IStorage {

  // User operations
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async getAllUsers(): Promise<User[]> {
    return await db.select().from(users);
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user;
  }

  async getUserByPhone(phone: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.phone, phone));
    return user;
  }

  async getUserByFirebaseUid(firebaseUid: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.firebaseUid, firebaseUid));
    return user;
  }

  async getUserByToken(token: string): Promise<User | undefined> {
    // Simple token validation - in production this would be more sophisticated
    // For now, assume token is just the user ID for testing purposes
    try {
      const userId = parseInt(token);
      if (isNaN(userId)) return undefined;

      const [user] = await db.select().from(users).where(eq(users.id, userId));
      return user;
    } catch {
      return undefined;
    }
  }

  async createUser(user: InsertUser): Promise<User> {
    const [newUser] = await db.insert(users).values(user).returning();
    return newUser;
  }

  async updateUser(id: number, updates: Partial<InsertUser>): Promise<User | undefined> {
    const [updatedUser] = await db.update(users).set(updates).where(eq(users.id, id)).returning();
    return updatedUser;
  }

  async deleteUserAccount(userId: number): Promise<void> {
    console.log(`🗑️ CRITICAL: Starting comprehensive account deletion for user ID: ${userId}`);
    console.log(`🚨 STACK TRACE:`);
    console.trace('Account deletion called from:');
    
    try {
      // Delete user account and all associated data in the correct order to respect foreign key constraints
      
      // 1. Delete cart items
      const deletedCartItems = await db.delete(cartItems).where(eq(cartItems.userId, userId));
      console.log(`✅ Deleted cart items for user ${userId}`);
      
      // 2. Delete wishlist items
      await db.delete(wishlistItems).where(eq(wishlistItems.userId, userId));
      console.log(`✅ Deleted wishlist items for user ${userId}`);
      
      // 3. Delete notifications
      await db.delete(notifications).where(eq(notifications.userId, userId));
      console.log(`✅ Deleted notifications for user ${userId}`);
      
      // 4. Delete push notification tokens
      await db.delete(pushNotificationTokens).where(eq(pushNotificationTokens.userId, userId));
      console.log(`✅ Deleted push notification tokens for user ${userId}`);
      
      // 5. Delete password reset tokens
      await db.delete(passwordResetTokens).where(eq(passwordResetTokens.userId, userId));
      console.log(`✅ Deleted password reset tokens for user ${userId}`);
      
      // 6. Get user's stores first
      const userStores = await db.select().from(stores).where(eq(stores.ownerId, userId));
      console.log(`📦 Found ${userStores.length} stores owned by user ${userId}`);
      
      // 7. For each store, delete associated data
      for (const store of userStores) {
        console.log(`🏪 Processing store: ${store.name} (ID: ${store.id})`);
        
        // Get store products first
        const storeProducts = await db.select().from(products).where(eq(products.storeId, store.id));
        console.log(`📦 Found ${storeProducts.length} products in store ${store.id}`);
        
        // Delete store-specific data first
        await db.delete(storeReviews).where(eq(storeReviews.storeId, store.id));
        await db.delete(storeReviewLikes).where(eq(storeReviewLikes.storeId, store.id));
        await db.delete(storeAnalytics).where(eq(storeAnalytics.storeId, store.id));
        await db.delete(inventoryLogs).where(eq(inventoryLogs.storeId, store.id));
        await db.delete(settlements).where(eq(settlements.storeId, store.id));
        console.log(`✅ Deleted store-specific data for store ${store.id}`);
        
        // For each product, delete related data
        for (const product of storeProducts) {
          // Delete product reviews and their likes
          const productReviewsToDelete = await db.select().from(productReviews).where(eq(productReviews.productId, product.id));
          for (const review of productReviewsToDelete) {
            await db.delete(reviewLikes).where(eq(reviewLikes.reviewId, review.id));
          }
          await db.delete(productReviews).where(eq(productReviews.productId, product.id));
          
          // Delete product attributes
          await db.delete(productAttributes).where(eq(productAttributes.productId, product.id));
          
          // Delete order items (but keep orders for business records)
          await db.delete(orderItems).where(eq(orderItems.productId, product.id));
          
          console.log(`✅ Deleted data for product: ${product.name} (ID: ${product.id})`);
        }
        
        // Delete all products for this store
        await db.delete(products).where(eq(products.storeId, store.id));
        console.log(`✅ Deleted all products for store ${store.id}`);
      }
      
      // 8. Delete all stores owned by user
      await db.delete(stores).where(eq(stores.ownerId, userId));
      console.log(`✅ Deleted all stores owned by user ${userId}`);
      
      // 9. Delete promotions, advertisements, coupons, banners created by user
      await db.delete(promotions).where(eq(promotions.storeId, sql`(SELECT id FROM stores WHERE owner_id = ${userId})`));
      await db.delete(advertisements).where(eq(advertisements.userId, userId));
      await db.delete(coupons).where(eq(coupons.storeId, sql`(SELECT id FROM stores WHERE owner_id = ${userId})`));
      await db.delete(banners).where(eq(banners.storeId, sql`(SELECT id FROM stores WHERE owner_id = ${userId})`));
      await db.delete(flashSales).where(eq(flashSales.storeId, sql`(SELECT id FROM stores WHERE owner_id = ${userId})`));
      console.log(`✅ Deleted marketing content for user ${userId}`);
      
      // 10. Handle delivery partner data if user is a delivery partner
      const deliveryPartner = await db.select().from(deliveryPartners).where(eq(deliveryPartners.userId, userId)).limit(1);
      if (deliveryPartner.length > 0) {
        const partnerId = deliveryPartner[0].id;
        console.log(`🚚 Processing delivery partner data for partner ID: ${partnerId}`);
        
        // Delete delivery location tracking
        await db.delete(deliveryLocationTracking).where(eq(deliveryLocationTracking.deliveryPartnerId, partnerId));
        
        // Update deliveries to remove partner reference (don't delete delivery records for audit purposes)
        await db.update(deliveries).set({ deliveryPartnerId: null }).where(eq(deliveries.deliveryPartnerId, partnerId));
        
        // Delete delivery partner record
        await db.delete(deliveryPartners).where(eq(deliveryPartners.userId, userId));
        console.log(`✅ Processed delivery partner data for user ${userId}`);
      }
      
      // 11. Delete support tickets created by user
      await db.delete(supportTickets).where(eq(supportTickets.userId, userId));
      console.log(`✅ Deleted support tickets for user ${userId}`);
      
      // 12. Delete fraud alerts related to user
      await db.delete(fraudAlerts).where(eq(fraudAlerts.userId, userId));
      console.log(`✅ Deleted fraud alerts for user ${userId}`);
      
      // 13. Delete vendor verifications
      await db.delete(vendorVerifications).where(eq(vendorVerifications.userId, userId));
      console.log(`✅ Deleted vendor verifications for user ${userId}`);
      
      // 14. Handle orders - anonymize customer orders rather than delete for business/legal records
      const userOrders = await db.select().from(orders).where(eq(orders.customerId, userId));
      if (userOrders.length > 0) {
        await db.update(orders).set({ 
          customerName: 'Deleted User',
          email: 'deleted@user.com',
          phone: 'DELETED',
          address: 'User Account Deleted'
        }).where(eq(orders.customerId, userId));
        console.log(`✅ Anonymized ${userOrders.length} orders for user ${userId}`);
      }
      
      // 15. Delete website visits and tracking data
      await db.delete(websiteVisits).where(eq(websiteVisits.userId, userId));
      console.log(`✅ Deleted website visits for user ${userId}`);
      
      // 16. Delete commission records
      await db.delete(commissions).where(eq(commissions.userId, userId));
      console.log(`✅ Deleted commission records for user ${userId}`);
      
      // 17. Finally, delete the user account
      await db.delete(users).where(eq(users.id, userId));
      console.log(`✅ Successfully deleted user account ${userId}`);
      
      console.log(`🎉 Account deletion completed successfully for user ID: ${userId}`);
      
    } catch (error) {
      console.error(`❌ Error during account deletion for user ${userId}:`, error);
      throw new Error(`Failed to delete user account: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Admin user operations
  async getAdminUser(id: number): Promise<AdminUser | undefined> {
    const [adminUser] = await db.select().from(adminUsers).where(eq(adminUsers.id, id));
    return adminUser;
  }

  async getAdminUserByEmail(email: string): Promise<AdminUser | undefined> {
    const [adminUser] = await db.select().from(adminUsers).where(eq(adminUsers.email, email));
    return adminUser;
  }

  async createAdminUser(adminUser: InsertAdminUser): Promise<AdminUser> {
    const [newAdminUser] = await db.insert(adminUsers).values(adminUser).returning();
    return newAdminUser;
  }

  async getAdminUsers(): Promise<AdminUser[]> {
    return await db.select().from(adminUsers);
  }

  // User approval operations
  async getPendingUsers(): Promise<User[]> {
    return await db.select().from(users).where(eq(users.status, 'pending'));
  }

  async approveUser(userId: number, adminId: number): Promise<User | undefined> {
    try {
      console.log(`Attempting to approve user ${userId} by admin ${adminId}`);

      // For now, we'll set approvedBy to null to avoid foreign key constraint issues
      // until we properly migrate the database schema
      const [approvedUser] = await db
        .update(users)
        .set({
          status: 'active',
          approvalDate: new Date(),
          approvedBy: null, // Temporarily set to null to avoid FK constraint
          updatedAt: new Date()
        })
        .where(eq(users.id, userId))
        .returning();

      console.log('User approval successful:', approvedUser);
      return approvedUser;
    } catch (error) {
      console.error('Error in approveUser:', error);
      throw error;
    }
  }

  async rejectUser(userId: number, adminId: number): Promise<User | undefined> {
    try {
      console.log(`Attempting to reject user ${userId} by admin ${adminId}`);

      const [rejectedUser] = await db
        .update(users)
        .set({
          status: 'rejected',
          approvalDate: new Date(),
          approvedBy: null, // Temporarily set to null to avoid FK constraint
          updatedAt: new Date()
        })
        .where(eq(users.id, userId))
        .returning();

      console.log('User rejection successful:', rejectedUser);
      return rejectedUser;
    } catch (error) {
      console.error('Error in rejectUser:', error);
      throw error;
    }
  }

  async getAllUsersWithStatus(): Promise<User[]> {
    try {
      const result = await db.select().from(users).orderBy(desc(users.createdAt));
      return result;
    } catch (error) {
      console.error("Database error in getAllUsersWithStatus:", error);
      throw error;
    }
  }

  // Store operations
  async getStore(id: number): Promise<Store | undefined> {
    const [store] = await db.select().from(stores).where(eq(stores.id, id));
    return store;
  }

  async getStoresByOwnerId(ownerId: number): Promise<Store[]> {
    try {
      const result = await db.select().from(stores).where(eq(stores.ownerId, ownerId));
      return result;
    } catch (error) {
      console.error("Database error in getStoresByOwnerId:", error);
      throw error;
    }
  }

  async getAllStores(): Promise<Store[]> {
    return await db.select().from(stores);
  }

  async createStore(store: InsertStore): Promise<Store> {
    // Generate a unique slug from the store name
    const baseSlug = store.name.toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '') // Remove special characters
      .replace(/\s+/g, '-') // Replace spaces with hyphens
      .replace(/-+/g, '-') // Replace multiple hyphens with single
      .trim();

    let slug = baseSlug;
    let counter = 1;

    // Check if slug exists and make it unique
    while (true) {
      const existingStore = await db.select().from(stores).where(eq(stores.slug, slug)).limit(1);
      if (existingStore.length === 0) {
        break;
      }
      slug = `${baseSlug}-${counter}`;
      counter++;
    }

    const storeWithSlug = {
      ...store,
      slug,
      isActive: true,
      featured: false,
      rating: "0.00",
      totalReviews: 0,
      state: store.state || 'Not specified'
    };

    const [newStore] = await db.insert(stores).values(storeWithSlug).returning();
    return newStore;
  }

  async updateStore(id: number, updates: Partial<InsertStore>): Promise<Store | undefined> {
    const [updatedStore] = await db.update(stores).set(updates).where(eq(stores.id, id)).returning();
    return updatedStore;
  }

  // Category operations
  async getAllCategories(): Promise<Category[]> {
    return await db.select().from(categories);
  }

  async getCategory(id: number): Promise<Category | undefined> {
    const [category] = await db.select().from(categories).where(eq(categories.id, id));
    return category;
  }

  async createCategory(category: InsertCategory): Promise<Category> {
    const [newCategory] = await db.insert(categories).values(category).returning();
    return newCategory;
  }

  async updateCategory(id: number, updates: Partial<InsertCategory>): Promise<Category | undefined> {
    const [updatedCategory] = await db
      .update(categories)
      .set(updates)
      .where(eq(categories.id, id))
      .returning();
    return updatedCategory;
  }

  async deleteCategory(id: number): Promise<boolean> {
    const result = await db.delete(categories).where(eq(categories.id, id));
    return (result.rowCount ?? 0) > 0;
  }

  // Product operations
  async getProduct(id: number): Promise<Product | undefined> {
    const [productWithRatings] = await db
      .select({
        ...products,
        avgRating: sql<number>`COALESCE(AVG(${productReviews.rating}), 0)`.as('avgRating'),
        reviewCount: sql<number>`COUNT(${productReviews.id})`.as('reviewCount')
      })
      .from(products)
      .leftJoin(productReviews, eq(products.id, productReviews.productId))
      .where(eq(products.id, id))
      .groupBy(products.id);

    if (!productWithRatings) return undefined;

    const avgRating = productWithRatings.avgRating ? Number(productWithRatings.avgRating) : 0;
    const reviewCount = productWithRatings.reviewCount ? Number(productWithRatings.reviewCount) : 0;
    
    return {
      ...productWithRatings,
      rating: avgRating > 0 ? avgRating.toFixed(1) : "0.0",
      totalReviews: reviewCount
    };
  }

  async getProductsByStoreId(storeId: number): Promise<Product[]> {
    const productsWithRatings = await db
      .select({
        ...products,
        avgRating: sql<number>`COALESCE(AVG(${productReviews.rating}), 0)`.as('avgRating'),
        reviewCount: sql<number>`COUNT(${productReviews.id})`.as('reviewCount')
      })
      .from(products)
      .leftJoin(productReviews, eq(products.id, productReviews.productId))
      .where(eq(products.storeId, storeId))
      .groupBy(products.id)
      .orderBy(desc(products.createdAt));

    return productsWithRatings.map(product => {
      const avgRating = product.avgRating ? Number(product.avgRating) : 0;
      const reviewCount = product.reviewCount ? Number(product.reviewCount) : 0;
      
      return {
        ...product,
        rating: avgRating > 0 ? avgRating.toFixed(1) : "0.0",
        totalReviews: reviewCount
      };
    });
  }

  async getAllProducts(): Promise<Product[]> {
    // Get products with calculated average rating and review count
    const productsWithRatings = await db
      .select({
        ...products,
        avgRating: sql<number>`COALESCE(AVG(${productReviews.rating}), 0)`.as('avgRating'),
        reviewCount: sql<number>`COUNT(${productReviews.id})`.as('reviewCount')
      })
      .from(products)
      .leftJoin(productReviews, eq(products.id, productReviews.productId))
      .groupBy(products.id)
      .orderBy(desc(products.createdAt));

    // Update the rating field with calculated average and return
    return productsWithRatings.map(product => {
      const avgRating = product.avgRating ? Number(product.avgRating) : 0;
      const reviewCount = product.reviewCount ? Number(product.reviewCount) : 0;
      
      return {
        ...product,
        rating: avgRating > 0 ? avgRating.toFixed(1) : "0.0",
        totalReviews: reviewCount
      };
    });
  }

  async getProductsByCategory(categoryId: number): Promise<Product[]> {
    try {
      console.log(`[STORAGE] Filtering products by categoryId: ${categoryId}`);
      const productsWithRatings = await db
        .select({
          ...products,
          avgRating: sql<number>`COALESCE(AVG(${productReviews.rating}), 0)`.as('avgRating'),
          reviewCount: sql<number>`COUNT(${productReviews.id})`.as('reviewCount')
        })
        .from(products)
        .leftJoin(productReviews, eq(products.id, productReviews.productId))
        .where(eq(products.categoryId, categoryId))
        .groupBy(products.id);

      console.log(`[STORAGE] Database query returned ${productsWithRatings.length} products for category ${categoryId}`);
      
      // Debug: Log first few products to verify filtering
      if (productsWithRatings.length > 0) {
        console.log(`[STORAGE] Sample products:`, productsWithRatings.slice(0, 3).map(p => ({
          id: p.id,
          name: p.name,
          categoryId: p.categoryId
        })));
      }
      
      return productsWithRatings.map(product => {
        const avgRating = product.avgRating ? Number(product.avgRating) : 0;
        const reviewCount = product.reviewCount ? Number(product.reviewCount) : 0;
        
        return {
          ...product,
          rating: avgRating > 0 ? avgRating.toFixed(1) : "0.0",
          totalReviews: reviewCount
        };
      });
    } catch (error) {
      console.error(`[STORAGE] Error in getProductsByCategory:`, error);
      throw error;
    }
  }

  async searchProducts(query: string): Promise<Product[]> {
    const productsWithRatings = await db
      .select({
        ...products,
        avgRating: sql<number>`COALESCE(AVG(${productReviews.rating}), 0)`.as('avgRating'),
        reviewCount: sql<number>`COUNT(${productReviews.id})`.as('reviewCount')
      })
      .from(products)
      .leftJoin(productReviews, eq(products.id, productReviews.productId))
      .where(
        or(
          ilike(products.name, `%${query}%`),
          ilike(products.description, `%${query}%`)
        )
      )
      .groupBy(products.id);

    return productsWithRatings.map(product => {
      const avgRating = product.avgRating ? Number(product.avgRating) : 0;
      const reviewCount = product.reviewCount ? Number(product.reviewCount) : 0;
      
      return {
        ...product,
        rating: avgRating > 0 ? avgRating.toFixed(1) : "0.0",
        totalReviews: reviewCount
      };
    });
  }

  async createProduct(product: InsertProduct): Promise<Product> {
    // Generate slug if not provided
    let slug = product.slug;
    if (!slug) {
      const baseSlug = product.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      let counter = 1;
      slug = baseSlug;

      while (true) {
        const existingProduct = await db.select().from(products).where(eq(products.slug, slug)).limit(1);
        if (existingProduct.length === 0) {
          break;
        }
        slug = `${baseSlug}-${counter}`;
        counter++;
      }
    }

    const productWithDefaults = {
      ...product,
      slug,
      isActive: product.isActive !== undefined ? product.isActive : true,
      rating: product.rating || "0.00",
      totalReviews: product.totalReviews || 0,
      stock: product.stock || 0,
      imageUrl: product.imageUrl || "",
      images: product.images || []
    };

    const [newProduct] = await db.insert(products).values(productWithDefaults).returning();
    return newProduct;
  }

  async updateProduct(id: number, updates: Partial<InsertProduct>): Promise<Product | undefined> {
    const [updatedProduct] = await db.update(products).set(updates).where(eq(products.id, id)).returning();
    return updatedProduct;
  }

  async deleteProduct(id: number): Promise<boolean> {
    const result = await db.delete(products).where(eq(products.id, id));
    return (result.rowCount || 0) > 0;
  }

  // Order operations
  async getOrder(id: number): Promise<Order | undefined> {
    const [order] = await db.select().from(orders).where(eq(orders.id, id));
    return order;
  }

  async getOrdersByCustomerId(customerId: number): Promise<Order[]> {
    return await db.select().from(orders).where(eq(orders.customerId, customerId)).orderBy(desc(orders.createdAt));
  }

  async getOrdersByStoreId(storeId: number): Promise<Order[]> {
    // Use a simple approach - get all orders and filter on the backend for now
    const allOrders = await db.select().from(orders).orderBy(desc(orders.createdAt));

    // Filter orders that have items from this store
    const storeOrders = [];
    for (const order of allOrders) {
      const orderItemsForStore = await db.select().from(orderItems)
        .where(and(eq(orderItems.orderId, order.id), eq(orderItems.storeId, storeId)));

      if (orderItemsForStore.length > 0) {
        storeOrders.push(order);
      }
    }

    return storeOrders;
  }

  async createOrder(order: InsertOrder): Promise<Order> {
    const [newOrder] = await db.insert(orders).values(order).returning();
    return newOrder;
  }

  async updateOrderStatus(id: number, status: string): Promise<Order | undefined> {
    const [updatedOrder] = await db.update(orders).set({ status }).where(eq(orders.id, id)).returning();
    return updatedOrder;
  }

  async getOrdersByStatus(status: string): Promise<Order[]> {
    try {
      return await db.select().from(orders).where(eq(orders.status, status));
    } catch {
      return [];
    }
  }

  async getDeliveryByOrderId(orderId: number): Promise<Delivery | undefined> {
    try {
      const [delivery] = await db.select().from(deliveries).where(eq(deliveries.orderId, orderId));
      return delivery;
    } catch {
      return undefined;
    }
  }

  // Order item operations
  async getOrderItems(orderId: number): Promise<OrderItem[]> {
    return await db.select().from(orderItems).where(eq(orderItems.orderId, orderId));
  }

  async createOrderItem(orderItem: InsertOrderItem): Promise<OrderItem> {
    console.log("Storage: createOrderItem received data:", orderItem);
    const [newOrderItem] = await db.insert(orderItems).values(orderItem).returning();
    return newOrderItem;
  }

  // Cart operations
  async getCartItems(userId: number): Promise<CartItem[]> {
    try {
      return await db.select().from(cartItems).where(eq(cartItems.userId, userId));
    } catch (error) {
      console.error("Error fetching cart items:", error);
      return [];
    }
  }

  async addToCart(cartItem: InsertCartItem): Promise<CartItem> {
    // Check if item already exists in cart
    const existingItem = await db.select().from(cartItems)
      .where(and(eq(cartItems.userId, cartItem.userId), eq(cartItems.productId, cartItem.productId)));

    if (existingItem.length > 0) {
      // Update quantity
      const [updatedItem] = await db.update(cartItems)
        .set({ quantity: existingItem[0].quantity + cartItem.quantity })
        .where(eq(cartItems.id, existingItem[0].id))
        .returning();
      return updatedItem;
    } else {
      // Add new item
      const [newItem] = await db.insert(cartItems).values(cartItem).returning();
      return newItem;
    }
  }

  async updateCartItem(id: number, quantity: number): Promise<CartItem | undefined> {
    const [updatedItem] = await db.update(cartItems).set({ quantity }).where(eq(cartItems.id, id)).returning();
    return updatedItem;
  }

  async removeFromCart(id: number): Promise<boolean> {
    const result = await db.delete(cartItems).where(eq(cartItems.id, id));
    return (result.rowCount || 0) > 0;
  }

  async clearCart(userId: number): Promise<boolean> {
    const result = await db.delete(cartItems).where(eq(cartItems.userId, userId));
    return (result.rowCount || 0) >= 0;
  }

  // Wishlist operations
  async getWishlistItems(userId: number): Promise<any[]> {
    try {
      const result = await db
        .select({
          id: wishlistItems.id,
          userId: wishlistItems.userId,
          productId: wishlistItems.productId,
          createdAt: wishlistItems.createdAt,
          product: products
        })
        .from(wishlistItems)
        .leftJoin(products, eq(wishlistItems.productId, products.id))
        .where(eq(wishlistItems.userId, userId));
      
      return result;
    } catch (error) {
      console.error("Error fetching wishlist items:", error);
      return [];
    }
  }

  async addToWishlist(wishlistItem: InsertWishlistItem): Promise<WishlistItem> {
    // Check if item already exists in wishlist
    const existingItem = await db.select().from(wishlistItems)
      .where(and(eq(wishlistItems.userId, wishlistItem.userId), eq(wishlistItems.productId, wishlistItem.productId)));

    if (existingItem.length > 0) {
      return existingItem[0];
    } else {
      const [newItem] = await db.insert(wishlistItems).values(wishlistItem).returning();
      return newItem;
    }
  }

  async removeFromWishlist(id: number): Promise<boolean> {
    const result = await db.delete(wishlistItems).where(eq(wishlistItems.id, id));
    return (result.rowCount || 0) > 0;
  }

  async isInWishlist(userId: number, productId: number): Promise<boolean> {
    const result = await db.select().from(wishlistItems)
      .where(and(eq(wishlistItems.userId, userId), eq(wishlistItems.productId, productId)))
      .limit(1);
    return result.length > 0;
  }

  // Admin operations
  async getAdmin(id: number): Promise<Admin | undefined> {
    const [admin] = await db.select().from(admins).where(eq(admins.id, id));
    return admin;
  }

  async getAdminByEmail(email: string): Promise<Admin | undefined> {
    const [admin] = await db.select().from(admins).where(eq(admins.email, email));
    return admin;
  }

  async createAdmin(admin: InsertAdmin): Promise<Admin> {
    const [newAdmin] = await db.insert(admins).values(admin).returning();
    return newAdmin;
  }

  // Website visit tracking
  async recordVisit(visit: InsertWebsiteVisit): Promise<WebsiteVisit> {
    const [newVisit] = await db.insert(websiteVisits).values(visit).returning();
    return newVisit;
  }

  async getVisitStats(days: number = 30): Promise<any> {
    const dateThreshold = new Date();
    dateThreshold.setDate(dateThreshold.getDate() - days);

    const totalVisits = await db.select({ count: count() })
      .from(websiteVisits)
      .where(gte(websiteVisits.visitedAt, dateThreshold));

    const uniqueVisitors = await db.select({ count: count(websiteVisits.ipAddress) })
      .from(websiteVisits)
      .where(gte(websiteVisits.visitedAt, dateThreshold));

    const pageViews = await db.select({
      page: websiteVisits.page,
      count: count()
    })
    .from(websiteVisits)
    .where(gte(websiteVisits.visitedAt, dateThreshold))
    .groupBy(websiteVisits.page)
    .orderBy(desc(count()));

    return {
      totalVisits: totalVisits[0]?.count || 0,
      uniqueVisitors: uniqueVisitors[0]?.count || 0,
      pageViews
    };
  }

  async getPageViews(page?: string): Promise<WebsiteVisit[]> {
    if (page) {
      return await db.select().from(websiteVisits).where(eq(websiteVisits.page, page)).orderBy(desc(websiteVisits.visitedAt));
    }
    return await db.select().from(websiteVisits).orderBy(desc(websiteVisits.visitedAt));
  }

  // Notifications
  async createNotification(notification: InsertNotification): Promise<Notification> {
    console.log('Creating notification in database:', notification);
    const [newNotification] = await db.insert(notifications).values(notification).returning();
    console.log('Notification created successfully:', newNotification);
    return newNotification;
  }

  async getUserNotifications(userId: number): Promise<Notification[]> {
    return await db.select().from(notifications)
      .where(eq(notifications.userId, userId))
      .orderBy(desc(notifications.createdAt));
  }

  async getNotificationsByUserId(userId: number): Promise<Notification[]> {
    return await db.select().from(notifications)
      .where(eq(notifications.userId, userId))
      .orderBy(desc(notifications.createdAt));
  }

  async getNotificationsByType(type: string): Promise<Notification[]> {
    return await db.select().from(notifications)
      .where(eq(notifications.type, type))
      .orderBy(desc(notifications.createdAt));
  }

  async markNotificationAsRead(id: number): Promise<Notification> {
    const [updated] = await db.update(notifications)
      .set({ isRead: true })
      .where(eq(notifications.id, id))
      .returning();
    return updated;
  }

  async markAllNotificationsAsRead(userId: number): Promise<boolean> {
    try {
      await db.update(notifications)
        .set({ isRead: true })
        .where(eq(notifications.userId, userId));
      return true;
    } catch {
      return false;
    }
  }

  // Order tracking
  async createOrderTracking(tracking: InsertOrderTracking): Promise<OrderTracking> {
    const [newTracking] = await db.insert(orderTracking).values(tracking).returning();
    return newTracking;
  }

  async getOrderTracking(orderId: number): Promise<OrderTracking[]> {
    try {
      const result = await db.select().from(orderTracking)
        .where(eq(orderTracking.orderId, orderId))
        .orderBy(sql`updated_at DESC`);
      return result;
    } catch (error) {
      console.error('Error in getOrderTracking:', error);
      // Return empty array as fallback
      return [];
    }
  }

  async updateOrderTracking(orderId: number, status: string, description?: string, location?: string): Promise<OrderTracking> {
    const trackingData = {
      orderId,
      status,
      description: description || `Order ${status}`,
      location: location || 'Unknown',
      updatedAt: new Date()
    };

    const [newTracking] = await db.insert(orderTracking).values(trackingData).returning();
    return newTracking;
  }

  // Return policy
  async createReturnPolicy(policy: InsertReturnPolicy): Promise<ReturnPolicy> {
    const [newPolicy] = await db.insert(returnPolicies).values(policy).returning();
    return newPolicy;
  }

  async getReturnPolicy(storeId: number): Promise<ReturnPolicy | undefined> {
    const [policy] = await db.select().from(returnPolicies).where(eq(returnPolicies.storeId, storeId));
    return policy;
  }

  async updateReturnPolicy(storeId: number, updates: Partial<InsertReturnPolicy>): Promise<ReturnPolicy | undefined> {
    const [updated] = await db.update(returnPolicies)
      .set(updates)
      .where(eq(returnPolicies.storeId, storeId))
      .returning();
    return updated;
  }

  // Returns
  async createReturn(returnItem: InsertReturn): Promise<Return> {
    const [newReturn] = await db.insert(returns).values(returnItem).returning();
    return newReturn;
  }

  async getReturn(id: number): Promise<Return | undefined> {
    const [returnItem] = await db.select().from(returns).where(eq(returns.id, id));
    return returnItem;
  }

  async getReturnsByCustomer(customerId: number): Promise<Return[]> {
    return await db.select().from(returns).where(eq(returns.customerId, customerId));
  }

  async getReturnsByStore(storeId: number): Promise<Return[]> {
    return await db.select().from(returns).where(eq(returns.storeId, storeId));
  }

  async updateReturnStatus(id: number, status: string): Promise<Return | undefined> {
    const [updated] = await db.update(returns)
      .set({ status })
      .where(eq(returns.id, id))
      .returning();
    return updated;
  }

  // Distance calculation between stores and user location
  calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const R = 6371; // Radius of the Earth in kilometers
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = 
      Math.sin(dLat/2) * Math.sin(dLat/2) +
      Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
      Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    const distance = R * c; // Distance in kilometers
    return distance;
  }

  async getStoresWithDistance(userLat: number, userLon: number, storeType?: string): Promise<(Store & { distance: number })[]> {
    try {
      console.log(`[DEBUG] getStoresWithDistance called with userLat: ${userLat}, userLon: ${userLon}, storeType: ${storeType}`);
      
      let allStores = await db.select().from(stores);
      console.log(`[DEBUG] Found ${allStores.length} total stores`);

      if (storeType && storeType !== 'all') {
        allStores = allStores.filter(store => store.storeType === storeType);
        console.log(`[DEBUG] After filtering by storeType '${storeType}': ${allStores.length} stores`);
      }

      // Log store coordinates for debugging
      allStores.forEach(store => {
        console.log(`[DEBUG] Store ${store.name}: lat=${store.latitude}, lon=${store.longitude}, type=${store.storeType}`);
      });

      const storesWithDistance = allStores.map((store) => {
        const storeLat = parseFloat(store.latitude || '0');
        const storeLon = parseFloat(store.longitude || '0');
        
        // Skip stores without coordinates
        if (!store.latitude || !store.longitude || storeLat === 0 || storeLon === 0) {
          console.log(`[DEBUG] Skipping store ${store.name} - missing coordinates`);
          return null;
        }
        
        const distance = this.calculateDistance(userLat, userLon, storeLat, storeLon);
        console.log(`[DEBUG] Store ${store.name} distance: ${distance} km`);

        return {
          ...store,
          distance: Math.round(distance * 100) / 100 // Round to 2 decimal places
        };
      }).filter(store => store !== null) as (Store & { distance: number })[];

      console.log(`[DEBUG] Returning ${storesWithDistance.length} stores with valid coordinates`);
      return storesWithDistance.sort((a, b) => a.distance - b.distance);
    } catch (error) {
      console.error('Error getting stores with distance:', error);
      throw error;
    }
  }

  // Modern food delivery app: Get restaurants within 10km radius (default)
  async getFoodStoresWithinRadius(userLat: number, userLon: number, radiusKm: number = 10): Promise<(Store & { distance: number })[]> {
    try {
      console.log(`[DEBUG] getFoodStoresWithinRadius called with userLat: ${userLat}, userLon: ${userLon}, radius: ${radiusKm}km`);
      
      // Get all restaurant/food stores only - with database fallback
      const foodStores = await this.getAllStores();
      const restaurantStores = foodStores.filter(store => 
        store.storeType === 'restaurant' || 
        store.name.toLowerCase().includes('restaurant') ||
        store.name.toLowerCase().includes('pizza') ||
        store.name.toLowerCase().includes('burger') ||
        store.name.toLowerCase().includes('food')
      );
      
      console.log(`[DEBUG] Found ${restaurantStores.length} food stores from ${foodStores.length} total stores`);

      const storesWithDistance = restaurantStores.map((store) => {
        const storeLat = parseFloat(store.latitude || '0');
        const storeLon = parseFloat(store.longitude || '0');
        
        // Skip stores without coordinates
        if (!store.latitude || !store.longitude || storeLat === 0 || storeLon === 0) {
          console.log(`[DEBUG] Skipping food store ${store.name} - missing coordinates`);
          return null;
        }
        
        const distance = this.calculateDistance(userLat, userLon, storeLat, storeLon);
        
        // Filter by radius (10km default, like Uber Eats, DoorDash)
        if (distance > radiusKm) {
          console.log(`[DEBUG] Filtering out ${store.name} - ${distance}km exceeds ${radiusKm}km radius`);
          return null;
        }

        console.log(`[DEBUG] Food store ${store.name} within radius: ${distance}km`);
        return {
          ...store,
          distance: Math.round(distance * 100) / 100 // Round to 2 decimal places
        };
      }).filter(store => store !== null) as (Store & { distance: number })[];

      console.log(`[DEBUG] Returning ${storesWithDistance.length} food stores within ${radiusKm}km radius`);
      return storesWithDistance.sort((a, b) => a.distance - b.distance);
    } catch (error) {
      console.error('Error getting food stores within radius:', error);
      throw error;
    }
  }

  // Modern food delivery app: Get food items from restaurants within 10km radius
  async getFoodItemsWithinRadius(userLat: number, userLon: number, radiusKm: number = 10): Promise<(Product & { distance: number; storeName: string; storeAddress: string; deliveryTime?: string })[]> {
    try {
      console.log(`[DEBUG] getFoodItemsWithinRadius called with userLat: ${userLat}, userLon: ${userLon}, radius: ${radiusKm}km`);
      
      // Use memory storage fallback - get all products and stores
      const allProducts = await this.getAllProducts();
      const allStores = await this.getAllStores();
      
      // Filter to food products only
      const foodProducts = allProducts.filter(product => 
        product.productType === 'food' || 
        product.name.toLowerCase().includes('pizza') ||
        product.name.toLowerCase().includes('burger') ||
        product.name.toLowerCase().includes('sandwich') ||
        product.name.toLowerCase().includes('chicken') ||
        product.name.toLowerCase().includes('pasta') ||
        product.name.toLowerCase().includes('rice') ||
        product.name.toLowerCase().includes('noodles')
      );
      
      // Create food items with store information
      const foodItemsWithStores = foodProducts.map(product => {
        const store = allStores.find(s => s.id === product.storeId);
        if (!store) return null;
        
        return {
          ...product,
          storeName: store.name,
          storeAddress: store.address,
          storeLatitude: store.latitude,
          storeLongitude: store.longitude,
          deliveryTime: store.deliveryTime,
          storeType: store.storeType,
          cuisineType: store.cuisineType,
          isDeliveryAvailable: store.isActive
        };
      }).filter(item => item !== null);

      console.log(`[DEBUG] Found ${foodItemsWithStores.length} food items from restaurants`);

      const itemsWithDistance = foodItemsWithStores.map((item) => {
        const storeLat = parseFloat(item.storeLatitude || '0');
        const storeLon = parseFloat(item.storeLongitude || '0');
        
        // Skip items from stores without coordinates
        if (!item.storeLatitude || !item.storeLongitude || storeLat === 0 || storeLon === 0) {
          console.log(`[DEBUG] Skipping food item ${item.name} from ${item.storeName} - missing store coordinates`);
          return null;
        }
        
        const distance = this.calculateDistance(userLat, userLon, storeLat, storeLon);
        
        // Filter by radius (10km default, like modern food apps)
        if (distance > radiusKm) {
          return null;
        }

        // Transform to match Product type with additional fields
        return {
          id: item.id,
          name: item.name,
          slug: item.slug,
          description: item.description,
          price: item.price,
          originalPrice: item.originalPrice,
          categoryId: item.categoryId,
          storeId: item.storeId,
          stock: item.stock,
          imageUrl: item.imageUrl,
          images: item.images,
          rating: item.rating,
          totalReviews: item.totalReviews,
          isActive: item.isActive,
          isFastSell: item.isFastSell,
          isOnOffer: item.isOnOffer,
          offerPercentage: item.offerPercentage,
          offerEndDate: item.offerEndDate,
          productType: item.productType,
          preparationTime: item.preparationTime,
          ingredients: item.ingredients,
          allergens: item.allergens,
          spiceLevel: item.spiceLevel,
          isVegetarian: item.isVegetarian,
          isVegan: item.isVegan,
          nutritionInfo: item.nutritionInfo,
          createdAt: item.createdAt,
          // Additional fields for food delivery
          distance: Math.round(distance * 100) / 100,
          storeName: item.storeName,
          storeAddress: item.storeAddress,
          deliveryTime: item.deliveryTime,
        };
      }).filter(item => item !== null) as (Product & { distance: number; storeName: string; storeAddress: string; deliveryTime?: string })[];

      console.log(`[DEBUG] Returning ${itemsWithDistance.length} food items within ${radiusKm}km radius`);
      return itemsWithDistance.sort((a, b) => a.distance - b.distance);
    } catch (error) {
      console.error('Error getting food items within radius:', error);
      throw error;
    }
  }

  // Seller hub analytics
  async getSellerDashboardStats(storeId: number): Promise<{
    totalProducts: number;
    totalOrders: number;
    totalRevenue: number;
    pendingOrders: number;
    averageRating: number;
    totalReviews: number;
  }> {
    try {
      const [productsCount] = await db.select({ count: count() })
        .from(products)
        .where(eq(products.storeId, storeId));

      const storeOrders = await this.getOrdersByStoreId(storeId);
      const totalOrders = storeOrders.length;
      const pendingOrders = storeOrders.filter(order => order.status === 'pending').length;

      let totalRevenue = 0;
      for (const order of storeOrders) {
        if (order.status === 'delivered') {
          totalRevenue += parseFloat(order.totalAmount);
        }
      }

      const [store] = await db.select().from(stores).where(eq(stores.id, storeId));
      const averageRating = store ? parseFloat(store.rating) : 0;
      const totalReviews = store ? store.totalReviews : 0;

      return {
        totalProducts: productsCount.count,
        totalOrders,
        totalRevenue,
        pendingOrders,
        averageRating,
        totalReviews
      };
    } catch (error) {
      console.error('Error fetching seller dashboard stats:', error);
      return {
        totalProducts: 0,
        totalOrders: 0,
        totalRevenue: 0,
        pendingOrders: 0,
        averageRating: 0,
        totalReviews: 0
      };
    }
  }

  async getStoreAnalytics(storeId: number, days: number = 30): Promise<StoreAnalytics[]> {
    try {
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      return await db.select().from(storeAnalytics)
        .where(and(eq(storeAnalytics.storeId, storeId), gte(storeAnalytics.date, startDate)))
        .orderBy(desc(storeAnalytics.date));
    } catch {
      return [];
    }
  }

  async updateStoreAnalytics(data: InsertStoreAnalytics): Promise<StoreAnalytics> {
    const [analytics] = await db.insert(storeAnalytics).values(data).returning();
    return analytics;
  }

  // Promotions
  async getStorePromotions(storeId: number): Promise<Promotion[]> {
    try {
      return await db.select().from(promotions)
        .where(eq(promotions.storeId, storeId))
        .orderBy(desc(promotions.createdAt));
    } catch {
      return [];
    }
  }

  async createPromotion(promotion: InsertPromotion): Promise<Promotion> {
    const [newPromotion] = await db.insert(promotions).values(promotion).returning();
    return newPromotion;
  }

  async updatePromotion(id: number, updates: Partial<InsertPromotion>): Promise<Promotion | undefined> {
    try {
      const [updated] = await db.update(promotions).set(updates).where(eq(promotions.id, id)).returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async deletePromotion(id: number): Promise<boolean> {
    try {
      await db.delete(promotions).where(eq(promotions.id, id));
      return true;
    } catch {
      return false;
    }
  }

  // Advertisements
  async getStoreAdvertisements(storeId: number): Promise<Advertisement[]> {
    try {
      return await db.select().from(advertisements)
        .where(eq(advertisements.storeId, storeId))
        .orderBy(desc(advertisements.createdAt));
    } catch {
      return [];
    }
  }

  async createAdvertisement(ad: InsertAdvertisement): Promise<Advertisement> {
    const [newAd] = await db.insert(advertisements).values(ad).returning();
    return newAd;
  }

  async updateAdvertisement(id: number, updates: Partial<InsertAdvertisement>): Promise<Advertisement | undefined> {
    try {
      const [updated] = await db.update(advertisements).set(updates).where(eq(advertisements.id, id)).returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async deleteAdvertisement(id: number): Promise<boolean> {
    try {
      await db.delete(advertisements).where(eq(advertisements.id, id));
      return true;
    } catch {
      return false;
    }
  }

  // Product reviews
  async getProductReviews(productId: number): Promise<ProductReview[]> {
    try {
      return await db.select().from(productReviews)
        .where(eq(productReviews.productId, productId))
        .orderBy(desc(productReviews.createdAt));
    } catch {
      return [];
    }
  }

  async getStoreReviews(storeId: number): Promise<ProductReview[]> {
    try {
      return await db.select().from(productReviews)
        .where(eq(productReviews.storeId, storeId))
        .orderBy(desc(productReviews.createdAt));
    } catch {
      return [];
    }
  }

  async createProductReview(review: InsertProductReview): Promise<ProductReview> {
    console.log("Storage layer - creating review with data:", review);
    const [newReview] = await db.insert(productReviews).values(review).returning();
    return newReview;
  }

  async updateProductReview(id: number, updates: Partial<InsertProductReview>): Promise<ProductReview | undefined> {
    try {
      const [updated] = await db.update(productReviews).set(updates).where(eq(productReviews.id, id)).returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async deleteProductReview(id: number): Promise<boolean> {
    try {
      await db.delete(productReviews).where(eq(productReviews.id, id));
      return true;
    } catch {
      return false;
    }
  }

  async incrementReviewHelpfulCount(id: number): Promise<ProductReview | undefined> {
    try {
      const [updated] = await db
        .update(productReviews)
        .set({ helpfulCount: sql`${productReviews.helpfulCount} + 1` })
        .where(eq(productReviews.id, id))
        .returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async markReviewAsHelpful(reviewId: number, userId: number): Promise<{ alreadyLiked: boolean; helpfulCount: number }> {
    try {
      // Create the review_likes table if it doesn't exist
      await db.execute(sql`
        CREATE TABLE IF NOT EXISTS review_likes (
          id SERIAL PRIMARY KEY,
          review_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          created_at TIMESTAMP DEFAULT NOW() NOT NULL,
          UNIQUE(review_id, user_id)
        )
      `);

      // Check if user has already liked this review using raw SQL for better reliability
      const existingLikeResult = await db.execute(sql`
        SELECT COUNT(*) as count FROM review_likes 
        WHERE review_id = ${reviewId} AND user_id = ${userId}
      `);

      const existingCount = existingLikeResult.rows[0]?.count || 0;
      
      if (Number(existingCount) > 0) {
        // User has already liked this review, return current count
        const currentReview = await db.select().from(productReviews).where(eq(productReviews.id, reviewId)).limit(1);
        return {
          alreadyLiked: true,
          helpfulCount: currentReview[0]?.helpfulCount || 0
        };
      }

      // Record the like using raw SQL to handle potential constraint violations
      try {
        await db.execute(sql`
          INSERT INTO review_likes (review_id, user_id) 
          VALUES (${reviewId}, ${userId})
          ON CONFLICT (review_id, user_id) DO NOTHING
        `);
      } catch (insertError) {
        console.log("Insert error (possibly duplicate):", insertError);
        // If insert fails due to duplicate, check current count and return
        const currentReview = await db.select().from(productReviews).where(eq(productReviews.id, reviewId)).limit(1);
        return {
          alreadyLiked: true,
          helpfulCount: currentReview[0]?.helpfulCount || 0
        };
      }

      // Increment the helpful count
      const [updated] = await db
        .update(productReviews)
        .set({ helpfulCount: sql`${productReviews.helpfulCount} + 1` })
        .where(eq(productReviews.id, reviewId))
        .returning();

      return {
        alreadyLiked: false,
        helpfulCount: updated?.helpfulCount || 0
      };
    } catch (error) {
      console.error("Error marking review as helpful:", error);
      throw error;
    }
  }

  // Store reviews
  async getStoreReviewsByStoreId(storeId: number): Promise<StoreReview[]> {
    try {
      return await db.select().from(storeReviews)
        .where(eq(storeReviews.storeId, storeId))
        .orderBy(desc(storeReviews.createdAt));
    } catch {
      return [];
    }
  }

  async createStoreReview(review: InsertStoreReview): Promise<StoreReview> {
    try {
      console.log("Storage layer - creating store review with data:", review);
      const [newReview] = await db.insert(storeReviews).values(review).returning();
      console.log("Storage layer - new review created:", newReview);
      
      // Update store rating after creating a review
      await this.updateStoreRating(review.storeId);
      
      return newReview;
    } catch (error) {
      console.error("Error in createStoreReview:", error);
      throw error;
    }
  }

  async updateStoreReview(id: number, updates: Partial<InsertStoreReview>): Promise<StoreReview | undefined> {
    try {
      const [updated] = await db.update(storeReviews).set(updates).where(eq(storeReviews.id, id)).returning();
      
      if (updated) {
        // Update store rating after updating a review
        await this.updateStoreRating(updated.storeId);
      }
      
      return updated;
    } catch {
      return undefined;
    }
  }

  async deleteStoreReview(id: number): Promise<boolean> {
    try {
      // Get the store ID before deleting
      const [reviewToDelete] = await db.select().from(storeReviews).where(eq(storeReviews.id, id));
      
      if (reviewToDelete) {
        await db.delete(storeReviews).where(eq(storeReviews.id, id));
        
        // Update store rating after deleting a review
        await this.updateStoreRating(reviewToDelete.storeId);
        
        return true;
      }
      
      return false;
    } catch {
      return false;
    }
  }

  async updateStoreRating(storeId: number): Promise<void> {
    try {
      console.log(`🔄 Updating rating for store ${storeId}...`);
      
      // Calculate average rating and total reviews for the store using only approved reviews
      const ratingResult = await db
        .select({
          avgRating: sql<string>`COALESCE(AVG(${storeReviews.rating})::NUMERIC(3,2), 0.00)`.as('avgRating'),
          totalReviews: sql<string>`COUNT(${storeReviews.id})`.as('totalReviews')
        })
        .from(storeReviews)
        .where(and(
          eq(storeReviews.storeId, storeId),
          eq(storeReviews.isApproved, true)
        ));

      const avgRating = ratingResult[0]?.avgRating ? parseFloat(ratingResult[0].avgRating) : 0;
      const totalReviews = ratingResult[0]?.totalReviews ? parseInt(ratingResult[0].totalReviews) : 0;

      console.log(`📊 Store ${storeId} calculated stats: ${avgRating} stars, ${totalReviews} reviews`);

      // Update the store's rating and totalReviews with proper decimal formatting
      await db.update(stores)
        .set({
          rating: avgRating.toFixed(1),
          totalReviews: totalReviews
        })
        .where(eq(stores.id, storeId));
        
      console.log(`✅ Updated store ${storeId} rating to ${avgRating.toFixed(1)} with ${totalReviews} reviews`);
    } catch (error) {
      console.error("Error updating store rating:", error);
      throw error;
    }
  }

  // Store review likes
  async getStoreReviewLikes(reviewId: number): Promise<StoreReviewLike[]> {
    try {
      return await db.select().from(storeReviewLikes)
        .where(eq(storeReviewLikes.reviewId, reviewId))
        .orderBy(desc(storeReviewLikes.createdAt));
    } catch {
      return [];
    }
  }

  async createStoreReviewLike(like: InsertStoreReviewLike): Promise<StoreReviewLike> {
    const [newLike] = await db.insert(storeReviewLikes).values(like).returning();
    
    // Increment helpful count on the store review
    await db.update(storeReviews)
      .set({ helpfulCount: sql`${storeReviews.helpfulCount} + 1` })
      .where(eq(storeReviews.id, like.reviewId));
    
    return newLike;
  }

  async deleteStoreReviewLike(reviewId: number, userId: number): Promise<boolean> {
    try {
      const result = await db.delete(storeReviewLikes)
        .where(and(
          eq(storeReviewLikes.reviewId, reviewId),
          eq(storeReviewLikes.userId, userId)
        ))
        .returning();
      
      if (result.length > 0) {
        // Decrement helpful count on the store review
        await db.update(storeReviews)
          .set({ helpfulCount: sql`${storeReviews.helpfulCount} - 1` })
          .where(eq(storeReviews.id, reviewId));
        
        return true;
      }
      
      return false;
    } catch {
      return false;
    }
  }

  async hasUserLikedStoreReview(reviewId: number, userId: number): Promise<boolean> {
    try {
      const [like] = await db.select().from(storeReviewLikes)
        .where(and(
          eq(storeReviewLikes.reviewId, reviewId),
          eq(storeReviewLikes.userId, userId)
        ))
        .limit(1);
      
      return !!like;
    } catch {
      return false;
    }
  }

  // Settlements
  async getStoreSettlements(storeId: number): Promise<Settlement[]> {
    try {
      return await db.select().from(settlements)
        .where(eq(settlements.storeId, storeId))
        .orderBy(desc(settlements.createdAt));
    } catch {
      return [];
    }
  }

  async createSettlement(settlement: InsertSettlement): Promise<Settlement> {
    const [newSettlement] = await db.insert(settlements).values(settlement).returning();
    return newSettlement;
  }

  async updateSettlement(id: number, updates: Partial<InsertSettlement>): Promise<Settlement | undefined> {
    try {
      const [updated] = await db.update(settlements).set(updates).where(eq(settlements.id, id)).returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  // Inventory management
  async getInventoryLogs(storeId: number, productId?: number): Promise<InventoryLog[]> {
    try {
      let query = db.select().from(inventoryLogs).where(eq(inventoryLogs.storeId, storeId));

      if (productId) {
        query = query.where(eq(inventoryLogs.productId, productId));
      }

      return await query.orderBy(desc(inventoryLogs.createdAt));
    } catch {
      return [];
    }
  }

  async createInventoryLog(log: InsertInventoryLog): Promise<InventoryLog> {
    const [newLog] = await db.insert(inventoryLogs).values(log).returning();
    return newLog;
  }

  async updateProductStock(productId: number, quantity: number, type: string, reason?: string): Promise<boolean> {
    try {
      const product = await this.getProduct(productId);
      if (!product) return false;

      let newStock = product.stock;
      if (type === 'add') {
        newStock += quantity;
      } else if (type === 'subtract') {
        newStock -= quantity;
        if (newStock < 0) newStock = 0;
      } else if (type === 'set') {
        newStock = quantity;
      }

      await db.update(products)
        .set({ stock: newStock })
        .where(eq(products.id, productId));

      // Create inventory log
      await this.createInventoryLog({
        productId,
        storeId: product.storeId,
        type,
        quantity,
        reason: reason || `Stock ${type}`,
        previousStock: product.stock,
        newStock,
        createdAt: new Date()
      });

      return true;
    } catch {
      return false;
    }
  }

  // Enhanced admin management methods
  async getAllOrders(): Promise<Order[]> {
    try {
      return await db.select().from(orders).orderBy(desc(orders.createdAt));
    } catch {
      return [];
    }
  }

  async getAllTransactions(): Promise<PaymentTransaction[]> {
    try {
      return await db.select().from(paymentTransactions).orderBy(desc(paymentTransactions.createdAt));
    } catch {
      return [];
    }
  }

  async getAllCoupons(): Promise<Coupon[]> {
    try {
      return await db.select().from(coupons).orderBy(desc(coupons.createdAt));
    } catch {
      return [];
    }
  }

  async createCoupon(coupon: InsertCoupon): Promise<Coupon> {
    const [newCoupon] = await db.insert(coupons).values(coupon).returning();
    return newCoupon;
  }

  async updateCoupon(id: number, updates: Partial<InsertCoupon>): Promise<Coupon | undefined> {
    try {
      const [updated] = await db.update(coupons).set(updates).where(eq(coupons.id, id)).returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async deleteCoupon(id: number): Promise<boolean> {
    try {
      await db.delete(coupons).where(eq(coupons.id, id));
      return true;
    } catch {
      return false;
    }
  }

  // Flash Sales operations
  async getAllFlashSales(): Promise<FlashSale[]> {
    try {
      return await db.select().from(flashSales).orderBy(desc(flashSales.createdAt));
    } catch {
      return [];
    }
  }

  async getActiveFlashSales(): Promise<FlashSale[]> {
    try {
      const now = new Date();
      return await db.select()
        .from(flashSales)
        .where(
          and(
            eq(flashSales.isActive, true),
            lte(flashSales.startsAt, now),
            gt(flashSales.endsAt, now)
          )
        )
        .orderBy(desc(flashSales.createdAt));
    } catch {
      return [];
    }
  }

  async getFlashSale(id: number): Promise<FlashSale | undefined> {
    try {
      const [flashSale] = await db.select().from(flashSales).where(eq(flashSales.id, id));
      return flashSale;
    } catch {
      return undefined;
    }
  }

  async createFlashSale(flashSale: InsertFlashSale): Promise<FlashSale> {
    const [newFlashSale] = await db.insert(flashSales).values(flashSale).returning();
    return newFlashSale;
  }

  async updateFlashSale(id: number, updates: Partial<InsertFlashSale>): Promise<FlashSale | undefined> {
    try {
      const [updated] = await db.update(flashSales).set(updates).where(eq(flashSales.id, id)).returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async deleteFlashSale(id: number): Promise<boolean> {
    try {
      await db.delete(flashSales).where(eq(flashSales.id, id));
      return true;
    } catch {
      return false;
    }
  }

  async getFlashSaleProducts(flashSaleId: number): Promise<Product[]> {
    try {
      // Get current flash sale
      const flashSale = await this.getFlashSale(flashSaleId);
      if (!flashSale || !flashSale.isActive) {
        return [];
      }

      const now = new Date();
      if (flashSale.startsAt > now || flashSale.endsAt < now) {
        return [];
      }

      // Return products marked as fast sell that could be part of flash sales
      return await db.select()
        .from(products)
        .where(
          and(
            eq(products.isActive, true),
            eq(products.isFastSell, true)
          )
        )
        .orderBy(desc(products.createdAt));
    } catch {
      return [];
    }
  }

  async getAllBanners(): Promise<Banner[]> {
    try {
      return await db.select().from(banners).orderBy(desc(banners.createdAt));
    } catch {
      return [];
    }
  }

  async createBanner(banner: InsertBanner): Promise<Banner> {
    const [newBanner] = await db.insert(banners).values(banner).returning();
    return newBanner;
  }

  async updateBanner(id: number, updates: Partial<InsertBanner>): Promise<Banner | undefined> {
    try {
      const [updated] = await db.update(banners).set(updates).where(eq(banners.id, id)).returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async deleteBanner(id: number): Promise<boolean> {
    try {
      await db.delete(banners).where(eq(banners.id, id));
      return true;
    } catch {
      return false;
    }
  }

  async getAllSupportTickets(): Promise<SupportTicket[]> {
    try {
      return await db.select().from(supportTickets).orderBy(desc(supportTickets.createdAt));
    } catch {
      return [];
    }
  }

  async createSupportTicket(ticket: InsertSupportTicket): Promise<SupportTicket> {
    const [newTicket] = await db.insert(supportTickets).values(ticket).returning();
    return newTicket;
  }

  async updateSupportTicket(id: number, updates: Partial<InsertSupportTicket>): Promise<SupportTicket | undefined> {
    try {
      const [updated] = await db.update(supportTickets).set(updates).where(eq(supportTickets.id, id)).returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async getAllSiteSettings(): Promise<SiteSetting[]> {
    try {
      return await db.select().from(siteSettings);
    } catch {
      return [];
    }
  }

  async updateSiteSetting(key: string, value: string): Promise<SiteSetting | undefined> {
    try {
      const [updated] = await db.update(siteSettings)
        .set({ value })
        .where(eq(siteSettings.key, key))
        .returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  // Enhanced admin features
  async getDashboardStats(): Promise<any> {
    try {
      const [totalUsers, totalStores, totalOrders, pendingOrders, activeUsers] = await Promise.all([
        this.getTotalUsersCount(),
        this.getTotalStoresCount(),
        this.getTotalOrdersCount(),
        this.getPendingOrdersCount(),
        this.getActiveUsersCount()
      ]);

      const totalRevenue = await this.getTotalRevenue();

      return {
        totalUsers,
        totalStores,
        totalOrders,
        totalRevenue,
        pendingOrders,
        activeUsers
      };
    } catch {
      return {
        totalUsers: 0,
        totalStores: 0,
        totalOrders: 0,
        totalRevenue: 0,
        pendingOrders: 0,
        activeUsers: 0
      };
    }
  }

  async getAllVendorVerifications(): Promise<VendorVerification[]> {
    try {
      return await db.select().from(vendorVerifications).orderBy(desc(vendorVerifications.createdAt));
    } catch {
      return [];
    }
  }

  async updateVendorVerification(id: number, updates: Partial<InsertVendorVerification>): Promise<VendorVerification | undefined> {
    try {
      const [updated] = await db.update(vendorVerifications).set(updates).where(eq(vendorVerifications.id, id)).returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async approveVendorVerification(id: number, adminId: number): Promise<VendorVerification | undefined> {
    try {
      const [updated] = await db.update(vendorVerifications)
        .set({ 
          status: 'approved',
          reviewedBy: adminId,
          reviewedAt: new Date()
        })
        .where(eq(vendorVerifications.id, id))
        .returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async rejectVendorVerification(id: number, adminId: number, reason: string): Promise<VendorVerification | undefined> {
    try {
      const [updated] = await db.update(vendorVerifications)
        .set({ 
          status: 'rejected',
          reviewedBy: adminId,
          reviewedAt: new Date(),
          rejectionReason: reason
        })
        .where(eq(vendorVerifications.id, id))
        .returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async getAllFraudAlerts(): Promise<FraudAlert[]> {
    try {
      return await db.select().from(fraudAlerts).orderBy(desc(fraudAlerts.createdAt));
    } catch {
      return [];
    }
  }

  async createFraudAlert(alert: InsertFraudAlert): Promise<FraudAlert> {
    const [newAlert] = await db.insert(fraudAlerts).values(alert).returning();
    return newAlert;
  }

  async updateFraudAlert(id: number, updates: Partial<InsertFraudAlert>): Promise<FraudAlert | undefined> {
    try {
      const [updated] = await db.update(fraudAlerts).set(updates).where(eq(fraudAlerts.id, id)).returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async updateFraudAlertStatus(id: number, status: string): Promise<FraudAlert | undefined> {
    try {
      const [updated] = await db.update(fraudAlerts)
        .set({ status })
        .where(eq(fraudAlerts.id, id))
        .returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async getCommissions(status?: string): Promise<Commission[]> {
    try {
      let query = db.select().from(commissions);

      if (status) {
        query = query.where(eq(commissions.status, status));
      }

      return await query;
    } catch {
      return [];
    }
  }

  async updateCommissionStatus(id: number, status: string): Promise<Commission | undefined> {
    try {
      const [updated] = await db.update(commissions)
        .set({ status })
        .where(eq(commissions.id, id))
        .returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  // Dashboard statistics methods
  async getTotalUsersCount(): Promise<number> {
    try {
      const result = await db.select({ count: count() }).from(users);
      return result[0]?.count || 0;
    } catch {
      return 0;
    }
  }

  async getTotalStoresCount(): Promise<number> {
    try {
      const result = await db.select({ count: count() }).from(stores);
      return result[0]?.count || 0;
    } catch {
      return 0;
    }
  }

  async getTotalOrdersCount(): Promise<number> {
    try {
      const result = await db.select({ count: count() }).from(orders);
      return result[0]?.count || 0;
    } catch {
      return 0;
    }
  }

  async getTotalRevenue(): Promise<number> {
    try {
      const result = await db.select({
        total: sql`sum(${orders.totalAmount})`
      }).from(orders).where(eq(orders.status, 'delivered'));

      return parseFloat(result[0]?.total || '0');
    } catch {
      return 0;
    }
  }

  async getPendingOrdersCount(): Promise<number> {
    try {
      const result = await db.select({ count: count() })
        .from(orders)
        .where(eq(orders.status, 'pending'));
      return result[0]?.count || 0;
    } catch {
      return 0;
    }
  }

  async getActiveUsersCount(): Promise<number> {
    try {
      const result = await db.select({ count: count() })
        .from(users)
        .where(eq(users.status, 'active'));
      return result[0]?.count || 0;
    } catch {
      return 0;
    }
  }

  async getPendingVendorVerificationsCount(): Promise<number> {
    try {
      const result = await db.select({ count: count() })
        .from(vendorVerifications)
        .where(eq(vendorVerifications.status, 'pending'));
      return result[0]?.count || 0;
    } catch {
      return 0;
    }
  }

  async getOpenFraudAlertsCount(): Promise<number> {
    try {
      const result = await db.select({ count: count() })
        .from(fraudAlerts)
        .where(eq(fraudAlerts.status, 'open'));
      return result[0]?.count || 0;
    } catch {
      return 0;
    }
  }

  async getAllCommissions(): Promise<Commission[]> {
    try {
      return await db.select().from(commissions).orderBy(commissions.createdAt);
    } catch {
      return [];
    }
  }

  async createCommission(commission: InsertCommission): Promise<Commission> {
    const [newCommission] = await db.insert(commissions).values(commission).returning();
    return newCommission;
  }

  async updateCommission(id: number, updates: Partial<InsertCommission>): Promise<Commission | undefined> {
    try {
      const [updated] = await db.update(commissions).set(updates).where(eq(commissions.id, id)).returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async getProductAttributes(productId: number): Promise<ProductAttribute[]> {
    try {
      return await db.select().from(productAttributes).where(eq(productAttributes.productId, productId));
    } catch {
      return [];
    }
  }

  async createProductAttribute(attribute: InsertProductAttribute): Promise<ProductAttribute> {
    const [newAttribute] = await db.insert(productAttributes).values(attribute).returning();
    return newAttribute;
  }

  async deleteProductAttribute(id: number): Promise<boolean> {
    try {
      await db.delete(productAttributes).where(eq(productAttributes.id, id));
      return true;
    } catch {
      return false;
    }
  }

  async logAdminAction(log: InsertAdminLog): Promise<AdminLog> {
    const [newLog] = await db.insert(adminLogs).values(log).returning();
    return newLog;
  }

  async getAdminLogs(adminId?: number): Promise<AdminLog[]> {
    try {
      if (adminId) {
        return await db.select().from(adminLogs).where(eq(adminLogs.adminId, adminId)).orderBy(desc(adminLogs.createdAt));
      }
      return await db.select().from(adminLogs).orderBy(desc(adminLogs.createdAt));
    } catch {
      return [];
    }
  }

  async bulkUpdateProductStatus(productIds: number[], status: boolean): Promise<boolean> {
    try {
      await db.update(products).set({ isActive: status }).where(inArray(products.id, productIds));
      return true;
    } catch {
      return false;
    }
  }

  async getOrdersWithDetails(): Promise<any[]> {
    try {
      return await db.select().from(orders).orderBy(desc(orders.createdAt));
    } catch {
      return [];
    }
  }

  async getRevenueAnalytics(days: number = 30): Promise<any> {
    try {
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      const result = await db.select({
        total: sql`sum(${orders.totalAmount})`,
        count: count()
      }).from(orders).where(and(
        gte(orders.createdAt, startDate),
        eq(orders.status, 'delivered')
      ));

      return {
        totalRevenue: parseFloat(result[0]?.total || '0'),
        totalOrders: result[0]?.count || 0
      };
    } catch {
      return { totalRevenue: 0, totalOrders: 0 };
    }
  }

  async getUsersAnalytics(): Promise<any> {
    try {
      const [total, active, pending] = await Promise.all([
        db.select({ count: count() }).from(users),
        db.select({ count: count() }).from(users).where(eq(users.status, 'active')),
        db.select({ count: count() }).from(users).where(eq(users.status, 'pending'))
      ]);

      return {
        total: total[0]?.count || 0,
        active: active[0]?.count || 0,
        pending: pending[0]?.count || 0
      };
    } catch {
      return { total: 0, active: 0, pending: 0 };
    }
  }

  async getInventoryAlerts(): Promise<any[]> {
    try {
      return await db.select().from(products).where(sql`${products.stock} < 10`);
    } catch {
      return [];
    }
  }

  // Delivery partner operations
  async getDeliveryPartner(id: number): Promise<DeliveryPartner | undefined> {
    try {
      const [partner] = await db.select().from(deliveryPartners).where(eq(deliveryPartners.id, id));
      return partner;
    } catch {
      return undefined;
    }
  }

  async getDeliveryPartnerByUserId(userId: number): Promise<DeliveryPartner | undefined> {
    try {
      const [partner] = await db.select().from(deliveryPartners).where(eq(deliveryPartners.userId, userId));
      return partner;
    } catch {
      return undefined;
    }
  }

  async getAllDeliveryPartners(): Promise<DeliveryPartner[]> {
    try {
      return await db.select().from(deliveryPartners).orderBy(desc(deliveryPartners.createdAt));
    } catch {
      return [];
    }
  }

  async getPendingDeliveryPartners(): Promise<DeliveryPartner[]> {
    try {
      return await db.select().from(deliveryPartners).where(eq(deliveryPartners.status, 'pending'));
    } catch {
      return [];
    }
  }

  async createDeliveryPartner(deliveryPartner: InsertDeliveryPartner): Promise<DeliveryPartner> {
    const [newPartner] = await db.insert(deliveryPartners).values(deliveryPartner).returning();
    return newPartner;
  }

  async updateDeliveryPartner(id: number, updates: Partial<InsertDeliveryPartner>): Promise<DeliveryPartner | undefined> {
    try {
      const [updated] = await db.update(deliveryPartners).set(updates).where(eq(deliveryPartners.id, id)).returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async updateDeliveryPartnerDocuments(id: number, documentData: any): Promise<DeliveryPartner | undefined> {
    try {
      const [updated] = await db.update(deliveryPartners)
        .set({
          idProofUrl: documentData.idProofUrl,
          drivingLicenseUrl: documentData.drivingLicenseUrl,
          vehicleRegistrationUrl: documentData.vehicleRegistrationUrl,
          insuranceUrl: documentData.insuranceUrl,
          photoUrl: documentData.photoUrl
        })
        .where(eq(deliveryPartners.id, id))
        .returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async approveDeliveryPartner(id: number, adminId: number): Promise<DeliveryPartner | undefined> {
    try {
      // First, get the delivery partner to find the associated user
      const partner = await db.select().from(deliveryPartners).where(eq(deliveryPartners.id, id)).limit(1);
      
      if (!partner || partner.length === 0) {
        return undefined;
      }

      const userId = partner[0].userId;

      // Update delivery partner status
      const [updated] = await db.update(deliveryPartners)
        .set({ 
          status: 'approved',
          approvedBy: adminId,
          approvedAt: new Date()
        })
        .where(eq(deliveryPartners.id, id))
        .returning();

      // Also update the user's status to 'active' so they can login properly
      await db.update(users)
        .set({ 
          status: 'active',
          updatedAt: new Date()
        })
        .where(eq(users.id, userId));

      return updated;
    } catch (error) {
      console.error('Error approving delivery partner:', error);
      return undefined;
    }
  }

  async rejectDeliveryPartner(id: number, adminId: number, reason: string): Promise<DeliveryPartner | undefined> {
    try {
      // First, get the delivery partner to find the associated user
      const partner = await db.select().from(deliveryPartners).where(eq(deliveryPartners.id, id)).limit(1);
      
      if (!partner || partner.length === 0) {
        return undefined;
      }

      const userId = partner[0].userId;

      // Update delivery partner status
      const [updated] = await db.update(deliveryPartners)
        .set({ 
          status: 'rejected',
          approvedBy: adminId,
          approvedAt: new Date(),
          rejectionReason: reason
        })
        .where(eq(deliveryPartners.id, id))
        .returning();

      // Also update the user's status to 'rejected' for consistency
      await db.update(users)
        .set({ 
          status: 'rejected',
          updatedAt: new Date()
        })
        .where(eq(users.id, userId));

      return updated;
    } catch (error) {
      console.error('Error rejecting delivery partner:', error);
      return undefined;
    }
  }

  // Delivery operations
  async getDelivery(id: number): Promise<Delivery | undefined> {
    try {
      const [delivery] = await db.select().from(deliveries).where(eq(deliveries.id, id));
      return delivery;
    } catch {
      return undefined;
    }
  }

  async getDeliveriesByPartnerId(partnerId: number): Promise<Delivery[]> {
    try {
      return await db.select().from(deliveries).where(eq(deliveries.deliveryPartnerId, partnerId));
    } catch {
      return [];
    }
  }

  async getActiveDeliveries(partnerId: number): Promise<Delivery[]> {
    try {
      return await db.select().from(deliveries).where(
        and(
          eq(deliveries.deliveryPartnerId, partnerId),
          sql`${deliveries.status} IN ('assigned', 'picked_up', 'in_transit')`
        )
      );
    } catch {
      return [];
    }
  }

  async getDeliveriesByOrderId(orderId: number): Promise<Delivery[]> {
    try {
      return await db.select().from(deliveries).where(eq(deliveries.orderId, orderId));
    } catch {
      return [];
    }
  }

  async getPendingDeliveries(): Promise<Delivery[]> {
    try {
      return await db.select().from(deliveries).where(eq(deliveries.status, 'pending'));
    } catch {
      return [];
    }
  }

  async createDelivery(delivery: InsertDelivery): Promise<Delivery> {
    const [newDelivery] = await db.insert(deliveries).values(delivery).returning();
    return newDelivery;
  }

  async updateDeliveryStatus(id: number, status: string, partnerId?: number): Promise<Delivery | undefined> {
    try {
      const updates: any = { status };
      if (partnerId) updates.deliveryPartnerId = partnerId;

      const [updated] = await db.update(deliveries).set(updates).where(eq(deliveries.id, id)).returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async assignDeliveryToPartner(deliveryId: number, partnerId: number): Promise<Delivery | undefined> {
    try {
      const [updated] = await db.update(deliveries)
        .set({ 
          deliveryPartnerId: partnerId,
          status: 'assigned',
          assignedAt: new Date()
        })
        .where(eq(deliveries.id, deliveryId))
        .returning();
      return updated;
    } catch {
      return undefined;
    }
  }

  async getActiveDeliveriesForStore(storeId: number): Promise<any[]> {
    try {
      return await db.select().from(deliveries)
        .where(and(
          eq(deliveries.storeId, storeId),
          sql`${deliveries.status} NOT IN ('delivered', 'cancelled')`
        ));
    } catch {
      return [];
    }
  }

  // Delivery tracking
  async getDeliveryTrackingData(deliveryId: number): Promise<any> {
    try {
      const [delivery] = await db.select().from(deliveries).where(eq(deliveries.id, deliveryId));
      return delivery;
    } catch {
      return null;
    }
  }

  async updateDeliveryLocation(deliveryId: number, latitude: number, longitude: number): Promise<void> {
    try {
      await db.update(deliveries)
        .set({ 
          currentLatitude: latitude.toString(),
          currentLongitude: longitude.toString(),
          updatedAt: new Date()
        })
        .where(eq(deliveries.id, deliveryId));
    } catch (error) {
      console.error('Failed to update delivery location:', error);
    }
  }

  // Delivery Zone methods
  async createDeliveryZone(data: InsertDeliveryZone): Promise<DeliveryZone> {
    const [newZone] = await db.insert(deliveryZones).values(data).returning();
    return newZone;
  }

  async getDeliveryZones(): Promise<DeliveryZone[]> {
    try {
      return await db.select().from(deliveryZones).orderBy(deliveryZones.minDistance);
    } catch {
      return [];
    }
  }

  async getAllDeliveryZones(): Promise<DeliveryZone[]> {
    try {
      return await db.select().from(deliveryZones).orderBy(deliveryZones.minDistance);
    } catch {
      return [];
    }
  }

  async updateDeliveryZone(id: number, data: Partial<InsertDeliveryZone>): Promise<DeliveryZone> {
    const [updated] = await db.update(deliveryZones).set(data).where(eq(deliveryZones.id, id)).returning();
    return updated;
  }

  async deleteDeliveryZone(id: number): Promise<void> {
    await db.delete(deliveryZones).where(eq(deliveryZones.id, id));
  }

  async calculateDeliveryFee(distance: number): Promise<{ fee: number; zone: DeliveryZone | null }> {
    try {
      const zones = await this.getDeliveryZones();

      for (const zone of zones) {
        if (distance >= zone.minDistance && distance <= zone.maxDistance) {
          return { fee: parseFloat(zone.deliveryFee), zone };
        }
      }

      return { fee: 0, zone: null };
    } catch {
      return { fee: 0, zone: null };
    }
  }

  // Admin profile management methods
  async getAdminProfile(adminId: number): Promise<any> {
    try {
      const [admin] = await db.select().from(adminUsers).where(eq(adminUsers.id, adminId));
      return admin;
    } catch {
      return null;
    }
  }

  async updateAdminProfile(adminId: number, updates: any): Promise<any> {
    try {
      const [updated] = await db.update(adminUsers)
        .set({ ...updates, updatedAt: new Date() })
        .where(eq(adminUsers.id, adminId))
        .returning();
      return updated;
    } catch {
      return null;
    }
  }

  async verifyAdminPassword(adminId: number, password: string): Promise<boolean> {
    try {
      const [admin] = await db.select().from(adminUsers).where(eq(adminUsers.id, adminId));
      if (!admin) return false;

      // In a real application, you would hash the password and compare
      // For now, we'll do a simple comparison (not secure for production)
      return admin.password === password;
    } catch {
      return false;
    }
  }

  async changeAdminPassword(adminId: number, currentPassword: string, newPassword: string): Promise<boolean> {
    try {
      // Verify current password
      const isCurrentPasswordValid = await this.verifyAdminPassword(adminId, currentPassword);
      if (!isCurrentPasswordValid) {
        return false;
      }

      // Update password
      await db.update(adminUsers)
        .set({ password: newPassword, updatedAt: new Date() })
        .where(eq(adminUsers.id, adminId));

      return true;
    } catch {
      return false;
    }
  }

  async authenticateAdmin(email: string, password: string): Promise<AdminUser | null> {
    try {
      console.log('Authenticating admin:', email);
      
      // First try adminUsers table
      try {
        const [admin] = await db.select()
          .from(adminUsers)
          .where(eq(adminUsers.email, email))
          .limit(1);

        if (admin) {
          console.log('Found admin in adminUsers:', admin.email, 'Active:', admin.isActive);
          
          // Check if admin is active and password matches
          if (admin.isActive && admin.password === password) {
            console.log('Authentication successful');
            return admin;
          }
        }
      } catch (adminUsersError) {
        console.log('AdminUsers table query failed, trying admins table:', adminUsersError.message);
      }

      // Fallback to admins table
      try {
        const [admin] = await db.select()
          .from(admins)
          .where(eq(admins.email, email))
          .limit(1);

        if (admin && admin.isActive && admin.password === password) {
          console.log('Authentication successful via admins table');
          // Convert to AdminUser format
          return {
            id: admin.id,
            email: admin.email,
            password: admin.password,
            fullName: admin.fullName,
            role: admin.role,
            isActive: admin.isActive,
            createdAt: admin.createdAt,
            updatedAt: new Date()
          };
        }
      } catch (adminsError) {
        console.log('Admins table query failed:', adminsError.message);
      }

      console.log('Authentication failed - user not found or invalid credentials');
      return null;
    } catch (error) {
      console.error('Admin authentication error:', error);
      return null;
    }
  }

  async createDefaultAdmin(): Promise<AdminUser | null> {
    try {
      // Check if default admin already exists in adminUsers table
      const existingAdmin = await db.select()
        .from(adminUsers)
        .where(eq(adminUsers.email, 'admin@sirahbazaar.com'))
        .limit(1);

      if (existingAdmin.length === 0) {
        // Create default admin in adminUsers table
        const [newAdmin] = await db.insert(adminUsers).values({
          email: 'admin@sirahbazaar.com',
          password: 'admin123', // In production, this should be hashed
          fullName: 'System Administrator',
          role: 'super_admin',
          isActive: true
        }).returning();
        console.log('✅ Default admin account created: admin@sirahbazaar.com / admin123');
        return newAdmin;
      } else {
        console.log('✅ Default admin account already exists');
        return existingAdmin[0];
      }

      // Also ensure the old admins table has the admin if it exists
      try {
        const existingOldAdmin = await db.select()
          .from(admins)
          .where(eq(admins.email, 'admin@sirahbazaar.com'))
          .limit(1);

        if (existingOldAdmin.length === 0) {
          await db.insert(admins).values({
            email: 'admin@sirahbazaar.com',
            password: 'admin123',
            fullName: 'System Administrator',
            role: 'super_admin',
            isActive: true,
            createdAt: new Date()
          });
        }
      } catch (error) {
        // Ignore errors for the old admins table if it doesn't exist
        console.log('Old admins table not found or error inserting, continuing...');
      }
    } catch (error) {
      console.error('Error creating default admin:', error);
      return null;
    }
  }

  // Device token management methods for Firebase FCM
  async saveDeviceToken(userId: number, token: string, deviceType: string): Promise<boolean> {
    try {
      const existing = await db.select()
        .from(pushNotificationTokens)
        .where(and(eq(pushNotificationTokens.userId, userId), eq(pushNotificationTokens.token, token)))
        .limit(1);

      if (existing.length === 0) {
        await db.insert(pushNotificationTokens).values({
          userId,
          token,
          deviceType,
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date()
        });
      } else {
        await db.update(pushNotificationTokens)
          .set({ 
            isActive: true, 
            deviceType,
            updatedAt: new Date() 
          })
          .where(and(eq(pushNotificationTokens.userId, userId), eq(pushNotificationTokens.token, token)));
      }
      
      return true;
    } catch (error) {
      console.error('Error saving device token:', error);
      return false;
    }
  }

  async removeDeviceToken(userId: number, token: string): Promise<boolean> {
    try {
      await db.update(pushNotificationTokens)
        .set({ isActive: false, updatedAt: new Date() })
        .where(and(eq(pushNotificationTokens.userId, userId), eq(pushNotificationTokens.token, token)));
      
      return true;
    } catch (error) {
      console.error('Error removing device token:', error);
      return false;
    }
  }

  async getDeviceTokensByUserId(userId: number): Promise<string[]> {
    try {
      const tokens = await db.select({ token: pushNotificationTokens.token })
        .from(pushNotificationTokens)
        .where(and(eq(pushNotificationTokens.userId, userId), eq(pushNotificationTokens.isActive, true)));
      
      return tokens.map(t => t.token);
    } catch (error) {
      console.error('Error getting device tokens by user ID:', error);
      return [];
    }
  }

  async getDeviceTokensByUserIds(userIds: number[]): Promise<string[]> {
    try {
      if (userIds.length === 0) return [];
    
      const tokens = await db.select({ token: pushNotificationTokens.token })
        .from(pushNotificationTokens)
        .where(and(
          inArray(pushNotificationTokens.userId, userIds),
          eq(pushNotificationTokens.isActive, true)
        ));
      
      return tokens.map(t => t.token);
    } catch (error) {
      console.error('Error getting device tokens by user IDs:', error);
      return [];
    }
  }

  async getDeviceTokensByUser(userId: number, deviceType?: string): Promise<any[]> {
    try {
      let whereConditions = [
        eq(pushNotificationTokens.userId, userId),
        eq(pushNotificationTokens.isActive, true)
      ];

      if (deviceType) {
        whereConditions.push(eq(pushNotificationTokens.platform, deviceType));
      }

      const tokens = await db.select()
        .from(pushNotificationTokens)
        .where(and(...whereConditions));
      
      return tokens;
    } catch (error) {
      console.error('Error getting device tokens by user and type:', error);
      return [];
    }
  }

  async createDeviceToken(tokenData: any): Promise<any> {
    try {
      const [deviceToken] = await db.insert(pushNotificationTokens)
        .values({
          ...tokenData,
          createdAt: new Date(),
          updatedAt: new Date()
        })
        .returning();
      
      return deviceToken;
    } catch (error) {
      console.error('Error creating device token:', error);
      throw error;
    }
  }

  async getDeviceTokensByRole(role: string): Promise<string[]> {
    try {
      const tokens = await db.select({ token: pushNotificationTokens.token })
        .from(pushNotificationTokens)
        .innerJoin(users, eq(pushNotificationTokens.userId, users.id))
        .where(and(
          eq(users.role, role),
          eq(users.status, 'active'),
          eq(pushNotificationTokens.isActive, true)
        ));
      
      return tokens.map(t => t.token);
    } catch (error) {
      console.error('Error getting device tokens by role:', error);
      return [];
    }
  }

  // Website Visit Tracking for Smart Recommendations
  async trackWebsiteVisit(visitData: {
    userId: number | null;
    page: string;
    ipAddress: string | null;
    userAgent: string | null;
    sessionId: string | null;
    referrer: string | null;
  }): Promise<void> {
    try {
      await db.insert(websiteVisits).values({
        userId: visitData.userId,
        page: visitData.page,
        ipAddress: visitData.ipAddress,
        userAgent: visitData.userAgent,
        sessionId: visitData.sessionId,
        referrer: visitData.referrer
      });
    } catch (error) {
      console.error('Error tracking website visit:', error);
    }
  }

  async getUserVisitHistory(userId: number, days: number = 30): Promise<any[]> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - days);
      
      const visits = await db.select()
        .from(websiteVisits)
        .where(and(
          eq(websiteVisits.userId, userId),
          gte(websiteVisits.visitedAt, cutoffDate)
        ))
        .orderBy(desc(websiteVisits.visitedAt))
        .limit(100);
      
      return visits;
    } catch (error) {
      console.error('Error getting user visit history:', error);
      return [];
    }
  }

  // Password reset token operations
  async storePasswordResetToken(userId: number, token: string, expiresAt: Date): Promise<void> {
    try {
      await db.insert(passwordResetTokens).values({
        userId,
        token,
        expiresAt,
        used: false
      });
    } catch (error) {
      console.error('Error storing password reset token:', error);
      throw error;
    }
  }

  async getPasswordResetToken(token: string): Promise<{ userId: number; expiresAt: Date } | undefined> {
    try {
      const [result] = await db.select({
        userId: passwordResetTokens.userId,
        expiresAt: passwordResetTokens.expiresAt
      })
      .from(passwordResetTokens)
      .where(and(
        eq(passwordResetTokens.token, token),
        eq(passwordResetTokens.used, false)
      ));
      
      return result;
    } catch (error) {
      console.error('Error getting password reset token:', error);
      return undefined;
    }
  }

  async deletePasswordResetToken(token: string): Promise<boolean> {
    try {
      await db.update(passwordResetTokens)
        .set({ used: true })
        .where(eq(passwordResetTokens.token, token));
      return true;
    } catch (error) {
      console.error('Error deleting password reset token:', error);
      return false;
    }
  }

  async updateUserPassword(userId: number, newPassword: string): Promise<void> {
    try {
      await db.update(users)
        .set({ password: newPassword, updatedAt: new Date() })
        .where(eq(users.id, userId));
    } catch (error) {
      console.error('Error updating user password:', error);
      throw error;
    }
  }
}

import { MemoryStorage } from "./memory-storage";

// Function to test database connectivity
async function testDatabaseConnection(): Promise<boolean> {
  try {
    const testStorage = new DatabaseStorage();
    await testStorage.getAllCategories();
    return true;
  } catch (error) {
    console.error('Database connection test failed:', error);
    return false;
  }
}

// Create and export the storage instance with fallback
async function createStorage(): Promise<IStorage> {
  const isConnected = await testDatabaseConnection();
  
  if (isConnected) {
    console.log('✅ Using DatabaseStorage');
    return new DatabaseStorage();
  } else {
    console.log('⚠️ Database connection failed, falling back to MemoryStorage with sample data');
    return new MemoryStorage();
  }
}

// Export storage promise that resolves to the appropriate storage
export const storagePromise = createStorage();

// Create a single instance that will be resolved once
let storageInstance: IStorage | null = null;

// Function to get or create storage instance
export const getStorage = async (): Promise<IStorage> => {
  if (!storageInstance) {
    storageInstance = await storagePromise;
  }
  return storageInstance;
};

// For backward compatibility - create a storage object that proxies to the database storage
export const storage = new Proxy({} as IStorage, {
  get(target, prop) {
    return async (...args: any[]) => {
      const actualStorage = await getStorage();
      const method = (actualStorage as any)[prop];
      if (typeof method === 'function') {
        return method.apply(actualStorage, args);
      }
      return method;
    };
  }
});