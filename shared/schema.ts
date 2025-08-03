import { pgTable, text, serial, integer, decimal, boolean, timestamp, unique } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").unique(),
  email: text("email").notNull().unique(),
  password: text("password"),
  firebaseUid: text("firebase_uid").unique(),
  fullName: text("full_name").notNull(),
  phone: text("phone"),
  address: text("address"),
  city: text("city"),
  state: text("state"),
  role: text("role").notNull().default("customer"), // customer, shopkeeper, delivery_partner
  status: text("status").notNull().default("active"), // active, pending, suspended, rejected
  approvalDate: timestamp("approval_date"),
  approvedBy: integer("approved_by").references(() => adminUsers.id),
  rejectionReason: text("rejection_reason"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const adminUsers = pgTable("admin_users", {
  id: serial("id").primaryKey(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  fullName: text("full_name").notNull(),
  role: text("role").notNull().default("admin"), // admin, super_admin
  createdAt: timestamp("created_at").defaultNow().notNull(),
  isActive: boolean("is_active").default(true),
});

export const passwordResetTokens = pgTable("password_reset_tokens", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  token: text("token").notNull().unique(),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  used: boolean("used").default(false),
});

export const stores = pgTable("stores", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  description: text("description"),
  ownerId: integer("owner_id").references(() => users.id).notNull(),
  address: text("address").notNull(),
  city: text("city"),
  state: text("state"),
  postalCode: text("postal_code"),
  country: text("country"),
  latitude: decimal("latitude", { precision: 10, scale: 8 }),
  longitude: decimal("longitude", { precision: 11, scale: 8 }),
  phone: text("phone"),
  website: text("website"),
  logo: text("logo"), // Store logo URL
  coverImage: text("cover_image"), // Store cover image URL
  rating: decimal("rating", { precision: 3, scale: 2 }).default("0.00"),
  totalReviews: integer("total_reviews").default(0),
  featured: boolean("featured").default(false),
  isActive: boolean("is_active").default(true),
  storeType: text("store_type").notNull().default("retail"), // retail, restaurant
  cuisineType: text("cuisine_type"), // For restaurants: indian, chinese, fast-food, etc.
  deliveryTime: text("delivery_time"), // For restaurants: "25-35 mins"
  minimumOrder: decimal("minimum_order", { precision: 10, scale: 2 }), // For restaurants
  deliveryFee: decimal("delivery_fee", { precision: 10, scale: 2 }), // For restaurants
  isDeliveryAvailable: boolean("is_delivery_available").default(false),
  openingHours: text("opening_hours"), // JSON string for business hours
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const categories = pgTable("categories", {
  id: serial("id").primaryKey(),
  name: text("name").notNull().unique(),
  slug: text("slug").notNull().unique(),
  description: text("description"),
  icon: text("icon").notNull().default("package"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const products = pgTable("products", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  description: text("description"),
  price: decimal("price", { precision: 10, scale: 2 }).notNull(),
  originalPrice: decimal("original_price", { precision: 10, scale: 2 }),
  categoryId: integer("category_id").references(() => categories.id),
  storeId: integer("store_id").references(() => stores.id).notNull(),
  stock: integer("stock").default(0),
  imageUrl: text("image_url").notNull().default(""),
  images: text("images").array().default([]),
  rating: decimal("rating", { precision: 3, scale: 2 }).default("0.00"),
  totalReviews: integer("total_reviews").default(0),
  isActive: boolean("is_active").default(true),
  isFastSell: boolean("is_fast_sell").default(false), // Fast sell product
  isOnOffer: boolean("is_on_offer").default(false), // Special offer
  offerPercentage: integer("offer_percentage").default(0), // Discount percentage
  offerEndDate: text("offer_end_date"), // When offer expires (stored as string)
  productType: text("product_type").notNull().default("retail"), // retail, food
  preparationTime: text("preparation_time"), // For food items: "15-20 mins"
  ingredients: text("ingredients").array().default([]), // For food items
  allergens: text("allergens").array().default([]), // For food items
  spiceLevel: text("spice_level"), // For food items: mild, medium, hot
  isVegetarian: boolean("is_vegetarian").default(false),
  isVegan: boolean("is_vegan").default(false),
  nutritionInfo: text("nutrition_info"), // JSON string for calories, protein, etc.
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const orders = pgTable("orders", {
  id: serial("id").primaryKey(),
  customerId: integer("customer_id").references(() => users.id).notNull(),
  storeId: integer("store_id").references(() => stores.id).notNull(),
  totalAmount: decimal("total_amount", { precision: 10, scale: 2 }).notNull(),
  deliveryFee: decimal("delivery_fee", { precision: 10, scale: 2 }).default("0.00"),
  taxAmount: decimal("tax_amount", { precision: 10, scale: 2 }).default("0.00"),
  discountAmount: decimal("discount_amount", { precision: 10, scale: 2 }).default("0.00"),
  status: text("status").notNull().default("pending"), // pending, processing, shipped, delivered, cancelled
  shippingAddress: text("shipping_address").notNull(),
  billingAddress: text("billing_address"),
  paymentMethod: text("payment_method").notNull(),
  paymentStatus: text("payment_status").notNull().default("pending"),
  phone: text("phone").notNull(),
  customerName: text("customer_name").notNull(),
  email: text("email"),
  specialInstructions: text("special_instructions"),
  latitude: decimal("latitude", { precision: 10, scale: 8 }), // Customer location latitude
  longitude: decimal("longitude", { precision: 11, scale: 8 }), // Customer location longitude
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const orderItems = pgTable("order_items", {
  id: serial("id").primaryKey(),
  orderId: integer("order_id").references(() => orders.id).notNull(),
  productId: integer("product_id").references(() => products.id).notNull(),
  storeId: integer("store_id").references(() => stores.id).notNull(),
  quantity: integer("quantity").notNull(),
  price: decimal("price", { precision: 10, scale: 2 }).notNull(),
  totalPrice: decimal("total_price", { precision: 10, scale: 2 }).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const cartItems = pgTable("cart_items", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  productId: integer("product_id").references(() => products.id).notNull(),
  quantity: integer("quantity").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const wishlistItems = pgTable("wishlist_items", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  productId: integer("product_id").references(() => products.id).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Admin table for tracking and management
export const admins = pgTable("admins", {
  id: serial("id").primaryKey(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  fullName: text("full_name").notNull(),
  role: text("role").notNull().default("admin"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Delivery Partners table
export const deliveryPartners = pgTable("delivery_partners", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  
  // Vehicle Information
  vehicleType: text("vehicle_type").notNull(), // motorcycle, bicycle, scooter, car, van
  vehicleNumber: text("vehicle_number").notNull(),
  vehicleBrand: text("vehicle_brand"),
  vehicleModel: text("vehicle_model"),
  vehicleYear: text("vehicle_year"),
  vehicleColor: text("vehicle_color"),
  
  // License & Documents
  drivingLicense: text("driving_license"),
  licenseExpiryDate: text("license_expiry_date"),
  idProofType: text("id_proof_type").notNull(),
  idProofNumber: text("id_proof_number").notNull(),
  
  // Banking Information
  bankAccountNumber: text("bank_account_number").notNull(),
  ifscCode: text("ifsc_code").notNull(),
  bankName: text("bank_name"),
  accountHolderName: text("account_holder_name"),
  
  // Emergency Contact
  emergencyContact: text("emergency_contact").notNull(),
  emergencyContactName: text("emergency_contact_name"),
  emergencyContactPhone: text("emergency_contact_phone"),
  emergencyContactRelation: text("emergency_contact_relation"),
  
  // Working Preferences
  deliveryAreas: text("delivery_areas").array().default([]),
  workingHours: text("working_hours"),
  experience: text("experience"),
  previousEmployment: text("previous_employment"),
  references: text("references"),
  
  // Documents & Certifications
  medicalCertificate: text("medical_certificate"),
  policeClearance: text("police_clearance"),
  idProofUrl: text("id_proof_url"),
  drivingLicenseUrl: text("driving_license_url"),
  vehicleRegistrationUrl: text("vehicle_registration_url"),
  insuranceUrl: text("insurance_url"),
  photoUrl: text("photo_url"),
  
  // Status & Approval
  status: text("status").notNull().default("pending"), // pending, approved, rejected
  approvedBy: integer("approved_by").references(() => adminUsers.id),
  approvedAt: timestamp("approved_at"),
  rejectionReason: text("rejection_reason"),
  
  // Operational Data
  isAvailable: boolean("is_available").default(true),
  currentLocation: text("current_location"), // JSON string for lat/lng
  totalDeliveries: integer("total_deliveries").default(0),
  rating: decimal("rating", { precision: 3, scale: 2 }).default("0.00"),
  totalEarnings: decimal("total_earnings", { precision: 10, scale: 2 }).default("0.00"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Delivery assignments
export const deliveries = pgTable("deliveries", {
  id: serial("id").primaryKey(),
  orderId: integer("order_id").references(() => orders.id).notNull(),
  deliveryPartnerId: integer("delivery_partner_id").references(() => deliveryPartners.id),
  status: text("status").notNull().default("pending"), // pending, assigned, picked_up, in_transit, delivered, cancelled
  assignedAt: timestamp("assigned_at"),
  pickedUpAt: timestamp("picked_up_at"),
  deliveredAt: timestamp("delivered_at"),
  deliveryFee: decimal("delivery_fee", { precision: 10, scale: 2 }).notNull(),
  pickupAddress: text("pickup_address").notNull(),
  deliveryAddress: text("delivery_address").notNull(),
  estimatedDistance: decimal("estimated_distance", { precision: 8, scale: 2 }), // in kilometers
  estimatedTime: integer("estimated_time"), // in minutes
  actualTime: integer("actual_time"), // in minutes
  specialInstructions: text("special_instructions"),
  proofOfDelivery: text("proof_of_delivery"), // photo URL
  customerRating: integer("customer_rating"), // 1-5 stars
  customerFeedback: text("customer_feedback"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Delivery zones for configurable delivery fees
export const deliveryZones = pgTable("delivery_zones", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  minDistance: decimal("min_distance", { precision: 8, scale: 2 }).notNull(),
  maxDistance: decimal("max_distance", { precision: 8, scale: 2 }).notNull(),
  baseFee: decimal("base_fee", { precision: 10, scale: 2 }).notNull(),
  perKmRate: decimal("per_km_rate", { precision: 10, scale: 2 }).notNull(),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Website analytics and tracking
export const websiteVisits = pgTable("website_visits", {
  id: serial("id").primaryKey(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  page: text("page").notNull(),
  referrer: text("referrer"),
  sessionId: text("session_id"),
  userId: integer("user_id").references(() => users.id),
  visitedAt: timestamp("visited_at").defaultNow().notNull(),
});

// Notifications system
export const notifications = pgTable("notifications", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  title: text("title").notNull(),
  message: text("message").notNull(),
  type: text("type").notNull().default("info"), // info, success, warning, error
  isRead: boolean("is_read").default(false),
  orderId: integer("order_id").references(() => orders.id),
  productId: integer("product_id").references(() => products.id),
  data: text("data"), // JSON string for additional notification data
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Order tracking system
export const orderTracking = pgTable("order_tracking", {
  id: serial("id").primaryKey(),
  orderId: integer("order_id").references(() => orders.id).notNull(),
  status: text("status").notNull(),
  description: text("description"),
  location: text("location"),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Real-time delivery tracking for HERE Maps integration
export const deliveryLocationTracking = pgTable("delivery_location_tracking", {
  id: serial("id").primaryKey(),
  deliveryId: integer("delivery_id").references(() => deliveries.id).notNull(),
  deliveryPartnerId: integer("delivery_partner_id").references(() => deliveryPartners.id).notNull(),
  currentLatitude: decimal("current_latitude", { precision: 10, scale: 8 }).notNull(),
  currentLongitude: decimal("current_longitude", { precision: 11, scale: 8 }).notNull(),
  heading: decimal("heading", { precision: 5, scale: 2 }), // Direction in degrees
  speed: decimal("speed", { precision: 8, scale: 2 }), // Speed in km/h
  accuracy: decimal("accuracy", { precision: 8, scale: 2 }), // GPS accuracy in meters
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  isActive: boolean("is_active").default(true),
});

// Route information for HERE Maps
export const deliveryRoutes = pgTable("delivery_routes", {
  id: serial("id").primaryKey(),
  deliveryId: integer("delivery_id").references(() => deliveries.id).notNull(),
  pickupLatitude: decimal("pickup_latitude", { precision: 10, scale: 8 }).notNull(),
  pickupLongitude: decimal("pickup_longitude", { precision: 11, scale: 8 }).notNull(),
  deliveryLatitude: decimal("delivery_latitude", { precision: 10, scale: 8 }).notNull(),
  deliveryLongitude: decimal("delivery_longitude", { precision: 11, scale: 8 }).notNull(),
  routeGeometry: text("route_geometry"), // HERE Maps polyline geometry
  distanceMeters: integer("distance_meters").notNull(),
  estimatedDurationSeconds: integer("estimated_duration_seconds").notNull(),
  actualDurationSeconds: integer("actual_duration_seconds"),
  trafficInfo: text("traffic_info"), // JSON string for traffic conditions
  hereRouteId: text("here_route_id"), // HERE Maps route identifier
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Push notification tokens for real-time notifications
export const pushNotificationTokens = pgTable("push_notification_tokens", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  token: text("token").notNull().unique(),
  platform: text("platform").notNull(), // web, android, ios
  deviceId: text("device_id"),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  lastUsed: timestamp("last_used").defaultNow(),
});

// WebSocket sessions for real-time tracking
export const webSocketSessions = pgTable("websocket_sessions", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  sessionId: text("session_id").notNull().unique(),
  userType: text("user_type").notNull(), // customer, delivery_partner, shopkeeper
  connectedAt: timestamp("connected_at").defaultNow().notNull(),
  lastActivity: timestamp("last_activity").defaultNow(),
  isActive: boolean("is_active").default(true),
});

// Delivery status history for detailed tracking
export const deliveryStatusHistory = pgTable("delivery_status_history", {
  id: serial("id").primaryKey(),
  deliveryId: integer("delivery_id").references(() => deliveries.id).notNull(),
  status: text("status").notNull(), // order_placed, assigned, en_route_pickup, arrived_pickup, picked_up, en_route_delivery, arrived_delivery, delivered, cancelled
  description: text("description"),
  latitude: decimal("latitude", { precision: 10, scale: 8 }),
  longitude: decimal("longitude", { precision: 11, scale: 8 }),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  updatedBy: integer("updated_by").references(() => users.id),
  metadata: text("metadata"), // JSON string for additional data
});

// Return policy and returns
export const returnPolicies = pgTable("return_policies", {
  id: serial("id").primaryKey(),
  storeId: integer("store_id").references(() => stores.id).notNull(),
  returnDays: integer("return_days").default(7),
  returnConditions: text("return_conditions"),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const returns = pgTable("returns", {
  id: serial("id").primaryKey(),
  orderId: integer("order_id").references(() => orders.id).notNull(),
  orderItemId: integer("order_item_id").references(() => orderItems.id).notNull(),
  customerId: integer("customer_id").references(() => users.id).notNull(),
  reason: text("reason").notNull(),
  description: text("description"),
  status: text("status").notNull().default("requested"), // requested, approved, rejected, completed
  refundAmount: decimal("refund_amount", { precision: 10, scale: 2 }),
  images: text("images").array().default([]),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Seller promotions and advertisements
export const promotions = pgTable("promotions", {
  id: serial("id").primaryKey(),
  storeId: integer("store_id").references(() => stores.id).notNull(),
  title: text("title").notNull(),
  description: text("description"),
  discountType: text("discount_type").notNull(), // percentage, fixed_amount
  discountValue: decimal("discount_value", { precision: 10, scale: 2 }).notNull(),
  minOrderAmount: decimal("min_order_amount", { precision: 10, scale: 2 }),
  maxDiscountAmount: decimal("max_discount_amount", { precision: 10, scale: 2 }),
  startDate: timestamp("start_date").notNull(),
  endDate: timestamp("end_date").notNull(),
  isActive: boolean("is_active").default(true),
  usageLimit: integer("usage_limit"),
  usedCount: integer("used_count").default(0),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Store advertisements/banners
export const advertisements = pgTable("advertisements", {
  id: serial("id").primaryKey(),
  storeId: integer("store_id").references(() => stores.id).notNull(),
  title: text("title").notNull(),
  description: text("description"),
  imageUrl: text("image_url").notNull(),
  targetUrl: text("target_url"),
  position: text("position").notNull(), // homepage_banner, category_sidebar, product_listing
  priority: integer("priority").default(0),
  startDate: timestamp("start_date").notNull(),
  endDate: timestamp("end_date").notNull(),
  isActive: boolean("is_active").default(true),
  impressions: integer("impressions").default(0),
  clicks: integer("clicks").default(0),
  budget: decimal("budget", { precision: 10, scale: 2 }),
  costPerClick: decimal("cost_per_click", { precision: 5, scale: 2 }),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Product reviews and ratings
export const productReviews = pgTable("product_reviews", {
  id: serial("id").primaryKey(),
  productId: integer("product_id").references(() => products.id).notNull(),
  customerId: integer("customer_id").references(() => users.id).notNull(),
  orderId: integer("order_id").references(() => orders.id),
  rating: integer("rating").notNull(), // 1-5 stars
  title: text("title"),
  comment: text("comment"),
  images: text("images").array().default([]),
  isVerifiedPurchase: boolean("is_verified_purchase").default(false),
  isApproved: boolean("is_approved").default(true),
  helpfulCount: integer("helpful_count").default(0),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Track which users have liked which reviews
export const reviewLikes = pgTable("review_likes", {
  id: serial("id").primaryKey(),
  reviewId: integer("review_id").references(() => productReviews.id).notNull(),
  userId: integer("user_id").references(() => users.id).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => ({
  // Ensure one user can only like a review once
  uniqueUserReview: unique().on(table.reviewId, table.userId),
}));

// Store reviews and ratings
export const storeReviews = pgTable("store_reviews", {
  id: serial("id").primaryKey(),
  storeId: integer("store_id").references(() => stores.id).notNull(),
  customerId: integer("customer_id").references(() => users.id).notNull(),
  orderId: integer("order_id").references(() => orders.id),
  rating: integer("rating").notNull(), // 1-5 stars
  title: text("title"),
  comment: text("comment"),
  images: text("images").array().default([]),
  isVerifiedPurchase: boolean("is_verified_purchase").default(false),
  isApproved: boolean("is_approved").default(true),
  helpfulCount: integer("helpful_count").default(0),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Track which users have liked which store reviews
export const storeReviewLikes = pgTable("store_review_likes", {
  id: serial("id").primaryKey(),
  reviewId: integer("review_id").references(() => storeReviews.id).notNull(),
  userId: integer("user_id").references(() => users.id).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
}, (table) => ({
  // Ensure one user can only like a store review once
  uniqueUserStoreReview: unique().on(table.reviewId, table.userId),
}));

// Store settlements and payouts
export const settlements = pgTable("settlements", {
  id: serial("id").primaryKey(),
  storeId: integer("store_id").references(() => stores.id).notNull(),
  orderId: integer("order_id").references(() => orders.id).notNull(),
  grossAmount: decimal("gross_amount", { precision: 10, scale: 2 }).notNull(),
  platformFee: decimal("platform_fee", { precision: 10, scale: 2 }).notNull(),
  paymentGatewayFee: decimal("payment_gateway_fee", { precision: 10, scale: 2 }).notNull(),
  netAmount: decimal("net_amount", { precision: 10, scale: 2 }).notNull(),
  status: text("status").notNull().default("pending"), // pending, processing, completed, failed
  settlementDate: timestamp("settlement_date"),
  bankAccount: text("bank_account"),
  transactionId: text("transaction_id"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Store analytics tracking
export const storeAnalytics = pgTable("store_analytics", {
  id: serial("id").primaryKey(),
  storeId: integer("store_id").references(() => stores.id).notNull(),
  date: text("date").notNull(), // YYYY-MM-DD format
  pageViews: integer("page_views").default(0),
  uniqueVisitors: integer("unique_visitors").default(0),
  productViews: integer("product_views").default(0),
  addToCartCount: integer("add_to_cart_count").default(0),
  checkoutCount: integer("checkout_count").default(0),
  ordersCount: integer("orders_count").default(0),
  revenue: decimal("revenue", { precision: 10, scale: 2 }).default("0.00"),
  conversionRate: decimal("conversion_rate", { precision: 5, scale: 2 }).default("0.00"),
});

// Inventory management
export const inventoryLogs = pgTable("inventory_logs", {
  id: serial("id").primaryKey(),
  productId: integer("product_id").references(() => products.id).notNull(),
  storeId: integer("store_id").references(() => stores.id).notNull(),
  type: text("type").notNull(), // stock_in, stock_out, adjustment, return
  quantity: integer("quantity").notNull(),
  previousStock: integer("previous_stock").notNull(),
  newStock: integer("new_stock").notNull(),
  reason: text("reason"),
  orderId: integer("order_id").references(() => orders.id),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Enhanced admin features schemas
export const coupons = pgTable("coupons", {
  id: serial("id").primaryKey(),
  code: text("code").notNull().unique(),
  title: text("title").notNull(),
  description: text("description"),
  discountType: text("discount_type").notNull().default("percentage"), // percentage, fixed
  discountValue: decimal("discount_value", { precision: 10, scale: 2 }).notNull(),
  minimumOrderAmount: decimal("minimum_order_amount", { precision: 10, scale: 2 }).default("0"),
  maximumDiscount: decimal("maximum_discount", { precision: 10, scale: 2 }),
  usageLimit: integer("usage_limit"),
  usedCount: integer("used_count").default(0),
  expiresAt: timestamp("expires_at"),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Product attributes for advanced product management
export const productAttributes = pgTable("product_attributes", {
  id: serial("id").primaryKey(),
  productId: integer("product_id").references(() => products.id).notNull(),
  attributeName: text("attribute_name").notNull(), // size, color, brand, material, etc.
  attributeValue: text("attribute_value").notNull(),
});

// Fraud detection and security
export const fraudAlerts = pgTable("fraud_alerts", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  orderId: integer("order_id").references(() => orders.id),
  alertType: text("alert_type").notNull(), // suspicious_activity, multiple_accounts, payment_fraud
  riskScore: integer("risk_score").notNull(), // 1-100
  description: text("description").notNull(),
  status: text("status").notNull().default("open"), // open, investigating, resolved, false_positive
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Role-based access control
export const adminRoles = pgTable("admin_roles", {
  id: serial("id").primaryKey(),
  name: text("name").notNull().unique(),
  description: text("description"),
  permissions: text("permissions").array().default([]), // array of permission strings
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const adminRoleAssignments = pgTable("admin_role_assignments", {
  id: serial("id").primaryKey(),
  adminId: integer("admin_id").references(() => adminUsers.id).notNull(),
  roleId: integer("role_id").references(() => adminRoles.id).notNull(),
  assignedAt: timestamp("assigned_at").defaultNow().notNull(),
});

// Vendor/Seller KYC and verification
export const vendorVerifications = pgTable("vendor_verifications", {
  id: serial("id").primaryKey(),
  storeId: integer("store_id").references(() => stores.id).notNull(),
  documentType: text("document_type").notNull(), // business_license, tax_certificate, id_proof
  documentUrl: text("document_url").notNull(),
  status: text("status").notNull().default("pending"), // pending, approved, rejected
  reviewedBy: integer("reviewed_by").references(() => adminUsers.id),
  reviewedAt: timestamp("reviewed_at"),
  rejectionReason: text("rejection_reason"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Commission tracking for multi-vendor
export const commissions = pgTable("commissions", {
  id: serial("id").primaryKey(),
  storeId: integer("store_id").references(() => stores.id).notNull(),
  orderId: integer("order_id").references(() => orders.id).notNull(),
  grossAmount: decimal("gross_amount", { precision: 10, scale: 2 }).notNull(),
  commissionRate: decimal("commission_rate", { precision: 5, scale: 2 }).notNull(),
  commissionAmount: decimal("commission_amount", { precision: 10, scale: 2 }).notNull(),
  status: text("status").notNull().default("pending"), // pending, paid, disputed
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const flashSales = pgTable("flash_sales", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description"),
  discountPercentage: integer("discount_percentage").notNull(),
  startsAt: timestamp("starts_at").notNull(),
  endsAt: timestamp("ends_at").notNull(),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const productTags = pgTable("product_tags", {
  id: serial("id").primaryKey(),
  name: text("name").notNull().unique(),
  slug: text("slug").notNull().unique(),
  color: text("color").default("#3B82F6"),
});

export const productTagRelations = pgTable("product_tag_relations", {
  id: serial("id").primaryKey(),
  productId: integer("product_id").references(() => products.id).notNull(),
  tagId: integer("tag_id").references(() => productTags.id).notNull(),
});

export const paymentTransactions = pgTable("payment_transactions", {
  id: serial("id").primaryKey(),
  orderId: integer("order_id").references(() => orders.id).notNull(),
  transactionId: text("transaction_id").unique(),
  paymentMethod: text("payment_method").notNull(),
  amount: decimal("amount", { precision: 10, scale: 2 }).notNull(),
  currency: text("currency").default("NPR"),
  status: text("status").notNull().default("pending"), // pending, completed, failed, refunded
  gatewayResponse: text("gateway_response"),
  processedAt: timestamp("processed_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const adminLogs = pgTable("admin_logs", {
  id: serial("id").primaryKey(),
  adminId: integer("admin_id").references(() => adminUsers.id).notNull(),
  action: text("action").notNull(),
  resourceType: text("resource_type").notNull(), // user, product, order, etc.
  resourceId: integer("resource_id"),
  details: text("details"),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const supportTickets = pgTable("support_tickets", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
  subject: text("subject").notNull(),
  message: text("message").notNull(),
  status: text("status").notNull().default("open"), // open, in_progress, resolved, closed
  priority: text("priority").notNull().default("medium"), // low, medium, high, urgent
  assignedTo: integer("assigned_to").references(() => adminUsers.id),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const banners = pgTable("banners", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  imageUrl: text("image_url").notNull(),
  linkUrl: text("link_url"),
  description: text("description"),
  position: text("position").notNull().default("main"), // main, sidebar, footer
  isActive: boolean("is_active").default(true),
  displayOrder: integer("display_order").default(0),
  startsAt: timestamp("starts_at"),
  endsAt: timestamp("ends_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const siteSettings = pgTable("site_settings", {
  id: serial("id").primaryKey(),
  settingKey: text("setting_key").notNull().unique(),
  settingValue: text("setting_value"),
  settingType: text("setting_type").notNull().default("string"), // string, number, boolean, json
  description: text("description"),
  isPublic: boolean("is_public").default(false),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});



// Insert schemas
export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
}).extend({
  username: z.string().optional(),
});

export const insertCouponSchema = createInsertSchema(coupons).omit({
  id: true,
  createdAt: true,
});

export const insertFlashSaleSchema = z.object({
  title: z.string(),
  description: z.string().optional(),
  discountPercentage: z.number(),
  startsAt: z.string().transform((str) => new Date(str)),
  endsAt: z.string().transform((str) => new Date(str)),
  isActive: z.boolean().default(true),
});

export const insertProductTagSchema = createInsertSchema(productTags).omit({
  id: true,
});

export const insertPaymentTransactionSchema = createInsertSchema(paymentTransactions).omit({
  id: true,
  createdAt: true,
});

export const insertAdminLogSchema = createInsertSchema(adminLogs).omit({
  id: true,
  createdAt: true,
});

export const insertSupportTicketSchema = createInsertSchema(supportTickets).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertBannerSchema = createInsertSchema(banners).omit({
  id: true,
  createdAt: true,
});

export const insertSiteSettingSchema = createInsertSchema(siteSettings).omit({
  id: true,
  updatedAt: true,
});

// New tracking table insert schemas
export const insertDeliveryLocationTrackingSchema = createInsertSchema(deliveryLocationTracking).omit({
  id: true,
  timestamp: true,
});

export const insertDeliveryRouteSchema = createInsertSchema(deliveryRoutes).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertPushNotificationTokenSchema = createInsertSchema(pushNotificationTokens).omit({
  id: true,
  createdAt: true,
  lastUsed: true,
});

export const insertWebSocketSessionSchema = createInsertSchema(webSocketSessions).omit({
  id: true,
  connectedAt: true,
  lastActivity: true,
});

export const insertDeliveryStatusHistorySchema = createInsertSchema(deliveryStatusHistory).omit({
  id: true,
  timestamp: true,
});

// Type definitions for the new tables
export type DeliveryLocationTracking = typeof deliveryLocationTracking.$inferSelect;
export type InsertDeliveryLocationTracking = typeof insertDeliveryLocationTrackingSchema._type;

export type DeliveryRoute = typeof deliveryRoutes.$inferSelect;
export type InsertDeliveryRoute = typeof insertDeliveryRouteSchema._type;

export type PushNotificationToken = typeof pushNotificationTokens.$inferSelect;
export type InsertPushNotificationToken = typeof insertPushNotificationTokenSchema._type;

export type WebSocketSession = typeof webSocketSessions.$inferSelect;
export type InsertWebSocketSession = typeof insertWebSocketSessionSchema._type;

export type DeliveryStatusHistory = typeof deliveryStatusHistory.$inferSelect;
export type InsertDeliveryStatusHistory = typeof insertDeliveryStatusHistorySchema._type;

// Add insert schemas for new tables
export const insertProductAttributeSchema = createInsertSchema(productAttributes).omit({
  id: true,
});

export const insertFraudAlertSchema = createInsertSchema(fraudAlerts).omit({
  id: true,
  createdAt: true,
});

export const insertAdminRoleSchema = createInsertSchema(adminRoles).omit({
  id: true,
  createdAt: true,
});

export const insertAdminRoleAssignmentSchema = createInsertSchema(adminRoleAssignments).omit({
  id: true,
  assignedAt: true,
});

export const insertVendorVerificationSchema = createInsertSchema(vendorVerifications).omit({
  id: true,
  createdAt: true,
});

export const insertCommissionSchema = createInsertSchema(commissions).omit({
  id: true,
  createdAt: true,
});

// Delivery partner schemas
export const insertDeliveryPartnerSchema = createInsertSchema(deliveryPartners).omit({
  id: true,
  createdAt: true,
});

export const insertDeliverySchema = createInsertSchema(deliveries).omit({
  id: true,
  createdAt: true,
});

// Enhanced admin feature types
export type Coupon = typeof coupons.$inferSelect;
export type InsertCoupon = z.infer<typeof insertCouponSchema>;
export type FlashSale = typeof flashSales.$inferSelect;
export type InsertFlashSale = z.infer<typeof insertFlashSaleSchema>;
export type ProductTag = typeof productTags.$inferSelect;
export type InsertProductTag = z.infer<typeof insertProductTagSchema>;
export type PaymentTransaction = typeof paymentTransactions.$inferSelect;
export type InsertPaymentTransaction = z.infer<typeof insertPaymentTransactionSchema>;
export type AdminLog = typeof adminLogs.$inferSelect;
export type InsertAdminLog = z.infer<typeof insertAdminLogSchema>;
export type SupportTicket = typeof supportTickets.$inferSelect;
export type InsertSupportTicket = z.infer<typeof insertSupportTicketSchema>;
export type Banner = typeof banners.$inferSelect;
export type InsertBanner = z.infer<typeof insertBannerSchema>;
export type SiteSetting = typeof siteSettings.$inferSelect;
export type InsertSiteSetting = z.infer<typeof insertSiteSettingSchema>;

export type DeliveryZone = typeof deliveryZones.$inferSelect;
export type InsertDeliveryZone = z.infer<typeof insertDeliveryZoneSchema>;
export type ProductAttribute = typeof productAttributes.$inferSelect;
export type InsertProductAttribute = z.infer<typeof insertProductAttributeSchema>;
export type FraudAlert = typeof fraudAlerts.$inferSelect;
export type InsertFraudAlert = z.infer<typeof insertFraudAlertSchema>;
export type AdminRole = typeof adminRoles.$inferSelect;
export type InsertAdminRole = z.infer<typeof insertAdminRoleSchema>;
export type AdminRoleAssignment = typeof adminRoleAssignments.$inferSelect;
export type InsertAdminRoleAssignment = z.infer<typeof insertAdminRoleAssignmentSchema>;
export type VendorVerification = typeof vendorVerifications.$inferSelect;
export type InsertVendorVerification = z.infer<typeof insertVendorVerificationSchema>;
export type Commission = typeof commissions.$inferSelect;
export type InsertCommission = z.infer<typeof insertCommissionSchema>;

// Delivery partner types
export type DeliveryPartner = typeof deliveryPartners.$inferSelect;
export type InsertDeliveryPartner = z.infer<typeof insertDeliveryPartnerSchema>;
export type Delivery = typeof deliveries.$inferSelect;
export type InsertDelivery = z.infer<typeof insertDeliverySchema>;

export const insertStoreSchema = createInsertSchema(stores).omit({
  id: true,
  slug: true,
  createdAt: true,
  updatedAt: true,
  rating: true,
  totalReviews: true,
  featured: true,
  isActive: true,
}).extend({
  // Make name more flexible - allow any valid store name
  name: z.string().min(1, "Store name is required").transform(val => val?.trim() || ""),
  
  // Handle all fields with null/undefined gracefully
  description: z.union([z.string(), z.null(), z.undefined()]).optional().transform(val => val || ""),
  
  // Make address required but flexible
  address: z.string().min(1, "Address is required").transform(val => val?.trim() || ""),
  
  // Handle optional string fields that can be null
  phone: z.union([z.string(), z.null(), z.undefined()]).optional().transform(val => val?.trim() || ""),
  website: z.union([z.string(), z.null(), z.undefined()]).optional().transform(val => {
    if (!val || val.trim() === "") return "";
    const trimmed = val.trim();
    // Add https:// if no protocol is provided and it's a valid URL
    if (trimmed && !trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      return `https://${trimmed}`;
    }
    return trimmed;
  }),
  
  // Handle numeric fields as strings, numbers, or null
  minimumOrder: z.union([z.string(), z.number(), z.null(), z.undefined()]).optional().transform((val) => 
    val !== undefined && val !== null && val !== "" ? String(val) : undefined
  ),
  deliveryFee: z.union([z.string(), z.number(), z.null(), z.undefined()]).optional().transform((val) => 
    val !== undefined && val !== null && val !== "" ? String(val) : undefined
  ),
  latitude: z.union([z.string(), z.number(), z.null(), z.undefined()]).optional().transform((val) => 
    val !== undefined && val !== null && val !== "" ? String(val) : undefined
  ),
  longitude: z.union([z.string(), z.number(), z.null(), z.undefined()]).optional().transform((val) => 
    val !== undefined && val !== null && val !== "" ? String(val) : undefined
  ),
  
  // Make optional fields handle null values
  logo: z.union([z.string(), z.null(), z.undefined()]).optional().transform(val => val || ""),
  coverImage: z.union([z.string(), z.null(), z.undefined()]).optional().transform(val => val || ""),
  cuisineType: z.union([z.string(), z.null(), z.undefined()]).optional().transform(val => val || ""),
  deliveryTime: z.union([z.string(), z.null(), z.undefined()]).optional().transform(val => val || ""),
  openingHours: z.union([z.string(), z.null(), z.undefined()]).optional().transform(val => val || ""),
  city: z.union([z.string(), z.null(), z.undefined()]).optional().transform(val => val || ""),
  state: z.union([z.string(), z.null(), z.undefined()]).optional().transform(val => val || ""),
  postalCode: z.union([z.string(), z.null(), z.undefined()]).optional().transform(val => val || ""),
  country: z.union([z.string(), z.null(), z.undefined()]).optional().transform(val => val || ""),
});

export const insertCategorySchema = createInsertSchema(categories).omit({
  id: true,
});

export const insertProductSchema = createInsertSchema(products).omit({
  id: true,
  createdAt: true,
  rating: true,
  totalReviews: true,
}).extend({
  slug: z.string().optional(),
  price: z.union([z.string(), z.number()]).transform((val) => String(val)),
  originalPrice: z.union([z.string(), z.number()]).optional().transform((val) => 
    val !== undefined ? String(val) : undefined
  ),
});

export const insertOrderSchema = createInsertSchema(orders).omit({
  id: true,
  createdAt: true,
}).extend({
  latitude: z.union([z.string(), z.number()]).optional().transform((val) => 
    val !== undefined ? String(val) : undefined
  ),
  longitude: z.union([z.string(), z.number()]).optional().transform((val) => 
    val !== undefined ? String(val) : undefined
  ),
});

export const insertOrderItemSchema = createInsertSchema(orderItems).omit({
  id: true,
});

export const insertCartItemSchema = createInsertSchema(cartItems).omit({
  id: true,
  createdAt: true,
});

export const insertWishlistItemSchema = createInsertSchema(wishlistItems).omit({
  id: true,
  createdAt: true,
});

export const insertAdminSchema = createInsertSchema(admins).omit({
  id: true,
  createdAt: true,
});

export const insertWebsiteVisitSchema = createInsertSchema(websiteVisits).omit({
  id: true,
  visitedAt: true,
});

export const insertNotificationSchema = createInsertSchema(notifications).omit({
  id: true,
  createdAt: true,
});

export const insertOrderTrackingSchema = createInsertSchema(orderTracking).omit({
  id: true,
  updatedAt: true,
});

export const insertReturnPolicySchema = createInsertSchema(returnPolicies).omit({
  id: true,
  createdAt: true,
});

export const insertReturnSchema = createInsertSchema(returns).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertPromotionSchema = createInsertSchema(promotions).omit({
  id: true,
  createdAt: true,
  usedCount: true,
});

export const insertAdvertisementSchema = createInsertSchema(advertisements).omit({
  id: true,
  createdAt: true,
  impressions: true,
  clicks: true,
});

export const insertDeliveryZoneSchema = createInsertSchema(deliveryZones).omit({
  id: true,
  createdAt: true,
});

export const insertProductReviewSchema = createInsertSchema(productReviews).omit({
  id: true,
  createdAt: true,
  helpfulCount: true,
});

export const insertStoreReviewSchema = createInsertSchema(storeReviews).omit({
  id: true,
  createdAt: true,
  helpfulCount: true,
});

export const insertStoreReviewLikeSchema = createInsertSchema(storeReviewLikes).omit({
  id: true,
  createdAt: true,
});

export const insertSettlementSchema = createInsertSchema(settlements).omit({
  id: true,
  createdAt: true,
});

export const insertStoreAnalyticsSchema = createInsertSchema(storeAnalytics).omit({
  id: true,
});

export const insertInventoryLogSchema = createInsertSchema(inventoryLogs).omit({
  id: true,
  createdAt: true,
});

// Types
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type Store = typeof stores.$inferSelect;
export type InsertStore = z.infer<typeof insertStoreSchema>;
export type Category = typeof categories.$inferSelect;
export type InsertCategory = z.infer<typeof insertCategorySchema>;
export type Product = typeof products.$inferSelect;
export type InsertProduct = z.infer<typeof insertProductSchema>;
export type Order = typeof orders.$inferSelect;
export type InsertOrder = z.infer<typeof insertOrderSchema>;
export type OrderItem = typeof orderItems.$inferSelect;
export type InsertOrderItem = z.infer<typeof insertOrderItemSchema>;
export type CartItem = typeof cartItems.$inferSelect;
export type InsertCartItem = z.infer<typeof insertCartItemSchema>;
export type WishlistItem = typeof wishlistItems.$inferSelect;
export type InsertWishlistItem = z.infer<typeof insertWishlistItemSchema>;
export type Admin = typeof admins.$inferSelect;
export type InsertAdmin = z.infer<typeof insertAdminSchema>;
export type WebsiteVisit = typeof websiteVisits.$inferSelect;
export type InsertWebsiteVisit = z.infer<typeof insertWebsiteVisitSchema>;
export type Notification = typeof notifications.$inferSelect;
export type InsertNotification = z.infer<typeof insertNotificationSchema>;
export type OrderTracking = typeof orderTracking.$inferSelect;
export type InsertOrderTracking = z.infer<typeof insertOrderTrackingSchema>;
export type ReturnPolicy = typeof returnPolicies.$inferSelect;
export type InsertReturnPolicy = z.infer<typeof insertReturnPolicySchema>;
export type Return = typeof returns.$inferSelect;
export type InsertReturn = z.infer<typeof insertReturnSchema>;
export type Promotion = typeof promotions.$inferSelect;
export type InsertPromotion = z.infer<typeof insertPromotionSchema>;
export type Advertisement = typeof advertisements.$inferSelect;
export type InsertAdvertisement = z.infer<typeof insertAdvertisementSchema>;
export type ProductReview = typeof productReviews.$inferSelect;
export type InsertProductReview = z.infer<typeof insertProductReviewSchema>;

export type StoreReview = typeof storeReviews.$inferSelect;
export type InsertStoreReview = z.infer<typeof insertStoreReviewSchema>;

export type StoreReviewLike = typeof storeReviewLikes.$inferSelect;
export type InsertStoreReviewLike = z.infer<typeof insertStoreReviewLikeSchema>;

// Review likes schema and types
export const insertReviewLikeSchema = createInsertSchema(reviewLikes).omit({
  id: true,
  createdAt: true,
});

export type ReviewLike = typeof reviewLikes.$inferSelect;
export type InsertReviewLike = z.infer<typeof insertReviewLikeSchema>;
export type Settlement = typeof settlements.$inferSelect;
export type InsertSettlement = z.infer<typeof insertSettlementSchema>;
export type StoreAnalytics = typeof storeAnalytics.$inferSelect;
export type InsertStoreAnalytics = z.infer<typeof insertStoreAnalyticsSchema>;
export type InventoryLog = typeof inventoryLogs.$inferSelect;
export type InsertInventoryLog = z.infer<typeof insertInventoryLogSchema>;

// Admin user schema
export const insertAdminUserSchema = createInsertSchema(adminUsers);
export type AdminUser = typeof adminUsers.$inferSelect;
export type InsertAdminUser = z.infer<typeof insertAdminUserSchema>;

// Password reset token schema
export const insertPasswordResetTokenSchema = createInsertSchema(passwordResetTokens).omit({
  id: true,
  createdAt: true,
});
export type PasswordResetToken = typeof passwordResetTokens.$inferSelect;
export type InsertPasswordResetToken = z.infer<typeof insertPasswordResetTokenSchema>;
