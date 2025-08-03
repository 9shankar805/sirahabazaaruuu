-- Complete Sample Data for Siraha Bazaar with Push Notifications

-- Insert Categories
INSERT INTO categories (name, slug, description, icon, created_at, updated_at) VALUES 
('Electronics', 'electronics', 'Electronics products and gadgets', 'smartphone', NOW(), NOW()),
('Fashion', 'fashion', 'Fashion and clothing items', 'shirt', NOW(), NOW()),
('Food & Beverages', 'food-beverages', 'Food and beverage items', 'utensils', NOW(), NOW()),
('Health & Beauty', 'health-beauty', 'Health and beauty products', 'heart', NOW(), NOW()),
('Sports & Fitness', 'sports-fitness', 'Sports and fitness equipment', 'dumbbell', NOW(), NOW()),
('Books & Education', 'books-education', 'Books and educational materials', 'book', NOW(), NOW()),
('Home & Garden', 'home-garden', 'Home and garden items', 'home', NOW(), NOW()),
('Grocery', 'grocery', 'Grocery and daily essentials', 'shopping-cart', NOW(), NOW())
ON CONFLICT (name) DO NOTHING;

-- Insert Users (with simple passwords for testing)
INSERT INTO users (username, email, password, full_name, phone, address, city, state, role, status, created_at, updated_at) VALUES 
('john_doe', 'john@customer.com', '$2b$10$easyhash1', 'John Doe', '+977-9801234567', 'Siraha Main Road', 'Siraha', 'Province 2', 'customer', 'active', NOW(), NOW()),
('jane_smith', 'jane@customer.com', '$2b$10$easyhash2', 'Jane Smith', '+977-9801234568', 'Lahan Center', 'Lahan', 'Province 2', 'customer', 'active', NOW(), NOW()),
('ram_kumar', 'ram@customer.com', '$2b$10$easyhash3', 'Ram Kumar', '+977-9801234569', 'Mirchaiya Bazaar', 'Mirchaiya', 'Province 2', 'customer', 'active', NOW(), NOW()),
('electronics_owner', 'electronics@shop.com', '$2b$10$easyhash4', 'Rajesh Sharma', '+977-9801234570', 'Electronics Market, Siraha', 'Siraha', 'Province 2', 'shopkeeper', 'approved', NOW(), NOW()),
('fashion_owner', 'fashion@shop.com', '$2b$10$easyhash5', 'Sita Devi', '+977-9801234571', 'Fashion Street, Lahan', 'Lahan', 'Province 2', 'shopkeeper', 'approved', NOW(), NOW()),
('restaurant_owner', 'restaurant@shop.com', '$2b$10$easyhash6', 'Krishna Prasad', '+977-9801234572', 'Food Court, Mirchaiya', 'Mirchaiya', 'Province 2', 'shopkeeper', 'approved', NOW(), NOW()),
('delivery_partner1', 'delivery1@partner.com', '$2b$10$easyhash7', 'Gokul Yadav', '+977-9801234573', 'Delivery Hub, Siraha', 'Siraha', 'Province 2', 'delivery_partner', 'approved', NOW(), NOW()),
('delivery_partner2', 'delivery2@partner.com', '$2b$10$easyhash8', 'Muna Thapa', '+977-9801234574', 'Delivery Center, Lahan', 'Lahan', 'Province 2', 'delivery_partner', 'approved', NOW(), NOW()),
('admin_user', 'admin@siraha.com', '$2b$10$easyhash9', 'Admin User', '+977-9801234575', 'Admin Office, Siraha', 'Siraha', 'Province 2', 'admin', 'active', NOW(), NOW())
ON CONFLICT (email) DO NOTHING;

-- Insert Stores
INSERT INTO stores (name, slug, description, owner_id, address, city, state, postal_code, country, latitude, longitude, phone, logo, cover_image, store_type, cuisine_type, delivery_time, minimum_order, delivery_fee, is_delivery_available, is_active, created_at, updated_at) VALUES 
(
  'Siraha Electronics Hub',
  'siraha-electronics-hub',
  'Latest electronics and gadgets for all your tech needs',
  (SELECT id FROM users WHERE email = 'electronics@shop.com'),
  'Electronics Market, Siraha, Nepal',
  'Siraha',
  'Province 2',
  '56500',
  'Nepal',
  26.6603,
  86.2064,
  '+977-9801234570',
  'https://images.unsplash.com/photo-1560472354-b33ff0c44a43?w=200&h=200&fit=crop',
  'https://images.unsplash.com/photo-1441986300917-64674bd600d8?w=800&h=400&fit=crop',
  'retail',
  NULL,
  NULL,
  NULL,
  NULL,
  false,
  true,
  NOW(),
  NOW()
),
(
  'Fashion Palace Lahan',
  'fashion-palace-lahan',
  'Latest fashion trends and traditional wear collection',
  (SELECT id FROM users WHERE email = 'fashion@shop.com'),
  'Fashion Street, Lahan, Nepal',
  'Lahan',
  'Province 2',
  '56501',
  'Nepal',
  26.7201,
  86.4928,
  '+977-9801234571',
  'https://images.unsplash.com/photo-1445205170230-053b83016050?w=200&h=200&fit=crop',
  'https://images.unsplash.com/photo-1441984904996-e0b6ba687e04?w=800&h=400&fit=crop',
  'retail',
  NULL,
  NULL,
  NULL,
  NULL,
  false,
  true,
  NOW(),
  NOW()
),
(
  'Mirchaiya Spice Kitchen',
  'mirchaiya-spice-kitchen',
  'Authentic Nepali cuisine and delicious food',
  (SELECT id FROM users WHERE email = 'restaurant@shop.com'),
  'Food Court, Mirchaiya, Nepal',
  'Mirchaiya',
  'Province 2',
  '56502',
  'Nepal',
  26.7815,
  86.4926,
  '+977-9801234572',
  'https://images.unsplash.com/photo-1571091718767-18b5b1457add?w=200&h=200&fit=crop',
  'https://images.unsplash.com/photo-1517248135467-4c7edcad34c4?w=800&h=400&fit=crop',
  'restaurant',
  'Nepali',
  '25-35 mins',
  200.00,
  50.00,
  true,
  true,
  NOW(),
  NOW()
)
ON CONFLICT (slug) DO NOTHING;

-- Insert Products
INSERT INTO products (name, slug, description, price, original_price, category_id, store_id, stock, image_url, images, is_active, product_type, preparation_time, ingredients, spice_level, is_vegetarian, created_at) VALUES 
-- Electronics Store Products
(
  'Samsung Galaxy A54 5G',
  'samsung-galaxy-a54-5g',
  'Latest 5G smartphone with excellent camera and performance',
  45000.00,
  50000.00,
  (SELECT id FROM categories WHERE name = 'Electronics'),
  (SELECT id FROM stores WHERE slug = 'siraha-electronics-hub'),
  25,
  'https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=400&h=400&fit=crop',
  ARRAY['https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=400&h=400&fit=crop'],
  true,
  'retail',
  NULL,
  ARRAY[]::text[],
  NULL,
  NULL,
  NOW()
),
(
  'Sony WH-1000XM4 Headphones',
  'sony-wh-1000xm4-headphones',
  'Industry-leading noise cancelling wireless headphones',
  28000.00,
  32000.00,
  (SELECT id FROM categories WHERE name = 'Electronics'),
  (SELECT id FROM stores WHERE slug = 'siraha-electronics-hub'),
  15,
  'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=400&h=400&fit=crop',
  ARRAY['https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=400&h=400&fit=crop'],
  true,
  'retail',
  NULL,
  ARRAY[]::text[],
  NULL,
  NULL,
  NOW()
),
(
  'Dell Laptop Inspiron 15',
  'dell-laptop-inspiron-15',
  'High performance laptop for work and gaming',
  65000.00,
  70000.00,
  (SELECT id FROM categories WHERE name = 'Electronics'),
  (SELECT id FROM stores WHERE slug = 'siraha-electronics-hub'),
  8,
  'https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=400&h=400&fit=crop',
  ARRAY['https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=400&h=400&fit=crop'],
  true,
  'retail',
  NULL,
  ARRAY[]::text[],
  NULL,
  NULL,
  NOW()
),

-- Fashion Store Products
(
  'Men''s Cotton T-Shirt',
  'mens-cotton-t-shirt',
  'Comfortable cotton t-shirt for daily wear',
  850.00,
  1000.00,
  (SELECT id FROM categories WHERE name = 'Fashion'),
  (SELECT id FROM stores WHERE slug = 'fashion-palace-lahan'),
  50,
  'https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=400&h=400&fit=crop',
  ARRAY['https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=400&h=400&fit=crop'],
  true,
  'retail',
  NULL,
  ARRAY[]::text[],
  NULL,
  NULL,
  NOW()
),
(
  'Women''s Kurta Set',
  'womens-kurta-set',
  'Traditional ethnic wear with beautiful embroidery',
  2500.00,
  3000.00,
  (SELECT id FROM categories WHERE name = 'Fashion'),
  (SELECT id FROM stores WHERE slug = 'fashion-palace-lahan'),
  30,
  'https://images.unsplash.com/photo-1583391733956-6c78276477e2?w=400&h=400&fit=crop',
  ARRAY['https://images.unsplash.com/photo-1583391733956-6c78276477e2?w=400&h=400&fit=crop'],
  true,
  'retail',
  NULL,
  ARRAY[]::text[],
  NULL,
  NULL,
  NOW()
),
(
  'Denim Jeans',
  'denim-jeans',
  'Classic blue denim jeans for casual wear',
  2200.00,
  2500.00,
  (SELECT id FROM categories WHERE name = 'Fashion'),
  (SELECT id FROM stores WHERE slug = 'fashion-palace-lahan'),
  40,
  'https://images.unsplash.com/photo-1542272604-787c3835535d?w=400&h=400&fit=crop',
  ARRAY['https://images.unsplash.com/photo-1542272604-787c3835535d?w=400&h=400&fit=crop'],
  true,
  'retail',
  NULL,
  ARRAY[]::text[],
  NULL,
  NULL,
  NOW()
),

-- Restaurant Products
(
  'Chicken Momo (10 pcs)',
  'chicken-momo-10-pcs',
  'Delicious steamed chicken dumplings with special sauce',
  180.00,
  NULL,
  (SELECT id FROM categories WHERE name = 'Food & Beverages'),
  (SELECT id FROM stores WHERE slug = 'mirchaiya-spice-kitchen'),
  100,
  'https://images.unsplash.com/photo-1496116218417-1a781b1c416c?w=400&h=400&fit=crop',
  ARRAY['https://images.unsplash.com/photo-1496116218417-1a781b1c416c?w=400&h=400&fit=crop'],
  true,
  'food',
  '15-20 mins',
  ARRAY['Chicken', 'Flour', 'Onion', 'Garlic', 'Spices'],
  'medium',
  false,
  NOW()
),
(
  'Dal Bhat Set',
  'dal-bhat-set',
  'Traditional Nepali meal with rice, lentils, and vegetables',
  220.00,
  NULL,
  (SELECT id FROM categories WHERE name = 'Food & Beverages'),
  (SELECT id FROM stores WHERE slug = 'mirchaiya-spice-kitchen'),
  50,
  'https://images.unsplash.com/photo-1585937421612-70a008356fbe?w=400&h=400&fit=crop',
  ARRAY['https://images.unsplash.com/photo-1585937421612-70a008356fbe?w=400&h=400&fit=crop'],
  true,
  'food',
  '20-25 mins',
  ARRAY['Rice', 'Lentils', 'Vegetables', 'Spices'],
  'mild',
  true,
  NOW()
),
(
  'Chicken Chow Mein',
  'chicken-chow-mein',
  'Stir-fried noodles with chicken and vegetables',
  200.00,
  NULL,
  (SELECT id FROM categories WHERE name = 'Food & Beverages'),
  (SELECT id FROM stores WHERE slug = 'mirchaiya-spice-kitchen'),
  75,
  'https://images.unsplash.com/photo-1612929633738-8fe44f7ec841?w=400&h=400&fit=crop',
  ARRAY['https://images.unsplash.com/photo-1612929633738-8fe44f7ec841?w=400&h=400&fit=crop'],
  true,
  'food',
  '18-22 mins',
  ARRAY['Noodles', 'Chicken', 'Vegetables', 'Soy Sauce', 'Spices'],
  'mild',
  false,
  NOW()
)
ON CONFLICT (slug) DO NOTHING;

-- Insert Device Tokens for Push Notifications
INSERT INTO device_tokens (user_id, token, platform, is_active, created_at) VALUES 
(1, 'eBH8i8SLNT:APA91bE8wR7JqWpQx4YQ0v5tVzNkNt5rA9nGl6XO2K8YjFyPsWz3oXkLMQrSvNpT7uGh4iWbVe3cHj9k', 'android', true, NOW()),
(2, 'fKL9j9TMOU:APA91bF9xS8KrXqRy5ZR1w6uWaOlOu6sB0oHm7YP3L9ZkGzQtXa4pYlNNRsVwOqU8vHi5jXcWf4dIk0l', 'android', true, NOW()),
(3, 'gLM0k0UNPV:APA91bG0yT9LsYrSz6aS2x7vXbPmPv7tC1pIn8ZQ4M0alHaRuYb5qZmOORtWxPrV9wIj6kYdXg5eJl1m', 'android', true, NOW()),
(4, 'hMN1l1VOQW:APA91bH1zU0MtZsSA7bT3y8wYcQnQw8uD2qJo9aR5N1bmIbSvZc6ranoOPSuXyQrW0xKj7lZeYh6fKm2n', 'android', true, NOW()),
(5, 'iNO2m2WPRX:APA91bI2aV1NuatTB8cU4z9xZdRoRx9vE3rKp0bS6O2cnJcTwad7sbopPQTvYzRsX1yLk8maeZi7gLn3o', 'android', true, NOW()),
(6, 'jOP3n3XQSY:APA91bJ3bW2OvbuUC9dV5a0yaeSpSy0wF4sLq1cT7P3doKdUxbe8tcpqQRUwZaStY2zMl9nbeaj8hMo4p', 'android', true, NOW()),
(7, 'kPQ4o4YRTZ:APA91bK4cX3PwcvVD0eW6b1zbfTqTz1xG5tMr2dU8Q4epLeVycf9udqrRSVxabTuZ3aNm0ocfbk9iNp5q', 'android', true, NOW()),
(8, 'lQR5p5ZSUA:APA91bL5dY4QxdwWE1fX7c2acgUrUa2yH6uNs3eV9R5fqMfWzdhOversSWTWycbvVA4aONn1pgdClao6r', 'android', true, NOW())
ON CONFLICT (token) DO NOTHING;

-- Insert Sample Orders
INSERT INTO orders (customer_id, store_id, total_amount, delivery_fee, tax_amount, discount_amount, status, shipping_address, billing_address, payment_method, payment_status, phone, customer_name, email, latitude, longitude, created_at, updated_at) VALUES 
(
  1,
  (SELECT id FROM stores WHERE slug = 'siraha-electronics-hub'),
  45000.00,
  100.00,
  0.00,
  5000.00,
  'delivered',
  'Siraha Main Road, Nepal',
  'Siraha Main Road, Nepal',
  'esewa',
  'completed',
  '+977-9801234567',
  'John Doe',
  'john@customer.com',
  26.6603,
  86.2064,
  NOW() - INTERVAL '2 days',
  NOW() - INTERVAL '1 day'
),
(
  2,
  (SELECT id FROM stores WHERE slug = 'mirchaiya-spice-kitchen'),
  400.00,
  50.00,
  0.00,
  0.00,
  'out_for_delivery',
  'Lahan Center, Nepal',
  'Lahan Center, Nepal',
  'cash_on_delivery',
  'pending',
  '+977-9801234568',
  'Jane Smith',
  'jane@customer.com',
  26.7201,
  86.4928,
  NOW() - INTERVAL '1 hour',
  NOW() - INTERVAL '30 minutes'
),
(
  3,
  (SELECT id FROM stores WHERE slug = 'fashion-palace-lahan'),
  3350.00,
  75.00,
  0.00,
  150.00,
  'processing',
  'Mirchaiya Bazaar, Nepal',
  'Mirchaiya Bazaar, Nepal',
  'khalti',
  'completed',
  '+977-9801234569',
  'Ram Kumar',
  'ram@customer.com',
  26.7815,
  86.4926,
  NOW() - INTERVAL '3 hours',
  NOW() - INTERVAL '2 hours'
);

-- Get the order IDs for order items
-- Insert Order Items
INSERT INTO order_items (order_id, product_id, store_id, quantity, price, total_price, created_at) VALUES 
-- Order 1 items (Electronics)
(
  (SELECT id FROM orders WHERE customer_name = 'John Doe' AND total_amount = 45000.00),
  (SELECT id FROM products WHERE slug = 'samsung-galaxy-a54-5g'),
  (SELECT id FROM stores WHERE slug = 'siraha-electronics-hub'),
  1,
  45000.00,
  45000.00,
  NOW() - INTERVAL '2 days'
),
-- Order 2 items (Food)
(
  (SELECT id FROM orders WHERE customer_name = 'Jane Smith' AND total_amount = 400.00),
  (SELECT id FROM products WHERE slug = 'chicken-momo-10-pcs'),
  (SELECT id FROM stores WHERE slug = 'mirchaiya-spice-kitchen'),
  1,
  180.00,
  180.00,
  NOW() - INTERVAL '1 hour'
),
(
  (SELECT id FROM orders WHERE customer_name = 'Jane Smith' AND total_amount = 400.00),
  (SELECT id FROM products WHERE slug = 'dal-bhat-set'),
  (SELECT id FROM stores WHERE slug = 'mirchaiya-spice-kitchen'),
  1,
  220.00,
  220.00,
  NOW() - INTERVAL '1 hour'
),
-- Order 3 items (Fashion)
(
  (SELECT id FROM orders WHERE customer_name = 'Ram Kumar' AND total_amount = 3350.00),
  (SELECT id FROM products WHERE slug = 'womens-kurta-set'),
  (SELECT id FROM stores WHERE slug = 'fashion-palace-lahan'),
  1,
  2500.00,
  2500.00,
  NOW() - INTERVAL '3 hours'
),
(
  (SELECT id FROM orders WHERE customer_name = 'Ram Kumar' AND total_amount = 3350.00),
  (SELECT id FROM products WHERE slug = 'mens-cotton-t-shirt'),
  (SELECT id FROM stores WHERE slug = 'fashion-palace-lahan'),
  1,
  850.00,
  850.00,
  NOW() - INTERVAL '3 hours'
);

-- Insert Notifications
INSERT INTO notifications (user_id, title, message, type, is_read, order_id, created_at) VALUES 
-- Customer notifications
(1, 'Order Delivered Successfully', 'Your order for Samsung Galaxy A54 has been delivered successfully!', 'order', false, (SELECT id FROM orders WHERE customer_name = 'John Doe' AND total_amount = 45000.00), NOW() - INTERVAL '1 day'),
(2, 'Order Out for Delivery', 'Your delicious meal is on the way! Estimated delivery in 25 minutes.', 'order', false, (SELECT id FROM orders WHERE customer_name = 'Jane Smith' AND total_amount = 400.00), NOW() - INTERVAL '15 minutes'),
(3, 'Order Being Processed', 'Your fashion items are being prepared for shipping.', 'order', false, (SELECT id FROM orders WHERE customer_name = 'Ram Kumar' AND total_amount = 3350.00), NOW() - INTERVAL '1 hour'),

-- Store owner notifications
((SELECT id FROM users WHERE email = 'electronics@shop.com'), 'New Order Received', 'You have received a new order for Samsung Galaxy A54 from John Doe.', 'order', false, (SELECT id FROM orders WHERE customer_name = 'John Doe' AND total_amount = 45000.00), NOW() - INTERVAL '2 days'),
((SELECT id FROM users WHERE email = 'restaurant@shop.com'), 'New Order Alert', 'New food order from Jane Smith: Chicken Momo + Dal Bhat Set', 'order', false, (SELECT id FROM orders WHERE customer_name = 'Jane Smith' AND total_amount = 400.00), NOW() - INTERVAL '1 hour'),
((SELECT id FROM users WHERE email = 'fashion@shop.com'), 'Order Processing Required', 'Process order from Ram Kumar for Kurta Set + T-Shirt', 'order', false, (SELECT id FROM orders WHERE customer_name = 'Ram Kumar' AND total_amount = 3350.00), NOW() - INTERVAL '3 hours'),

-- Delivery partner notifications
(7, 'New Delivery Assignment', 'Pick up food order from Mirchaiya Spice Kitchen → Lahan Center', 'delivery', false, (SELECT id FROM orders WHERE customer_name = 'Jane Smith' AND total_amount = 400.00), NOW() - INTERVAL '30 minutes'),
(8, 'Delivery Completed', 'Samsung Galaxy delivery completed successfully. Payment collected.', 'delivery', true, (SELECT id FROM orders WHERE customer_name = 'John Doe' AND total_amount = 45000.00), NOW() - INTERVAL '1 day'),

-- Promotional notifications
(1, 'Flash Sale Alert', '🔥 Get 30% off on all electronics! Limited time offer ending soon.', 'promotion', false, NULL, NOW() - INTERVAL '6 hours'),
(2, 'Welcome to Siraha Bazaar', 'Thank you for joining! Explore amazing deals from local stores.', 'welcome', false, NULL, NOW() - INTERVAL '1 day'),
(3, 'Weekend Special Offer', 'Free delivery on fashion items above Rs. 2000. Use code: WEEKEND50', 'promotion', false, NULL, NOW() - INTERVAL '12 hours');

-- Insert Delivery Partners
INSERT INTO delivery_partners (user_id, vehicle_type, vehicle_number, vehicle_brand, vehicle_model, driving_license, id_proof_type, id_proof_number, bank_account_number, ifsc_code, bank_name, account_holder_name, emergency_contact, emergency_contact_name, emergency_contact_relation, delivery_areas, status, is_available, rating, total_deliveries, total_earnings, created_at) VALUES 
(
  7,
  'motorcycle',
  'BA-01-PA-1234',
  'Honda',
  'CB Shine',
  'DL12345678901',
  'citizenship',
  'CIT123456789',
  '1234567890123456',
  'NABIL001',
  'Nabil Bank',
  'Gokul Yadav',
  '+977-9801234580',
  'Maya Yadav',
  'wife',
  ARRAY['Siraha', 'Lahan'],
  'approved',
  true,
  4.7,
  28,
  18500.00,
  NOW() - INTERVAL '30 days'
),
(
  8,
  'bicycle',
  'BC-02-PA-5678',
  'Hero',
  'Ranger DTB',
  NULL,
  'citizenship',
  'CIT987654321',
  '9876543210987654',
  'NCBL002',
  'Nepal Credit Bank',
  'Muna Thapa',
  '+977-9801234581',
  'Bishnu Thapa',
  'husband',
  ARRAY['Lahan', 'Mirchaiya'],
  'approved',
  true,
  4.9,
  22,
  14200.00,
  NOW() - INTERVAL '25 days'
);

-- Insert Deliveries
INSERT INTO deliveries (order_id, delivery_partner_id, status, assigned_at, picked_up_at, delivered_at, delivery_fee, pickup_address, delivery_address, estimated_distance, estimated_time, actual_time, customer_rating, customer_feedback, created_at) VALUES 
(
  (SELECT id FROM orders WHERE customer_name = 'John Doe' AND total_amount = 45000.00),
  (SELECT id FROM delivery_partners WHERE vehicle_number = 'BC-02-PA-5678'),
  'delivered',
  NOW() - INTERVAL '2 days',
  NOW() - INTERVAL '2 days' + INTERVAL '30 minutes',
  NOW() - INTERVAL '1 day',
  100.00,
  'Electronics Market, Siraha, Nepal',
  'Siraha Main Road, Nepal',
  3.2,
  20,
  18,
  5,
  'Excellent service! Very professional and quick delivery.',
  NOW() - INTERVAL '2 days'
),
(
  (SELECT id FROM orders WHERE customer_name = 'Jane Smith' AND total_amount = 400.00),
  (SELECT id FROM delivery_partners WHERE vehicle_number = 'BA-01-PA-1234'),
  'in_transit',
  NOW() - INTERVAL '45 minutes',
  NOW() - INTERVAL '30 minutes',
  NULL,
  50.00,
  'Food Court, Mirchaiya, Nepal',
  'Lahan Center, Nepal',
  8.5,
  35,
  NULL,
  NULL,
  NULL,
  NOW() - INTERVAL '45 minutes'
);

-- Insert Flash Sales
INSERT INTO flash_sales (title, description, discount_percentage, starts_at, ends_at, is_active, created_at, updated_at) VALUES 
(
  'Weekend Electronics Bonanza',
  'Massive discounts on all electronics items including smartphones, laptops, and accessories',
  30,
  NOW() - INTERVAL '6 hours',
  NOW() + INTERVAL '2 days',
  true,
  NOW() - INTERVAL '6 hours',
  NOW()
),
(
  'Fashion Friday Sale',
  'Get amazing deals on fashion items - clothes, accessories, and ethnic wear',
  25,
  NOW() + INTERVAL '1 day',
  NOW() + INTERVAL '4 days',
  true,
  NOW(),
  NOW()
);

-- Update store ratings based on completed orders
UPDATE stores SET 
  rating = 4.8,
  total_reviews = 15
WHERE slug = 'siraha-electronics-hub';

UPDATE stores SET 
  rating = 4.6,
  total_reviews = 8
WHERE slug = 'fashion-palace-lahan';

UPDATE stores SET 
  rating = 4.9,
  total_reviews = 23
WHERE slug = 'mirchaiya-spice-kitchen';

-- Update product ratings
UPDATE products SET 
  rating = 4.7,
  total_reviews = 12
WHERE slug = 'samsung-galaxy-a54-5g';

UPDATE products SET 
  rating = 4.9,
  total_reviews = 28
WHERE slug = 'chicken-momo-10-pcs';

UPDATE products SET 
  rating = 4.8,
  total_reviews = 19
WHERE slug = 'dal-bhat-set';

COMMIT;