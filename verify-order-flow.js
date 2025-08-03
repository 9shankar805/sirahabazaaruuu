import fetch from 'node-fetch';

const BASE_URL = 'http://localhost:5000';

// Test credentials - using existing users that work
const testUsers = {
  customer: { email: 'yadav', password: 'user123' }, // Known working customer
  shopkeeper: { email: 'shopkeeper@test.com', password: 'test123' },
  delivery: { email: 'delivery@test.com', password: 'test123' }
};

async function loginUser(email, password) {
  const response = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  
  if (!response.ok) {
    throw new Error(`Login failed for ${email}: ${response.statusText}`);
  }
  
  const data = await response.json();
  return data;
}

async function addToCart(userId, productId, quantity = 1) {
  const response = await fetch(`${BASE_URL}/api/cart/add`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId, productId, quantity })
  });
  
  const data = await response.json();
  return data;
}

async function createOrder(userId, cartItems) {
  const response = await fetch(`${BASE_URL}/api/orders`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      userId,
      cartItems,
      deliveryAddress: '123 Main Street, Siraha',
      paymentMethod: 'cash_on_delivery',
      totalAmount: 25000
    })
  });
  
  const data = await response.json();
  return data;
}

async function getOrders(userId, role) {
  let endpoint = '/api/orders';
  if (role === 'shopkeeper') {
    endpoint = `/api/orders/store/${userId}`;
  } else if (role === 'delivery_partner') {
    endpoint = '/api/delivery/available-orders';
  } else {
    endpoint = `/api/orders/user/${userId}`;
  }
  
  const response = await fetch(`${BASE_URL}${endpoint}`);
  const data = await response.json();
  return data;
}

async function updateOrderStatus(orderId, status, userId) {
  const response = await fetch(`${BASE_URL}/api/orders/${orderId}/status`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, userId })
  });
  
  const data = await response.json();
  return data;
}

async function assignDelivery(orderId, deliveryPartnerId) {
  const response = await fetch(`${BASE_URL}/api/delivery/assign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ orderId, deliveryPartnerId })
  });
  
  const data = await response.json();
  return data;
}

async function testOrderFlow() {
  try {
    console.log('🚀 Starting order flow test...\n');
    
    // Step 1: Login all users
    console.log('1️⃣ Logging in test users...');
    const customerLogin = await loginUser(testUsers.customer.email, testUsers.customer.password);
    const shopkeeperLogin = await loginUser(testUsers.shopkeeper.email, testUsers.shopkeeper.password);
    const deliveryLogin = await loginUser(testUsers.delivery.email, testUsers.delivery.password);
    
    console.log(`✅ Customer logged in: ${customerLogin.user.fullName} (ID: ${customerLogin.user.id})`);
    console.log(`✅ Shopkeeper logged in: ${shopkeeperLogin.user.fullName} (ID: ${shopkeeperLogin.user.id})`);
    console.log(`✅ Delivery partner logged in: ${deliveryLogin.user.fullName} (ID: ${deliveryLogin.user.id})`);
    
    // Step 2: Customer adds product to cart
    console.log('\n2️⃣ Customer adding product to cart...');
    const cartResult = await addToCart(customerLogin.user.id, 10, 1); // Product ID 10 (Test Smartphone)
    console.log('✅ Product added to cart:', cartResult);
    
    // Step 3: Customer creates order
    console.log('\n3️⃣ Customer creating order...');
    const orderResult = await createOrder(customerLogin.user.id, [
      { productId: 10, quantity: 1, price: 25000, storeId: 4 }
    ]);
    console.log('✅ Order created:', orderResult);
    
    const orderId = orderResult.order?.id;
    if (!orderId) {
      throw new Error('Order creation failed - no order ID returned');
    }
    
    // Wait a moment for order to be processed
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Step 4: Shopkeeper views order
    console.log('\n4️⃣ Shopkeeper checking for new orders...');
    const shopkeeperOrders = await getOrders(shopkeeperLogin.user.id, 'shopkeeper');
    console.log('📦 Shopkeeper orders:', shopkeeperOrders);
    
    // Step 5: Shopkeeper confirms order
    console.log('\n5️⃣ Shopkeeper confirming order...');
    const confirmResult = await updateOrderStatus(orderId, 'confirmed', shopkeeperLogin.user.id);
    console.log('✅ Order confirmed by shopkeeper:', confirmResult);
    
    // Step 6: Shopkeeper marks order as ready for pickup
    console.log('\n6️⃣ Shopkeeper marking order ready for pickup...');
    const readyResult = await updateOrderStatus(orderId, 'ready_for_pickup', shopkeeperLogin.user.id);
    console.log('✅ Order ready for pickup:', readyResult);
    
    // Step 7: Delivery partner views available orders
    console.log('\n7️⃣ Delivery partner checking available orders...');
    const availableOrders = await getOrders(deliveryLogin.user.id, 'delivery_partner');
    console.log('🛵 Available orders for delivery:', availableOrders);
    
    // Step 8: Assign delivery partner to order
    console.log('\n8️⃣ Assigning delivery partner to order...');
    const assignResult = await assignDelivery(orderId, deliveryLogin.user.id);
    console.log('✅ Delivery partner assigned:', assignResult);
    
    // Step 9: Delivery partner updates status
    console.log('\n9️⃣ Delivery partner picking up order...');
    const pickupResult = await updateOrderStatus(orderId, 'picked_up', deliveryLogin.user.id);
    console.log('✅ Order picked up:', pickupResult);
    
    console.log('\n🔟 Delivery partner out for delivery...');
    const deliveryResult = await updateOrderStatus(orderId, 'out_for_delivery', deliveryLogin.user.id);
    console.log('✅ Order out for delivery:', deliveryResult);
    
    console.log('\n🏁 Delivery partner delivering order...');
    const completedResult = await updateOrderStatus(orderId, 'delivered', deliveryLogin.user.id);
    console.log('✅ Order delivered:', completedResult);
    
    // Final verification - check order status
    console.log('\n🎉 Order flow completed successfully!');
    console.log('📋 Final order verification...');
    
    const finalCustomerOrders = await getOrders(customerLogin.user.id, 'customer');
    const completedOrder = finalCustomerOrders.find(order => order.id === orderId);
    
    if (completedOrder) {
      console.log(`✅ Order ${orderId} final status: ${completedOrder.status}`);
      console.log('🎯 Order flow test PASSED! ✨');
    } else {
      console.log('❌ Order not found in customer orders');
    }
    
  } catch (error) {
    console.error('❌ Order flow test FAILED:', error.message);
    console.error('Stack trace:', error.stack);
  }
}

// Run the test
testOrderFlow();