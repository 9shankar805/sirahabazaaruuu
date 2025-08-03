import fetch from 'node-fetch';

async function testLoginMethods() {
  console.log('Testing login methods...');
  
  try {
    // Test 1: Regular email/password login
    console.log('\n1. Testing email/password login...');
    const loginResponse = await fetch('http://localhost:5000/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'john@customer.com',
        password: 'password123'
      })
    });
    
    console.log('Login response status:', loginResponse.status);
    const loginData = await loginResponse.json();
    console.log('Login response:', loginData);
    
    // Test 2: Firebase login (for Google/Phone)
    console.log('\n2. Testing Firebase login...');
    const firebaseResponse = await fetch('http://localhost:5000/api/auth/firebase-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        firebaseUid: 'test123',
        email: 'test@example.com',
        phone: '+9779801234567',
        displayName: 'Test User'
      })
    });
    
    console.log('Firebase login response status:', firebaseResponse.status);
    const firebaseData = await firebaseResponse.json();
    console.log('Firebase login response:', firebaseData);
    
    // Test 3: Check if server is running
    console.log('\n3. Testing server health...');
    const healthResponse = await fetch('http://localhost:5000/api/debug-test');
    console.log('Health response status:', healthResponse.status);
    const healthData = await healthResponse.json();
    console.log('Health response:', healthData);
    
  } catch (error) {
    console.error('Test failed:', error.message);
  }
}

testLoginMethods(); 