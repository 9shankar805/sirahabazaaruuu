const fetch = require('node-fetch');

async function testLogin() {
  console.log('Testing login functionality...');
  
  try {
    // Test 1: Regular email/password login
    console.log('\n1. Testing email/password login...');
    const loginResponse = await fetch('http://localhost:5000/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'customer@example.com',
        password: 'password123'
      })
    });
    
    console.log('Login response status:', loginResponse.status);
    const loginData = await loginResponse.json();
    console.log('Login response:', loginData);
    
    // Test 2: Check if server is running
    console.log('\n2. Testing server health...');
    const healthResponse = await fetch('http://localhost:5000/api/debug-test');
    console.log('Health response status:', healthResponse.status);
    const healthData = await healthResponse.json();
    console.log('Health response:', healthData);
    
  } catch (error) {
    console.error('Test failed:', error.message);
  }
}

testLogin(); 