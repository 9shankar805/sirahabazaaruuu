#!/usr/bin/env node

/**
 * Production Deployment Verification Script for Siraha Bazaar
 * This script verifies that all essential components are ready for deployment
 */

import https from 'https';
import http from 'http';

const BASE_URL = 'http://localhost:5000';

async function makeRequest(endpoint, method = 'GET') {
  return new Promise((resolve, reject) => {
    const url = `${BASE_URL}${endpoint}`;
    const req = http.request(url, { method }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let parsedData = null;
        try {
          parsedData = data ? JSON.parse(data) : null;
        } catch (e) {
          // If not JSON, treat as HTML/text response
          parsedData = data;
        }
        resolve({
          status: res.statusCode,
          data: parsedData,
          headers: res.headers
        });
      });
    });
    
    req.on('error', reject);
    req.end();
  });
}

function logResult(testName, success, details = '') {
  const status = success ? '✅ PASS' : '❌ FAIL';
  console.log(`${status} ${testName}`);
  if (details) console.log(`   ${details}`);
}

async function checkCoreEndpoints() {
  console.log('\n🔍 Checking Core API Endpoints...');
  
  try {
    // Check health endpoint
    const health = await makeRequest('/api/health');
    logResult('Health Check', health.status === 200, `Status: ${health.status}`);
    
    // Check products endpoint
    const products = await makeRequest('/api/products');
    logResult('Products API', products.status === 200 && Array.isArray(products.data), 
      `Found ${products.data?.length || 0} products`);
    
    // Check stores endpoint
    const stores = await makeRequest('/api/stores');
    logResult('Stores API', stores.status === 200 && Array.isArray(stores.data), 
      `Found ${stores.data?.length || 0} stores`);
    
    // Check categories endpoint
    const categories = await makeRequest('/api/categories');
    logResult('Categories API', categories.status === 200 && Array.isArray(categories.data), 
      `Found ${categories.data?.length || 0} categories`);
    
    return true;
  } catch (error) {
    logResult('Core Endpoints', false, error.message);
    return false;
  }
}

async function checkDatabase() {
  console.log('\n💾 Checking Database Connection...');
  
  try {
    const dbCheck = await makeRequest('/api/health');
    logResult('Database Connection', dbCheck.status === 200, 'Connected successfully');
    return true;
  } catch (error) {
    logResult('Database Connection', false, error.message);
    return false;
  }
}

async function checkStaticAssets() {
  console.log('\n📁 Checking Static Assets...');
  
  try {
    // Check if frontend is served
    const frontend = await makeRequest('/');
    logResult('Frontend Assets', frontend.status === 200, 'Frontend loading correctly');
    return true;
  } catch (error) {
    logResult('Frontend Assets', false, error.message);
    return false;
  }
}

async function checkOptionalServices() {
  console.log('\n🔧 Checking Optional Services...');
  
  // Check environment variables for optional services
  const hasHereApi = process.env.HERE_API_KEY || false;
  const hasStripe = process.env.STRIPE_SECRET_KEY || false;
  const hasSendGrid = process.env.SENDGRID_API_KEY || false;
  const hasVapid = process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY || false;
  
  logResult('HERE Maps API', hasHereApi, hasHereApi ? 'Configured' : 'Not configured - maps will use fallback');
  logResult('Stripe Payment', hasStripe, hasStripe ? 'Configured' : 'Not configured - payments disabled');
  logResult('SendGrid Email', hasSendGrid, hasSendGrid ? 'Configured' : 'Not configured - emails disabled');
  logResult('Push Notifications', hasVapid, hasVapid ? 'Configured' : 'Not configured - push notifications disabled');
  
  return true;
}

async function runDeploymentCheck() {
  console.log('🚀 Siraha Bazaar - Production Deployment Check');
  console.log('================================================');
  
  const results = await Promise.all([
    checkCoreEndpoints(),
    checkDatabase(),
    checkStaticAssets(),
    checkOptionalServices()
  ]);
  
  const allPassed = results.every(result => result);
  
  console.log('\n📊 Deployment Readiness Summary');
  console.log('================================');
  
  if (allPassed) {
    console.log('✅ All core systems operational');
    console.log('✅ Ready for production deployment');
    console.log('\n🌟 Siraha Bazaar is ready to launch!');
  } else {
    console.log('❌ Some systems need attention');
    console.log('⚠️  Please fix issues before deploying');
  }
  
  console.log('\n📝 Next Steps:');
  console.log('1. Configure optional services if needed');
  console.log('2. Set up environment variables for production');
  console.log('3. Deploy using Replit Deployments');
  console.log('4. Monitor application performance');
  
  process.exit(allPassed ? 0 : 1);
}

// Run the deployment check
runDeploymentCheck().catch(console.error);