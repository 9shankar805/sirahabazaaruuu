import React, { useState, useEffect } from 'react';
import { PWAService } from '../utils/pwa';
import { Download, Bell, Smartphone, Wifi, WifiOff } from 'lucide-react';

export default function PWATest() {
  const [isInstalled, setIsInstalled] = useState(false);
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const [swRegistration, setSwRegistration] = useState<ServiceWorkerRegistration | null>(null);
  const [notificationPermission, setNotificationPermission] = useState<NotificationPermission>('default');
  const [testResults, setTestResults] = useState<any[]>([]);

  useEffect(() => {
    // Check PWA installation status
    setIsInstalled(PWAService.isPWA());
    
    // Check notification permission
    setNotificationPermission(Notification.permission);
    
    // Get service worker registration
    navigator.serviceWorker.ready.then(reg => {
      setSwRegistration(reg);
    });

    // Listen for online/offline events
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);
    
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    
    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  const runPWATests = async () => {
    const results = [];
    
    // Test 1: Service Worker Registration
    try {
      const registration = await navigator.serviceWorker.ready;
      results.push({
        test: 'Service Worker Registration',
        status: 'passed',
        details: `Registered at scope: ${registration.scope}`
      });
    } catch (error) {
      results.push({
        test: 'Service Worker Registration',
        status: 'failed',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }

    // Test 2: Cache API
    try {
      const cacheNames = await caches.keys();
      results.push({
        test: 'Cache API',
        status: 'passed',
        details: `${cacheNames.length} caches found: ${cacheNames.join(', ')}`
      });
    } catch (error) {
      results.push({
        test: 'Cache API',
        status: 'failed',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }

    // Test 3: Manifest Parsing
    try {
      const response = await fetch('/manifest.json');
      const manifest = await response.json();
      results.push({
        test: 'Web App Manifest',
        status: 'passed',
        details: `App: ${manifest.name}, Icons: ${manifest.icons.length}`
      });
    } catch (error) {
      results.push({
        test: 'Web App Manifest',
        status: 'failed',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }

    // Test 4: Notification API
    try {
      if ('Notification' in window) {
        results.push({
          test: 'Notification API',
          status: 'passed',
          details: `Permission: ${Notification.permission}`
        });
      } else {
        results.push({
          test: 'Notification API',
          status: 'failed',
          details: 'Notifications not supported'
        });
      }
    } catch (error) {
      results.push({
        test: 'Notification API',
        status: 'failed',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }

    // Test 5: Push Messaging
    try {
      const registration = await navigator.serviceWorker.ready;
      const subscription = await registration.pushManager.getSubscription();
      results.push({
        test: 'Push Messaging',
        status: subscription ? 'passed' : 'warning',
        details: subscription ? 'Push subscription active' : 'No push subscription found'
      });
    } catch (error) {
      results.push({
        test: 'Push Messaging',
        status: 'failed',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }

    setTestResults(results);
  };

  const testNotification = async () => {
    try {
      await PWAService.showNotification({
        title: 'PWA Test Notification',
        body: 'This is a test notification from Siraha Bazaar PWA!',
        data: { test: true }
      });
    } catch (error) {
      console.error('Test notification failed:', error);
    }
  };

  const installPWA = async () => {
    try {
      const success = await PWAService.installPWA();
      if (success) {
        setIsInstalled(true);
      }
    } catch (error) {
      console.error('PWA installation failed:', error);
    }
  };

  const requestNotificationPermission = async () => {
    const permission = await PWAService.requestNotificationPermission();
    setNotificationPermission(Notification.permission);
    return permission;
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-8">
      <div className="max-w-4xl mx-auto px-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-8">
            PWA Testing Dashboard
          </h1>

          {/* PWA Status */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <div className="bg-blue-50 dark:bg-blue-900 p-4 rounded-lg">
              <div className="flex items-center">
                <Smartphone className="w-8 h-8 text-blue-600 dark:text-blue-400 mr-3" />
                <div>
                  <div className="text-sm font-medium text-blue-600 dark:text-blue-400">
                    PWA Status
                  </div>
                  <div className="text-lg font-bold text-blue-900 dark:text-blue-100">
                    {isInstalled ? 'Installed' : 'Web Browser'}
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-green-50 dark:bg-green-900 p-4 rounded-lg">
              <div className="flex items-center">
                {isOnline ? (
                  <Wifi className="w-8 h-8 text-green-600 dark:text-green-400 mr-3" />
                ) : (
                  <WifiOff className="w-8 h-8 text-red-600 dark:text-red-400 mr-3" />
                )}
                <div>
                  <div className="text-sm font-medium text-green-600 dark:text-green-400">
                    Network
                  </div>
                  <div className="text-lg font-bold text-green-900 dark:text-green-100">
                    {isOnline ? 'Online' : 'Offline'}
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-purple-50 dark:bg-purple-900 p-4 rounded-lg">
              <div className="flex items-center">
                <Bell className="w-8 h-8 text-purple-600 dark:text-purple-400 mr-3" />
                <div>
                  <div className="text-sm font-medium text-purple-600 dark:text-purple-400">
                    Notifications
                  </div>
                  <div className="text-lg font-bold text-purple-900 dark:text-purple-100">
                    {notificationPermission === 'granted' ? 'Enabled' : 
                     notificationPermission === 'denied' ? 'Blocked' : 'Pending'}
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-orange-50 dark:bg-orange-900 p-4 rounded-lg">
              <div className="flex items-center">
                <Download className="w-8 h-8 text-orange-600 dark:text-orange-400 mr-3" />
                <div>
                  <div className="text-sm font-medium text-orange-600 dark:text-orange-400">
                    Service Worker
                  </div>
                  <div className="text-lg font-bold text-orange-900 dark:text-orange-100">
                    {swRegistration ? 'Active' : 'Inactive'}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-4 mb-8">
            <button
              onClick={runPWATests}
              className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg transition-colors"
            >
              Run PWA Tests
            </button>
            
            {!isInstalled && (
              <button
                onClick={installPWA}
                className="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded-lg transition-colors"
              >
                Install PWA
              </button>
            )}
            
            {notificationPermission !== 'granted' && (
              <button
                onClick={requestNotificationPermission}
                className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-2 rounded-lg transition-colors"
              >
                Enable Notifications
              </button>
            )}
            
            <button
              onClick={testNotification}
              className="bg-orange-600 hover:bg-orange-700 text-white px-6 py-2 rounded-lg transition-colors"
            >
              Test Notification
            </button>
          </div>

          {/* Test Results */}
          {testResults.length > 0 && (
            <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-6">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
                Test Results
              </h2>
              <div className="space-y-3">
                {testResults.map((result, index) => (
                  <div key={index} className="flex items-start space-x-3">
                    <div className={`w-3 h-3 rounded-full mt-1 ${
                      result.status === 'passed' ? 'bg-green-500' :
                      result.status === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
                    }`} />
                    <div className="flex-1">
                      <div className="font-medium text-gray-900 dark:text-white">
                        {result.test}
                      </div>
                      <div className="text-sm text-gray-600 dark:text-gray-400">
                        {result.details}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}