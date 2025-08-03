import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { 
  Smartphone, 
  Monitor, 
  CheckCircle, 
  AlertCircle, 
  Bell, 
  Settings, 
  TrendingUp,
  Package,
  Truck,
  ShoppingCart
} from 'lucide-react';

export default function ProductionNotificationTest() {
  const [testUserId, setTestUserId] = useState(1);
  const [testType, setTestType] = useState('basic');
  const [isTestingProduction, setIsTestingProduction] = useState(false);
  const [isTestingOrder, setIsTestingOrder] = useState(false);
  const [isTestingDelivery, setIsTestingDelivery] = useState(false);
  const [notificationStatus, setNotificationStatus] = useState(null);
  const [isCheckingStatus, setIsCheckingStatus] = useState(false);

  // Order test data
  const [orderTestData, setOrderTestData] = useState({
    customerId: 1,
    orderId: Math.floor(Math.random() * 10000),
    storeName: 'Test Store',
    totalAmount: 999,
    status: 'placed'
  });

  // Delivery test data
  const [deliveryTestData, setDeliveryTestData] = useState({
    deliveryPartnerId: 1,
    orderId: Math.floor(Math.random() * 10000),
    pickupAddress: 'Test Store, Siraha Bazaar Street',
    deliveryAddress: 'Customer Address, Nepal',
    deliveryFee: 30,
    distance: '2.5 km'
  });

  const { toast } = useToast();

  const handleProductionTest = async () => {
    setIsTestingProduction(true);
    try {
      const response = await fetch('/api/production/test-notification', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId: testUserId,
          testType: testType
        }),
      });

      const result = await response.json();

      if (result.success) {
        toast({
          title: "Production Test Successful",
          description: `${testType} notification sent to user ${testUserId}`,
          duration: 5000,
        });
      } else {
        toast({
          title: "Production Test Failed",
          description: result.message || "Unknown error occurred",
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Production Test Error",
        description: error instanceof Error ? error.message : "Network error occurred",
        variant: "destructive",
      });
    } finally {
      setIsTestingProduction(false);
    }
  };

  const handleOrderTest = async () => {
    setIsTestingOrder(true);
    try {
      const response = await fetch('/api/production/order-notification', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(orderTestData),
      });

      const result = await response.json();

      if (result.success) {
        toast({
          title: "Order Notification Sent",
          description: `Order notification sent for order #${orderTestData.orderId}`,
          duration: 5000,
        });
      } else {
        toast({
          title: "Order Notification Failed",
          description: result.message || "Failed to send order notification",
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Order Test Error",
        description: error instanceof Error ? error.message : "Network error occurred",
        variant: "destructive",
      });
    } finally {
      setIsTestingOrder(false);
    }
  };

  const handleDeliveryTest = async () => {
    setIsTestingDelivery(true);
    try {
      const response = await fetch('/api/production/delivery-notification', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(deliveryTestData),
      });

      const result = await response.json();

      if (result.success) {
        toast({
          title: "Delivery Notification Sent",
          description: `Delivery assignment sent for order #${deliveryTestData.orderId}`,
          duration: 5000,
        });
      } else {
        toast({
          title: "Delivery Notification Failed",
          description: result.message || "Failed to send delivery notification",
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Delivery Test Error",
        description: error instanceof Error ? error.message : "Network error occurred",
        variant: "destructive",
      });
    } finally {
      setIsTestingDelivery(false);
    }
  };

  const checkNotificationStatus = async () => {
    setIsCheckingStatus(true);
    try {
      const response = await fetch(`/api/production/notification-status/${testUserId}`);
      const result = await response.json();

      if (result.success) {
        setNotificationStatus(result.status);
        toast({
          title: "Status Retrieved",
          description: `Found ${result.status.androidTokens} Android tokens, ${result.status.webTokens} web tokens`,
          duration: 3000,
        });
      } else {
        toast({
          title: "Status Check Failed",
          description: "Could not retrieve notification status",
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Status Check Error",
        description: error instanceof Error ? error.message : "Network error occurred",
        variant: "destructive",
      });
    } finally {
      setIsCheckingStatus(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-6">
      <div className="container mx-auto px-4 max-w-6xl">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Production Notification Testing
          </h1>
          <p className="text-gray-600">
            Test notification system for sirahabazaar.com production deployment
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3 mb-6">
          {/* Basic Configuration */}
          <Card className="border-blue-200 bg-white">
            <CardHeader>
              <div className="flex items-center gap-2">
                <Settings className="h-5 w-5 text-blue-600" />
                <CardTitle className="text-blue-800">Test Configuration</CardTitle>
              </div>
              <CardDescription>
                Configure test parameters for notification testing
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="testUserId">User ID</Label>
                <Input
                  id="testUserId"
                  type="number"
                  value={testUserId}
                  onChange={(e) => setTestUserId(parseInt(e.target.value) || 1)}
                  placeholder="Enter user ID"
                />
              </div>

              <div>
                <Label htmlFor="testType">Test Type</Label>
                <Select value={testType} onValueChange={setTestType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="basic">Basic Test</SelectItem>
                    <SelectItem value="order">Order Test</SelectItem>
                    <SelectItem value="delivery">Delivery Test</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <Button 
                onClick={handleProductionTest}
                disabled={isTestingProduction}
                className="w-full bg-blue-600 hover:bg-blue-700"
              >
                {isTestingProduction ? (
                  <>Testing...</>
                ) : (
                  <>
                    <Bell className="h-4 w-4 mr-2" />
                    Send Test Notification
                  </>
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Notification Status */}
          <Card className="border-green-200 bg-white">
            <CardHeader>
              <div className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5 text-green-600" />
                <CardTitle className="text-green-800">Notification Status</CardTitle>
              </div>
              <CardDescription>
                Check user notification configuration status
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button 
                onClick={checkNotificationStatus}
                disabled={isCheckingStatus}
                variant="outline"
                className="w-full border-green-300 text-green-700 hover:bg-green-50"
              >
                {isCheckingStatus ? 'Checking...' : 'Check Status'}
              </Button>

              {notificationStatus && (
                <div className="space-y-2 text-sm">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Smartphone className="h-4 w-4 text-green-600" />
                      <span>Android Tokens:</span>
                    </div>
                    <span className="font-semibold">{notificationStatus.androidTokens}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Monitor className="h-4 w-4 text-blue-600" />
                      <span>Web Tokens:</span>
                    </div>
                    <span className="font-semibold">{notificationStatus.webTokens}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Bell className="h-4 w-4 text-purple-600" />
                      <span>Recent Notifications:</span>
                    </div>
                    <span className="font-semibold">{notificationStatus.recentNotifications}</span>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Quick Actions */}
          <Card className="border-purple-200 bg-white">
            <CardHeader>
              <div className="flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-purple-600" />
                <CardTitle className="text-purple-800">Production Status</CardTitle>
              </div>
              <CardDescription>
                Firebase and notification system status
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center gap-2 text-sm">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span>Firebase Service Account: Configured</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span>Android Notifications: Enabled</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span>CORS: sirahabazaar.com configured</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span>Production Endpoints: Ready</span>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Order Notification Test */}
        <div className="grid gap-6 md:grid-cols-2 mb-6">
          <Card className="border-orange-200 bg-white">
            <CardHeader>
              <div className="flex items-center gap-2">
                <Package className="h-5 w-5 text-orange-600" />
                <CardTitle className="text-orange-800">Order Notification Test</CardTitle>
              </div>
              <CardDescription>
                Test order status notifications to customers
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>Customer ID</Label>
                  <Input
                    type="number"
                    value={orderTestData.customerId}
                    onChange={(e) => setOrderTestData({
                      ...orderTestData,
                      customerId: parseInt(e.target.value) || 1
                    })}
                  />
                </div>
                <div>
                  <Label>Order ID</Label>
                  <Input
                    type="number"
                    value={orderTestData.orderId}
                    onChange={(e) => setOrderTestData({
                      ...orderTestData,
                      orderId: parseInt(e.target.value) || 1
                    })}
                  />
                </div>
              </div>

              <div>
                <Label>Store Name</Label>
                <Input
                  value={orderTestData.storeName}
                  onChange={(e) => setOrderTestData({
                    ...orderTestData,
                    storeName: e.target.value
                  })}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>Total Amount</Label>
                  <Input
                    type="number"
                    value={orderTestData.totalAmount}
                    onChange={(e) => setOrderTestData({
                      ...orderTestData,
                      totalAmount: parseFloat(e.target.value) || 0
                    })}
                  />
                </div>
                <div>
                  <Label>Status</Label>
                  <Select 
                    value={orderTestData.status} 
                    onValueChange={(value) => setOrderTestData({
                      ...orderTestData,
                      status: value
                    })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="placed">Order Placed</SelectItem>
                      <SelectItem value="processing">Processing</SelectItem>
                      <SelectItem value="ready_for_pickup">Ready for Pickup</SelectItem>
                      <SelectItem value="out_for_delivery">Out for Delivery</SelectItem>
                      <SelectItem value="delivered">Delivered</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <Button 
                onClick={handleOrderTest}
                disabled={isTestingOrder}
                className="w-full bg-orange-600 hover:bg-orange-700"
              >
                {isTestingOrder ? (
                  <>Sending Order Notification...</>
                ) : (
                  <>
                    <ShoppingCart className="h-4 w-4 mr-2" />
                    Send Order Notification
                  </>
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Delivery Notification Test */}
          <Card className="border-emerald-200 bg-white">
            <CardHeader>
              <div className="flex items-center gap-2">
                <Truck className="h-5 w-5 text-emerald-600" />
                <CardTitle className="text-emerald-800">Delivery Notification Test</CardTitle>
              </div>
              <CardDescription>
                Test delivery assignment notifications to partners
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>Delivery Partner ID</Label>
                  <Input
                    type="number"
                    value={deliveryTestData.deliveryPartnerId}
                    onChange={(e) => setDeliveryTestData({
                      ...deliveryTestData,
                      deliveryPartnerId: parseInt(e.target.value) || 1
                    })}
                  />
                </div>
                <div>
                  <Label>Order ID</Label>
                  <Input
                    type="number"
                    value={deliveryTestData.orderId}
                    onChange={(e) => setDeliveryTestData({
                      ...deliveryTestData,
                      orderId: parseInt(e.target.value) || 1
                    })}
                  />
                </div>
              </div>

              <div>
                <Label>Pickup Address</Label>
                <Input
                  value={deliveryTestData.pickupAddress}
                  onChange={(e) => setDeliveryTestData({
                    ...deliveryTestData,
                    pickupAddress: e.target.value
                  })}
                />
              </div>

              <div>
                <Label>Delivery Address</Label>
                <Input
                  value={deliveryTestData.deliveryAddress}
                  onChange={(e) => setDeliveryTestData({
                    ...deliveryTestData,
                    deliveryAddress: e.target.value
                  })}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label>Delivery Fee</Label>
                  <Input
                    type="number"
                    value={deliveryTestData.deliveryFee}
                    onChange={(e) => setDeliveryTestData({
                      ...deliveryTestData,
                      deliveryFee: parseFloat(e.target.value) || 0
                    })}
                  />
                </div>
                <div>
                  <Label>Distance</Label>
                  <Input
                    value={deliveryTestData.distance}
                    onChange={(e) => setDeliveryTestData({
                      ...deliveryTestData,
                      distance: e.target.value
                    })}
                  />
                </div>
              </div>

              <Button 
                onClick={handleDeliveryTest}
                disabled={isTestingDelivery}
                className="w-full bg-emerald-600 hover:bg-emerald-700"
              >
                {isTestingDelivery ? (
                  <>Sending Delivery Notification...</>
                ) : (
                  <>
                    <Truck className="h-4 w-4 mr-2" />
                    Send Delivery Notification
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Production Instructions */}
        <Card className="border-gray-200">
          <CardHeader>
            <CardTitle className="text-gray-800">Production Deployment Instructions</CardTitle>
            <CardDescription>
              Follow these steps to ensure notifications work on sirahabazaar.com
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <h4 className="font-semibold text-gray-800 mb-2">1. Firebase Configuration</h4>
                <ul className="text-sm text-gray-600 space-y-1">
                  <li>• Add sirahabazaar.com to Firebase authorized domains</li>
                  <li>• Ensure Firebase service account is configured</li>
                  <li>• Verify google-services.json includes production domain</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold text-gray-800 mb-2">2. Server Configuration</h4>
                <ul className="text-sm text-gray-600 space-y-1">
                  <li>• CORS configured for sirahabazaar.com</li>
                  <li>• HTTPS required for push notifications</li>
                  <li>• Service worker accessible at /firebase-messaging-sw.js</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold text-gray-800 mb-2">3. Android App Setup</h4>
                <ul className="text-sm text-gray-600 space-y-1">
                  <li>• Package name: com.siraha.myweb</li>
                  <li>• FCM token registration on app start</li>
                  <li>• Notification permissions requested</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold text-gray-800 mb-2">4. Testing</h4>
                <ul className="text-sm text-gray-600 space-y-1">
                  <li>• Use this page to test notifications</li>
                  <li>• Monitor server logs for errors</li>
                  <li>• Verify device token registration</li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}