import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { MapPin, Package, Truck, Users, Clock, Navigation } from 'lucide-react';
import { DeliveryTrackingMap } from '../components/tracking/DeliveryTrackingMap';
import { DeliveryTrackingDashboard } from '../components/tracking/DeliveryTrackingDashboard';

interface DeliveryData {
  id: number;
  orderId: number;
  status: string;
  deliveryPartnerId?: number;
  pickupAddress: string;
  deliveryAddress: string;
  createdAt: string;
}

interface PartnerData {
  id: number;
  name: string;
  phone: string;
  vehicleType: string;
  status: string;
  rating: string;
}

interface TrackingData {
  deliveries: DeliveryData[];
  deliveryPartners: PartnerData[];
  orders: any[];
}

export default function TrackingDemo() {
  const [demoData, setDemoData] = useState<TrackingData>({
    deliveries: [],
    deliveryPartners: [],
    orders: []
  });
  const [selectedDeliveryId, setSelectedDeliveryId] = useState<number | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [demoMode, setDemoMode] = useState<'customer' | 'shopkeeper' | 'delivery_partner'>('customer');

  useEffect(() => {
    loadDemoData();
  }, []);

  const loadDemoData = async () => {
    try {
      // Load real delivery and partner data from the enhanced tracking endpoint
      const trackingRes = await fetch('/api/tracking/demo-data');
      
      if (trackingRes.ok) {
        const trackingData = await trackingRes.json();
        
        setDemoData({
          deliveries: trackingData.deliveries || [],
          deliveryPartners: trackingData.deliveryPartners || [],
          orders: trackingData.orders || []
        });

        // Auto-select first active delivery if available
        if (trackingData.deliveries && trackingData.deliveries.length > 0) {
          setSelectedDeliveryId(trackingData.deliveries[0].id);
        }

        console.log('Loaded real tracking data:', {
          deliveries: trackingData.deliveries?.length || 0,
          partners: trackingData.deliveryPartners?.length || 0,
          message: trackingData.message
        });
      } else {
        // Fallback to individual API calls if tracking endpoint fails
        const [deliveriesRes, partnersRes, ordersRes] = await Promise.all([
          fetch('/api/deliveries'),
          fetch('/api/delivery-partners'),
          fetch('/api/orders')
        ]);

        const deliveries = deliveriesRes.ok ? await deliveriesRes.json() : [];
        const partners = partnersRes.ok ? await partnersRes.json() : [];
        const orders = ordersRes.ok ? await ordersRes.json() : [];

        // Filter for active deliveries with assigned partners
        const activeDeliveries = deliveries.filter((delivery: any) => 
          delivery.deliveryPartnerId && 
          ['assigned', 'en_route_pickup', 'picked_up', 'en_route_delivery'].includes(delivery.status)
        );

        setDemoData({
          deliveries: activeDeliveries,
          deliveryPartners: partners.map((partner: any) => ({
            ...partner,
            name: partner.fullName || partner.name,
            realData: true
          })),
          orders: orders
        });

        if (activeDeliveries.length > 0) {
          setSelectedDeliveryId(activeDeliveries[0].id);
        }
      }

      setIsLoading(false);
    } catch (error) {
      console.error('Error loading tracking data:', error);
      setIsLoading(false);
    }
  };

  const createDemoDelivery = async () => {
    try {
      // Create a demo delivery with test data
      const demoDelivery = {
        orderId: Math.floor(Math.random() * 1000) + 100,
        deliveryPartnerId: null,
        deliveryFee: '50.00',
        pickupAddress: 'Tech World Electronics, Mall Road, Kanpur, UP 208001',
        deliveryAddress: 'IIT Kanpur, Kalyanpur, Kanpur, UP 208016',
        estimatedDistance: 12.5,
        estimatedTime: 25,
        specialInstructions: 'Handle with care - Electronics item'
      };

      const response = await fetch('/api/deliveries', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(demoDelivery)
      });

      if (response.ok) {
        const newDelivery = await response.json();
        setDemoData(prev => ({
          ...prev,
          deliveries: [newDelivery, ...prev.deliveries]
        }));
        setSelectedDeliveryId(newDelivery.id);
        
        // Initialize tracking for the new delivery
        await fetch(`/api/tracking/initialize/${newDelivery.id}`, {
          method: 'POST'
        });
      }
    } catch (error) {
      console.error('Error creating demo delivery:', error);
    }
  };

  const assignDeliveryPartner = async (deliveryId: number, partnerId: number) => {
    try {
      const response = await fetch(`/api/deliveries/${deliveryId}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: 'assigned',
          partnerId: partnerId
        })
      });

      if (response.ok) {
        loadDemoData();
      }
    } catch (error) {
      console.error('Error assigning delivery partner:', error);
    }
  };

  const simulateLocationUpdate = async (deliveryId: number) => {
    // Simulate delivery partner movement
    const locations = [
      { lat: 26.4499, lng: 80.3319 }, // Starting point
      { lat: 26.4520, lng: 80.3350 }, // Moving towards pickup
      { lat: 26.4545, lng: 80.3380 }, // At pickup location
      { lat: 26.4580, lng: 80.3420 }, // Moving towards delivery
      { lat: 26.5144, lng: 80.2329 }  // At delivery location (IIT Kanpur)
    ];

    for (let i = 0; i < locations.length; i++) {
      await new Promise(resolve => setTimeout(resolve, 2000)); // 2 second delay
      
      await fetch('/api/tracking/location', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deliveryId,
          latitude: locations[i].lat,
          longitude: locations[i].lng,
          speed: Math.random() * 30 + 10, // 10-40 km/h
          heading: Math.random() * 360
        })
      });

      // Update status at key points
      if (i === 2) {
        await fetch('/api/tracking/status', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deliveryId,
            status: 'picked_up',
            description: 'Order picked up from store'
          })
        });
      } else if (i === 4) {
        await fetch('/api/tracking/status', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            deliveryId,
            status: 'delivered',
            description: 'Order delivered successfully'
          })
        });
      }
    }
  };

  if (isLoading) {
    return (
      <div className="container mx-auto p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
            <p>Loading tracking demo...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-4">
          Real-Time Order Tracking System
        </h1>
        <p className="text-lg text-gray-600 mb-6">
          Experience live delivery tracking with HERE Maps integration, WebSocket notifications, and comprehensive dashboard views
        </p>
        
        {/* Feature Highlights */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <Card className="p-4">
            <div className="flex items-center space-x-3">
              <MapPin className="h-8 w-8 text-blue-500" />
              <div>
                <h3 className="font-semibold">HERE Maps</h3>
                <p className="text-sm text-gray-600">Live route calculation</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center space-x-3">
              <Truck className="h-8 w-8 text-green-500" />
              <div>
                <h3 className="font-semibold">Real-Time Tracking</h3>
                <p className="text-sm text-gray-600">Live location updates</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center space-x-3">
              <Users className="h-8 w-8 text-purple-500" />
              <div>
                <h3 className="font-semibold">Multi-User Views</h3>
                <p className="text-sm text-gray-600">Customer, shop, partner</p>
              </div>
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center space-x-3">
              <Clock className="h-8 w-8 text-orange-500" />
              <div>
                <h3 className="font-semibold">Live Notifications</h3>
                <p className="text-sm text-gray-600">WebSocket updates</p>
              </div>
            </div>
          </Card>
        </div>
      </div>

      {/* Demo Controls */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>Demo Controls</span>
            <div className="flex space-x-2">
              <Button onClick={createDemoDelivery} size="sm">
                Create Demo Delivery
              </Button>
              {selectedDeliveryId && (
                <Button 
                  onClick={() => simulateLocationUpdate(selectedDeliveryId)}
                  variant="outline"
                  size="sm"
                >
                  Simulate Movement
                </Button>
              )}
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <Label>View Mode</Label>
              <div className="flex space-x-2 mt-2">
                {(['customer', 'shopkeeper', 'delivery_partner'] as const).map((mode) => (
                  <Button
                    key={mode}
                    variant={demoMode === mode ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setDemoMode(mode)}
                  >
                    {mode.replace('_', ' ').toUpperCase()}
                  </Button>
                ))}
              </div>
            </div>
            <div>
              <Label>Active Deliveries</Label>
              <Badge variant="outline" className="ml-2">
                {demoData.deliveries.length} total
              </Badge>
            </div>
            <div>
              <Label>Available Partners</Label>
              <Badge variant="outline" className="ml-2">
                {demoData.deliveryPartners.length} online
              </Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">System Overview</TabsTrigger>
          <TabsTrigger value="tracking">Live Tracking</TabsTrigger>
          <TabsTrigger value="partner">Partner Dashboard</TabsTrigger>
          <TabsTrigger value="admin">Admin Panel</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Current Deliveries */}
            <Card>
              <CardHeader>
                <CardTitle>Active Deliveries</CardTitle>
              </CardHeader>
              <CardContent>
                {demoData.deliveries.length === 0 ? (
                  <div className="text-center py-8">
                    <Package className="h-12 w-12 text-gray-300 mx-auto mb-4" />
                    <p className="text-gray-500">No active deliveries</p>
                    <Button onClick={createDemoDelivery} className="mt-4">
                      Create Demo Delivery
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {demoData.deliveries.slice(0, 5).map((delivery: any) => (
                      <div 
                        key={delivery.id}
                        className={`p-3 border rounded-lg cursor-pointer transition-colors ${
                          selectedDeliveryId === delivery.id 
                            ? 'border-blue-500 bg-blue-50' 
                            : 'border-gray-200 hover:border-gray-300'
                        }`}
                        onClick={() => setSelectedDeliveryId(delivery.id)}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-medium">Delivery #{delivery.id}</span>
                          <Badge variant="outline">{delivery.status || 'pending'}</Badge>
                        </div>
                        <p className="text-sm text-gray-600">{delivery.pickupAddress}</p>
                        <p className="text-sm text-gray-600">→ {delivery.deliveryAddress}</p>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* System Status */}
            <Card>
              <CardHeader>
                <CardTitle>System Status</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">HERE Maps API</span>
                    <Badge className="bg-green-500 text-white">Connected</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">WebSocket Server</span>
                    <Badge className="bg-green-500 text-white">Active</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Real-time Tracking</span>
                    <Badge className="bg-green-500 text-white">Enabled</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Push Notifications</span>
                    <Badge className="bg-green-500 text-white">Ready</Badge>
                  </div>
                </div>

                <div className="mt-6">
                  <h4 className="font-medium mb-3">Key Features</h4>
                  <ul className="text-sm text-gray-600 space-y-1">
                    <li>• Real-time GPS tracking with HERE Maps</li>
                    <li>• WebSocket-based live updates</li>
                    <li>• Multi-user role support (customer, shopkeeper, delivery partner)</li>
                    <li>• Route optimization and ETA calculations</li>
                    <li>• Push notifications for status changes</li>
                    <li>• Google Maps integration for navigation</li>
                    <li>• Comprehensive delivery history</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="tracking" className="space-y-6">
          {selectedDeliveryId ? (
            <DeliveryTrackingMap
              deliveryId={selectedDeliveryId}
              userType={demoMode}
              onStatusUpdate={(status) => {
                console.log('Status updated:', status);
              }}
            />
          ) : (
            <Card>
              <CardContent className="p-12 text-center">
                <MapPin className="h-16 w-16 text-gray-300 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">No Delivery Selected</h3>
                <p className="text-gray-500 mb-4">Create a demo delivery to see live tracking in action</p>
                <Button onClick={createDemoDelivery}>
                  Create Demo Delivery
                </Button>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="partner" className="space-y-6">
          {demoData.deliveryPartners.length > 0 ? (
            <DeliveryTrackingDashboard partnerId={demoData.deliveryPartners[0].id} />
          ) : (
            <Card>
              <CardContent className="p-12 text-center">
                <Truck className="h-16 w-16 text-gray-300 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">No Delivery Partners Available</h3>
                <p className="text-gray-500">Partner dashboard will show once delivery partners are registered</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="admin" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Delivery Management */}
            <Card>
              <CardHeader>
                <CardTitle>Delivery Management</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {demoData.deliveries.map((delivery: any) => (
                    <div key={delivery.id} className="p-3 border rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium">Delivery #{delivery.id}</span>
                        <Badge variant="outline">{delivery.status || 'pending'}</Badge>
                      </div>
                      
                      {!delivery.deliveryPartnerId && demoData.deliveryPartners.length > 0 && (
                        <Button
                          size="sm"
                          onClick={() => assignDeliveryPartner(delivery.id, demoData.deliveryPartners[0].id)}
                        >
                          Assign Partner
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Analytics */}
            <Card>
              <CardHeader>
                <CardTitle>Analytics Overview</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-blue-600">{demoData.deliveries.length}</div>
                    <div className="text-sm text-gray-600">Total Deliveries</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-green-600">{demoData.deliveryPartners.length}</div>
                    <div className="text-sm text-gray-600">Active Partners</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-purple-600">
                      {demoData.deliveries.filter((d: any) => d.status === 'delivered').length}
                    </div>
                    <div className="text-sm text-gray-600">Completed</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-orange-600">
                      {demoData.deliveries.filter((d: any) => ['assigned', 'en_route_pickup', 'picked_up', 'en_route_delivery'].includes(d.status)).length}
                    </div>
                    <div className="text-sm text-gray-600">In Progress</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}