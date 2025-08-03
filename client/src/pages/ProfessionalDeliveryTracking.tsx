import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useQuery } from '@tanstack/react-query';
import { useUser } from '@/hooks/use-user';
import { MapPin, Navigation, Clock, Package, Truck, Phone, Star, ArrowRight } from 'lucide-react';
import ProfessionalLiveTracking from '@/components/tracking/ProfessionalLiveTracking';
import { BackToDashboard } from '@/components/BackToDashboard';

interface DeliveryAssignment {
  id: number;
  orderId: number;
  status: string;
  pickupAddress: string;
  deliveryAddress: string;
  customerName: string;
  customerPhone: string;
  deliveryFee: string;
  estimatedDistance: string;
  specialInstructions?: string;
  assignedAt: string;
}

export default function ProfessionalDeliveryTracking() {
  const { user } = useUser();
  const [selectedDelivery, setSelectedDelivery] = useState<number | null>(null);

  // Get delivery partner data
  const { data: partner } = useQuery({
    queryKey: ['/api/delivery-partners/user', user?.id],
    queryFn: async () => {
      const response = await fetch(`/api/delivery-partners/user?userId=${user?.id}`);
      if (!response.ok) {
        if (response.status === 404) return null;
        throw new Error('Failed to fetch partner data');
      }
      return response.json();
    },
    enabled: !!user?.id,
  });

  // Get active delivery assignments
  const { data: assignments = [] } = useQuery({
    queryKey: ['/api/delivery-partners/assignments'],
    queryFn: async () => {
      const response = await fetch('/api/delivery-partners/assignments');
      if (!response.ok) return [];
      const data = await response.json();
      return data.filter((assignment: DeliveryAssignment) => 
        ['assigned', 'picked_up', 'in_transit'].includes(assignment.status)
      );
    },
    refetchInterval: 3000,
    enabled: !!partner?.id,
  });

  // Auto-select first assignment
  useEffect(() => {
    if (assignments.length > 0 && !selectedDelivery) {
      setSelectedDelivery(assignments[0].id);
    }
  }, [assignments, selectedDelivery]);

  const selectedAssignment = assignments.find((a: DeliveryAssignment) => a.id === selectedDelivery);

  if (!partner) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <Card className="max-w-md w-full">
          <CardContent className="text-center py-12">
            <Truck className="h-16 w-16 text-gray-300 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">Partner Not Found</h3>
            <p className="text-gray-600">Please register as a delivery partner first.</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="mb-6">
          <BackToDashboard />
          <div className="flex items-center justify-between mt-4">
            <div>
              <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
                <MapPin className="h-8 w-8 text-blue-600" />
                Live Delivery Tracking
              </h1>
              <p className="text-gray-600 mt-1">Professional tracking with real-time location updates</p>
            </div>
            <Badge variant="secondary" className="bg-green-100 text-green-800 px-4 py-2">
              <div className="w-2 h-2 bg-green-500 rounded-full mr-2 animate-pulse"></div>
              Live Tracking Active
            </Badge>
          </div>
        </div>

        {assignments.length === 0 ? (
          <Card className="shadow-lg border-0">
            <CardContent className="text-center py-16">
              <Navigation className="h-20 w-20 text-gray-300 mx-auto mb-6" />
              <h3 className="text-xl font-semibold text-gray-900 mb-3">No Active Deliveries</h3>
              <p className="text-gray-600 mb-6 max-w-md mx-auto">
                You currently have no active deliveries to track. When you accept a delivery assignment, 
                professional live tracking will appear here with real-time maps and location updates.
              </p>
              <Button 
                onClick={() => window.location.href = '/delivery-partner/dashboard'}
                className="bg-blue-600 hover:bg-blue-700"
              >
                <Package className="h-4 w-4 mr-2" />
                Check for New Deliveries
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Delivery Selection Sidebar */}
            <div className="lg:col-span-4 space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Package className="h-5 w-5" />
                    Active Deliveries ({assignments.length})
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {assignments.map((assignment: DeliveryAssignment) => (
                    <div
                      key={assignment.id}
                      className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                        selectedDelivery === assignment.id
                          ? 'border-blue-500 bg-blue-50'
                          : 'border-gray-200 hover:border-gray-300'
                      }`}
                      onClick={() => setSelectedDelivery(assignment.id)}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <Badge 
                          variant={assignment.status === 'assigned' ? 'default' : 'secondary'}
                          className="text-xs"
                        >
                          {assignment.status.replace('_', ' ').toUpperCase()}
                        </Badge>
                        <span className="text-sm font-medium text-green-600">
                          NPR {assignment.deliveryFee}
                        </span>
                      </div>
                      
                      <div className="space-y-2">
                        <div className="flex items-center gap-2 text-sm">
                          <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                          <span className="font-medium">Order #{assignment.orderId}</span>
                        </div>
                        
                        <div className="text-sm text-gray-600">
                          <div className="flex items-center gap-1 mb-1">
                            <MapPin className="h-3 w-3" />
                            <span className="truncate">{assignment.deliveryAddress}</span>
                          </div>
                          <div className="flex items-center gap-1">
                            <Phone className="h-3 w-3" />
                            <span>{assignment.customerName}</span>
                          </div>
                        </div>
                        
                        <div className="flex items-center justify-between text-xs text-gray-500">
                          <span>{assignment.estimatedDistance} km</span>
                          <span>{new Date(assignment.assignedAt).toLocaleTimeString()}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>

              {/* Delivery Details */}
              {selectedAssignment && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Navigation className="h-5 w-5" />
                      Delivery Details
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <h4 className="font-medium text-gray-900 mb-2">Customer Information</h4>
                      <div className="space-y-1 text-sm">
                        <div className="flex items-center gap-2">
                          <Phone className="h-4 w-4 text-gray-400" />
                          <span>{selectedAssignment.customerName}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Phone className="h-4 w-4 text-gray-400" />
                          <span>{selectedAssignment.customerPhone}</span>
                        </div>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-medium text-gray-900 mb-2">Delivery Information</h4>
                      <div className="space-y-1 text-sm">
                        <div className="flex items-center gap-2">
                          <MapPin className="h-4 w-4 text-gray-400" />
                          <span className="text-gray-600">{selectedAssignment.deliveryAddress}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Clock className="h-4 w-4 text-gray-400" />
                          <span className="text-gray-600">{selectedAssignment.estimatedDistance} km</span>
                        </div>
                      </div>
                    </div>

                    {selectedAssignment.specialInstructions && (
                      <div>
                        <h4 className="font-medium text-gray-900 mb-2">Special Instructions</h4>
                        <p className="text-sm text-gray-600 bg-yellow-50 p-3 rounded-lg">
                          {selectedAssignment.specialInstructions}
                        </p>
                      </div>
                    )}

                    <div className="flex gap-2">
                      <Button 
                        size="sm" 
                        variant="outline" 
                        className="flex-1"
                        onClick={() => window.open(`tel:${selectedAssignment.customerPhone}`)}
                      >
                        <Phone className="h-4 w-4 mr-1" />
                        Call
                      </Button>
                      <Button 
                        size="sm" 
                        className="flex-1 bg-green-600 hover:bg-green-700"
                        onClick={() => {
                          const url = `https://www.google.com/maps/dir/?api=1&destination=${selectedAssignment.deliveryAddress}`;
                          window.open(url, '_blank');
                        }}
                      >
                        <Navigation className="h-4 w-4 mr-1" />
                        Navigate
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>

            {/* Professional Live Tracking Map */}
            <div className="lg:col-span-8">
              {selectedAssignment ? (
                <Card className="h-full min-h-[600px]">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <MapPin className="h-5 w-5 text-blue-600" />
                      Live Tracking - Order #{selectedAssignment.orderId}
                      <Badge variant="secondary" className="bg-green-100 text-green-800 ml-auto">
                        <div className="w-2 h-2 bg-green-500 rounded-full mr-2 animate-pulse"></div>
                        Real-time Updates
                      </Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="p-0 h-full">
                    <ProfessionalLiveTracking 
                      deliveryData={{
                        id: selectedAssignment.id,
                        orderId: selectedAssignment.orderId,
                        customerName: selectedAssignment.customerName,
                        customerPhone: selectedAssignment.customerPhone,
                        pickupAddress: selectedAssignment.pickupAddress,
                        deliveryAddress: selectedAssignment.deliveryAddress,
                        storeName: "Family Restaurant",
                        storePhone: "+977-9800000001",
                        deliveryFee: parseFloat(selectedAssignment.deliveryFee),
                        status: selectedAssignment.status,
                        estimatedDistance: parseFloat(selectedAssignment.estimatedDistance),
                        estimatedTime: 25,
                        specialInstructions: selectedAssignment.specialInstructions
                      }}
                      deliveryPartnerId={partner?.id || 0}
                      onLocationUpdate={(location: { lat: number; lng: number; timestamp: number }) => {
                        // Send location updates to server
                        fetch('/api/tracking/location', {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify({
                            deliveryId: selectedAssignment.id,
                            deliveryPartnerId: partner?.id,
                            latitude: location.lat,
                            longitude: location.lng,
                            timestamp: new Date(location.timestamp).toISOString()
                          })
                        }).catch(console.error);
                      }}
                    />
                  </CardContent>
                </Card>
              ) : (
                <Card className="h-full min-h-[600px] flex items-center justify-center">
                  <CardContent className="text-center">
                    <MapPin className="h-16 w-16 text-gray-300 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">Select a Delivery</h3>
                    <p className="text-gray-600">Choose a delivery from the list to start tracking</p>
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}