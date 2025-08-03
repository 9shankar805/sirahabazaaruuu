
import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { MapPin, Clock, DollarSign, Package, Navigation, Phone, X, Check } from 'lucide-react';
import { usePushNotifications } from '@/hooks/usePushNotifications';

interface DeliveryAssignment {
  id: number;
  orderId: number;
  customerName: string;
  customerPhone: string;
  pickupAddress: string;
  deliveryAddress: string;
  deliveryFee: string;
  estimatedDistance: number;
  estimatedTime: number;
  specialInstructions?: string;
  pickupLocation: { lat: number; lng: number };
  deliveryLocation: { lat: number; lng: number };
}

interface DeliveryAssignmentNotificationProps {
  assignment: DeliveryAssignment;
  onAccept: (assignmentId: number) => void;
  onDecline: (assignmentId: number) => void;
  onViewRoute: (assignment: DeliveryAssignment) => void;
}

export function DeliveryAssignmentNotification({ 
  assignment, 
  onAccept, 
  onDecline, 
  onViewRoute 
}: DeliveryAssignmentNotificationProps) {
  const [timeLeft, setTimeLeft] = useState(60); // 60 seconds to respond
  const { showNotification } = usePushNotifications();

  useEffect(() => {
    // Show push notification when assignment arrives
    showNotification('🚚 New Delivery Assignment', {
      body: `New order #${assignment.orderId} for ${assignment.customerName}`,
      icon: '/icons/delivery-icon.png',
      tag: `delivery-${assignment.id}`,
      actions: [
        { action: 'accept', title: 'Accept' },
        { action: 'view', title: 'View Details' }
      ]
    });

    const timer = setInterval(() => {
      setTimeLeft((prev) => {
        if (prev <= 1) {
          // Auto-decline when time runs out
          onDecline(assignment.id);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [assignment]);

  const formatDistance = (meters: number): string => {
    if (meters < 1000) {
      return `${meters}m`;
    }
    return `${(meters / 1000).toFixed(1)}km`;
  };

  const formatTime = (minutes: number): string => {
    if (minutes < 60) {
      return `${minutes} min`;
    }
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    return `${hours}h ${remainingMinutes}m`;
  };

  const openGoogleMapsRoute = () => {
    const { pickupLocation, deliveryLocation } = assignment;
    const url = `https://www.google.com/maps/dir/${pickupLocation.lat},${pickupLocation.lng}/${deliveryLocation.lat},${deliveryLocation.lng}`;
    window.open(url, '_blank');
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <Card className="w-full max-w-md bg-white shadow-xl border-2 border-blue-500 animate-pulse">
        <CardHeader className="bg-blue-50">
          <CardTitle className="flex items-center justify-between text-blue-900">
            <span className="flex items-center gap-2">
              <Package className="h-5 w-5" />
              New Delivery Assignment
            </span>
            <Badge variant="destructive" className="animate-bounce">
              {timeLeft}s
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-6 space-y-4">
          {/* Order Info */}
          <div className="bg-gray-50 p-3 rounded-lg">
            <h3 className="font-semibold text-lg">Order #{assignment.orderId}</h3>
            <p className="text-gray-600">Customer: {assignment.customerName}</p>
            <div className="flex items-center gap-2 mt-1">
              <Phone className="h-4 w-4 text-gray-500" />
              <a href={`tel:${assignment.customerPhone}`} className="text-blue-600 hover:underline">
                {assignment.customerPhone}
              </a>
            </div>
          </div>

          {/* Route Information */}
          <div className="space-y-3">
            <div className="flex items-start gap-3">
              <div className="w-3 h-3 bg-green-500 rounded-full mt-1.5"></div>
              <div className="flex-1">
                <p className="font-medium text-green-700">Pickup from:</p>
                <p className="text-sm text-gray-600">{assignment.pickupAddress}</p>
              </div>
            </div>
            
            <div className="flex items-start gap-3">
              <div className="w-3 h-3 bg-red-500 rounded-full mt-1.5"></div>
              <div className="flex-1">
                <p className="font-medium text-red-700">Deliver to:</p>
                <p className="text-sm text-gray-600">{assignment.deliveryAddress}</p>
              </div>
            </div>
          </div>

          {/* Delivery Stats */}
          <div className="grid grid-cols-3 gap-4 text-center">
            <div>
              <MapPin className="h-4 w-4 mx-auto text-gray-500 mb-1" />
              <p className="text-xs text-gray-500">Distance</p>
              <p className="font-semibold">{formatDistance(assignment.estimatedDistance)}</p>
            </div>
            <div>
              <Clock className="h-4 w-4 mx-auto text-gray-500 mb-1" />
              <p className="text-xs text-gray-500">Time</p>
              <p className="font-semibold">{formatTime(assignment.estimatedTime)}</p>
            </div>
            <div>
              <DollarSign className="h-4 w-4 mx-auto text-gray-500 mb-1" />
              <p className="text-xs text-gray-500">Fee</p>
              <p className="font-semibold">₹{assignment.deliveryFee}</p>
            </div>
          </div>

          {/* Special Instructions */}
          {assignment.specialInstructions && (
            <div className="bg-yellow-50 p-3 rounded-lg">
              <p className="text-sm font-medium text-yellow-800">Special Instructions:</p>
              <p className="text-sm text-yellow-700">{assignment.specialInstructions}</p>
            </div>
          )}

          {/* Action Buttons */}
          <div className="space-y-2">
            <Button 
              onClick={openGoogleMapsRoute}
              variant="outline" 
              className="w-full flex items-center gap-2"
            >
              <Navigation className="h-4 w-4" />
              View Route in Google Maps
            </Button>
            
            <div className="grid grid-cols-2 gap-2">
              <Button 
                onClick={() => onDecline(assignment.id)}
                variant="destructive"
                className="flex items-center gap-2"
              >
                <X className="h-4 w-4" />
                Decline
              </Button>
              <Button 
                onClick={() => onAccept(assignment.id)}
                variant="default"
                className="flex items-center gap-2 bg-green-600 hover:bg-green-700"
              >
                <Check className="h-4 w-4" />
                Accept
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
