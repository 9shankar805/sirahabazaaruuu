
import React, { useEffect, useRef, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { MapPin, Navigation, Clock, Phone, Truck, AlertCircle } from 'lucide-react';

interface DeliveryMapProps {
  deliveryId?: number;
  deliveryPartnerId?: number;
  pickupLocation?: { lat: number; lng: number; address: string };
  deliveryLocation?: { lat: number; lng: number; address: string };
  currentLocation?: { lat: number; lng: number };
  onLocationUpdate?: (location: { lat: number; lng: number }) => void;
}

export default function DeliveryMap({ 
  deliveryId, 
  deliveryPartnerId, 
  pickupLocation, 
  deliveryLocation, 
  currentLocation, 
  onLocationUpdate 
}: DeliveryMapProps) {
  const mapRef = useRef<HTMLDivElement>(null);
  const [isMapLoaded, setIsMapLoaded] = useState(false);
  const [userLocation, setUserLocation] = useState<{ lat: number; lng: number } | null>(null);
  const [mapError, setMapError] = useState<string | null>(null);

  // Get user's current location
  useEffect(() => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const location = {
            lat: position.coords.latitude,
            lng: position.coords.longitude
          };
          setUserLocation(location);
          if (onLocationUpdate) {
            onLocationUpdate(location);
          }
        },
        (error) => {
          console.error('Error getting location:', error);
          setMapError('Unable to get your location. Please enable location services.');
        }
      );
    } else {
      setMapError('Geolocation is not supported by this browser.');
    }
  }, [onLocationUpdate]);

  // Initialize map (placeholder for now, can be enhanced with HERE Maps or Google Maps)
  useEffect(() => {
    if (mapRef.current && !isMapLoaded) {
      // For now, we'll create a visual map placeholder
      // In production, this would initialize HERE Maps or Google Maps
      setIsMapLoaded(true);
    }
  }, [isMapLoaded]);

  const handleNavigate = (destination: { lat: number; lng: number; address: string }) => {
    const googleMapsUrl = `https://www.google.com/maps/dir/?api=1&destination=${destination.lat},${destination.lng}`;
    window.open(googleMapsUrl, '_blank');
  };

  // Calculate position on map based on real coordinates
  const calculateMapPosition = (lat: number, lng: number) => {
    // Convert Nepal coordinates to map percentage positions
    // Siraha area: lat ~26.66, lng ~86.20
    const baseLat = 26.65;
    const baseLng = 86.19;
    const latRange = 0.03; // ~3km range
    const lngRange = 0.03; // ~3km range
    
    const leftPercent = ((lng - baseLng) / lngRange) * 50 + 25; // 25-75% range
    const topPercent = ((baseLat + latRange - lat) / latRange) * 50 + 25; // 25-75% range
    
    return {
      left: `${Math.max(15, Math.min(85, leftPercent))}%`,
      top: `${Math.max(15, Math.min(85, topPercent))}%`
    };
  };

  const handleUpdateLocation = () => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const location = {
            lat: position.coords.latitude,
            lng: position.coords.longitude
          };
          setUserLocation(location);
          if (onLocationUpdate) {
            onLocationUpdate(location);
          }
        },
        (error) => {
          console.error('Error updating location:', error);
          setMapError('Failed to update location. Please try again.');
        }
      );
    }
  };

  if (mapError) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-center h-64">
            <div className="text-center">
              <AlertCircle className="h-12 w-12 text-red-500 mx-auto mb-4" />
              <p className="text-red-600 mb-4">{mapError}</p>
              <Button onClick={handleUpdateLocation} variant="outline">
                Try Again
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Map Container */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MapPin className="h-5 w-5" />
            Delivery Map
            <Badge variant="secondary" className="bg-green-100 text-green-800">
              Live Tracking
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div 
            ref={mapRef}
            className="w-full h-96 bg-gradient-to-br from-blue-50 to-indigo-100 rounded-lg border-2 border-blue-200 relative overflow-hidden"
          >
            {/* Map Overlay with Visual Elements */}
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="relative w-full h-full">
                {/* Grid Pattern */}
                <div className="absolute inset-0 opacity-10">
                  <div className="grid grid-cols-8 grid-rows-6 h-full">
                    {Array.from({ length: 48 }).map((_, i) => (
                      <div key={i} className="border border-blue-300"></div>
                    ))}
                  </div>
                </div>

                {/* Location Markers */}
                {pickupLocation && (
                  <div 
                    className="absolute transform -translate-x-1/2 -translate-y-1/2"
                    style={calculateMapPosition(pickupLocation.lat, pickupLocation.lng)}
                  >
                    <div className="relative">
                      <div className="w-6 h-6 bg-green-500 rounded-full border-2 border-white shadow-lg animate-pulse"></div>
                      <div className="absolute -top-8 left-1/2 transform -translate-x-1/2 bg-green-600 text-white text-xs px-2 py-1 rounded whitespace-nowrap">
                        🏪 Pickup
                      </div>
                    </div>
                  </div>
                )}

                {deliveryLocation && (
                  <div 
                    className="absolute transform -translate-x-1/2 -translate-y-1/2"
                    style={calculateMapPosition(deliveryLocation.lat, deliveryLocation.lng)}
                  >
                    <div className="relative">
                      <div className="w-6 h-6 bg-red-500 rounded-full border-2 border-white shadow-lg animate-pulse"></div>
                      <div className="absolute -top-8 left-1/2 transform -translate-x-1/2 bg-red-600 text-white text-xs px-2 py-1 rounded whitespace-nowrap">
                        🏠 Delivery
                      </div>
                    </div>
                  </div>
                )}

                {(userLocation || currentLocation) && (
                  <div 
                    className="absolute transform -translate-x-1/2 -translate-y-1/2"
                    style={calculateMapPosition(
                      (currentLocation?.lat || userLocation?.lat) ?? 26.6696,
                      (currentLocation?.lng || userLocation?.lng) ?? 86.2121
                    )}
                  >
                    <div className="relative">
                      <div className="w-5 h-5 bg-blue-500 rounded-full border-2 border-white shadow-lg">
                        <div className="absolute inset-0 bg-blue-500 rounded-full animate-ping opacity-75"></div>
                      </div>
                      <div className="absolute -top-8 left-1/2 transform -translate-x-1/2 bg-blue-600 text-white text-xs px-2 py-1 rounded whitespace-nowrap">
                        🚛 Partner
                      </div>
                    </div>
                  </div>
                )}

                {/* Route Lines */}
                {pickupLocation && deliveryLocation && (() => {
                  const pickupPos = calculateMapPosition(pickupLocation.lat, pickupLocation.lng);
                  const deliveryPos = calculateMapPosition(deliveryLocation.lat, deliveryLocation.lng);
                  const midX = (parseFloat(pickupPos.left) + parseFloat(deliveryPos.left)) / 2;
                  const midY = Math.min(parseFloat(pickupPos.top), parseFloat(deliveryPos.top)) - 5;
                  
                  return (
                    <div className="absolute inset-0">
                      <svg className="w-full h-full">
                        <defs>
                          <pattern id="dash" patternUnits="userSpaceOnUse" width="8" height="8">
                            <rect width="4" height="8" fill="#3B82F6" />
                          </pattern>
                        </defs>
                        <path
                          d={`M ${pickupPos.left} ${pickupPos.top} Q ${midX}% ${midY}% ${deliveryPos.left} ${deliveryPos.top}`}
                          stroke="#3B82F6"
                          strokeWidth="3"
                          strokeDasharray="5,5"
                          fill="none"
                          className="animate-pulse"
                        />
                      </svg>
                    </div>
                  );
                })()}

                {/* Map Info */}
                <div className="absolute top-4 left-4 bg-white/80 backdrop-blur-sm rounded-lg p-3">
                  <div className="text-sm font-medium text-gray-700">Live Tracking</div>
                  <div className="text-xs text-gray-500">
                    {userLocation ? 
                      `${userLocation.lat.toFixed(4)}, ${userLocation.lng.toFixed(4)}` : 
                      'Getting location...'
                    }
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Map Controls */}
          <div className="flex gap-2 mt-4">
            <Button 
              onClick={handleUpdateLocation}
              size="sm"
              variant="outline"
            >
              <MapPin className="h-4 w-4 mr-2" />
              Update Location
            </Button>
            
            {pickupLocation && (
              <Button 
                onClick={() => handleNavigate(pickupLocation)}
                size="sm"
                variant="outline"
              >
                <Navigation className="h-4 w-4 mr-2" />
                Navigate to Pickup
              </Button>
            )}
            
            {deliveryLocation && (
              <Button 
                onClick={() => handleNavigate(deliveryLocation)}
                size="sm"
                variant="outline"
              >
                <Navigation className="h-4 w-4 mr-2" />
                Navigate to Delivery
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Location Details */}
      {(pickupLocation || deliveryLocation) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {pickupLocation && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                  Pickup Location
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-gray-600 mb-2">{pickupLocation.address}</p>
                <div className="flex gap-2">
                  <Button 
                    size="sm" 
                    variant="outline"
                    onClick={() => handleNavigate(pickupLocation)}
                  >
                    <Navigation className="h-3 w-3 mr-1" />
                    Navigate
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {deliveryLocation && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                  Delivery Location
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-gray-600 mb-2">{deliveryLocation.address}</p>
                <div className="flex gap-2">
                  <Button 
                    size="sm" 
                    variant="outline"
                    onClick={() => handleNavigate(deliveryLocation)}
                  >
                    <Navigation className="h-3 w-3 mr-1" />
                    Navigate
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
