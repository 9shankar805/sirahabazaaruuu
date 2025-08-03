
import React, { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { MapPin, Play, Pause, Navigation } from 'lucide-react';

interface LocationTrackerProps {
  deliveryId: number;
  deliveryPartnerId: number;
  isActive: boolean;
  onToggleTracking: (active: boolean) => void;
}

export function LocationTracker({ deliveryId, deliveryPartnerId, isActive, onToggleTracking }: LocationTrackerProps) {
  const [watchId, setWatchId] = useState<number | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [accuracy, setAccuracy] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const startTracking = () => {
    if (!navigator.geolocation) {
      setError('Geolocation is not supported by this browser');
      return;
    }

    const options = {
      enableHighAccuracy: true,
      timeout: 10000,
      maximumAge: 5000 // Cache position for 5 seconds
    };

    const id = navigator.geolocation.watchPosition(
      (position) => {
        const { latitude, longitude, heading, speed, accuracy } = position.coords;
        
        // Send location update to server
        fetch('/api/tracking/location', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({
            deliveryId,
            deliveryPartnerId,
            latitude,
            longitude,
            heading: heading || undefined,
            speed: speed || undefined,
            accuracy: accuracy || undefined
          })
        }).then(() => {
          setLastUpdate(new Date());
          setAccuracy(accuracy);
          setError(null);
        }).catch((err) => {
          console.error('Failed to update location:', err);
          setError('Failed to update location');
        });
      },
      (err) => {
        console.error('Geolocation error:', err);
        setError(`Location error: ${err.message}`);
      },
      options
    );

    setWatchId(id);
    onToggleTracking(true);
  };

  const stopTracking = () => {
    if (watchId !== null) {
      navigator.geolocation.clearWatch(watchId);
      setWatchId(null);
    }
    onToggleTracking(false);
  };

  const toggleTracking = () => {
    if (isActive) {
      stopTracking();
    } else {
      startTracking();
    }
  };

  // Auto-start tracking when component mounts if it should be active
  useEffect(() => {
    if (isActive && watchId === null) {
      startTracking();
    }

    return () => {
      if (watchId !== null) {
        navigator.geolocation.clearWatch(watchId);
      }
    };
  }, []);

  return (
    <Card className="mb-4">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span className="flex items-center gap-2">
            <MapPin className="h-5 w-5" />
            Location Tracking
          </span>
          <Badge variant={isActive ? "default" : "secondary"}>
            {isActive ? "Active" : "Inactive"}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-600">
              {lastUpdate ? (
                <span>Last update: {lastUpdate.toLocaleTimeString()}</span>
              ) : (
                <span>No location updates yet</span>
              )}
              {accuracy && (
                <span className="block">Accuracy: ±{accuracy.toFixed(0)}m</span>
              )}
            </div>
            <Button 
              onClick={toggleTracking}
              variant={isActive ? "destructive" : "default"}
              size="sm"
              className="flex items-center gap-2"
            >
              {isActive ? (
                <>
                  <Pause className="h-4 w-4" />
                  Stop Tracking
                </>
              ) : (
                <>
                  <Play className="h-4 w-4" />
                  Start Tracking
                </>
              )}
            </Button>
          </div>
          
          {error && (
            <div className="text-sm text-red-600 bg-red-50 p-2 rounded">
              {error}
            </div>
          )}
          
          {isActive && (
            <div className="text-xs text-gray-500 bg-blue-50 p-2 rounded">
              <Navigation className="h-3 w-3 inline mr-1" />
              Your location is being shared with customers and the store for real-time tracking.
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
