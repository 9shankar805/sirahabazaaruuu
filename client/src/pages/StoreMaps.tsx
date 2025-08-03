import { useAuth } from "@/hooks/useAuth";
import StoreMap from "@/components/StoreMap";
import NotificationCenter from "@/components/NotificationCenter";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { MapPin } from "lucide-react";

export default function StoreMaps() {
  const { user } = useAuth();

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2 flex items-center gap-2">
          <MapPin className="h-8 w-8" />
          Store Locations
        </h1>
        <p className="text-gray-600">
          Find nearby stores and get directions to them
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <StoreMap storeType="retail" />
        </div>
        
        <div className="space-y-6">
          {user && (
            <NotificationCenter userId={user.id} />
          )}
          
          <Card>
            <CardHeader>
              <CardTitle>How It Works</CardTitle>
              <CardDescription>Getting directions to stores</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <h4 className="font-medium">1. Share Your Location</h4>
                <p className="text-sm text-gray-600">
                  Allow location access or enter your coordinates manually
                </p>
              </div>
              
              <div className="space-y-2">
                <h4 className="font-medium">2. Find Nearby Stores</h4>
                <p className="text-sm text-gray-600">
                  View stores sorted by distance from your location
                </p>
              </div>
              
              <div className="space-y-2">
                <h4 className="font-medium">3. Get Directions</h4>
                <p className="text-sm text-gray-600">
                  Click "Get Directions" to open Google Maps navigation
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}