import { useState, useEffect } from "react";
import { MapPin, Filter, Target } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { calculateDistance, getCurrentUserLocation, formatDistance } from "@/lib/distance";

interface Store {
  id: number;
  name: string;
  description?: string;
  address: string;
  latitude?: string;
  longitude?: string;
  phone?: string;
  website?: string;
  logo?: string;
  coverImage?: string;
  rating: string;
  totalReviews: number;
  storeType: string;
  cuisineType?: string;
  deliveryTime?: string;
  isDeliveryAvailable?: boolean;
}

interface StoreWithDistance extends Store {
  distance: number;
}

interface StoreDistanceFilterProps {
  stores: Store[];
  onFilteredStores: (stores: StoreWithDistance[]) => void;
  className?: string;
}

export default function StoreDistanceFilter({ stores, onFilteredStores, className }: StoreDistanceFilterProps) {
  const [userLocation, setUserLocation] = useState<{ latitude: number; longitude: number } | null>(null);
  const [isGettingLocation, setIsGettingLocation] = useState(false);
  const [sortBy, setSortBy] = useState<"distance" | "rating" | "name">("distance");
  const [maxDistance, setMaxDistance] = useState<number>(50); // km
  const [storesWithDistance, setStoresWithDistance] = useState<StoreWithDistance[]>([]);

  // Get user location
  const handleGetLocation = async () => {
    setIsGettingLocation(true);
    try {
      const location = await getCurrentUserLocation();
      setUserLocation(location);
    } catch (error) {
      console.error('Failed to get location:', error);
    } finally {
      setIsGettingLocation(false);
    }
  };

  // Calculate distances for all stores
  useEffect(() => {
    if (userLocation && stores.length > 0) {
      const storesWithDist: StoreWithDistance[] = stores
        .map(store => {
          if (!store.latitude || !store.longitude) {
            return { ...store, distance: Infinity };
          }
          
          const distance = calculateDistance(
            userLocation,
            { 
              latitude: parseFloat(store.latitude), 
              longitude: parseFloat(store.longitude) 
            }
          );
          
          return { ...store, distance };
        })
        .filter(store => store.distance <= maxDistance && store.distance !== Infinity);

      setStoresWithDistance(storesWithDist);
    } else {
      // If no location, show all stores without distance
      setStoresWithDistance(stores.map(store => ({ ...store, distance: 0 })));
    }
  }, [userLocation, stores, maxDistance]);

  // Sort and filter stores
  useEffect(() => {
    let sortedStores = [...storesWithDistance];

    switch (sortBy) {
      case "distance":
        sortedStores.sort((a, b) => a.distance - b.distance);
        break;
      case "rating":
        sortedStores.sort((a, b) => parseFloat(b.rating) - parseFloat(a.rating));
        break;
      case "name":
        sortedStores.sort((a, b) => a.name.localeCompare(b.name));
        break;
    }

    onFilteredStores(sortedStores);
  }, [storesWithDistance, sortBy, onFilteredStores]);

  return (
    <Card className={className}>
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-lg">
          <Filter className="h-5 w-5" />
          Store Distance Filter
        </CardTitle>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {/* Location Status */}
        <div className="space-y-2">
          {!userLocation ? (
            <Button 
              onClick={handleGetLocation} 
              disabled={isGettingLocation}
              variant="outline"
              className="w-full"
            >
              <Target className="h-4 w-4 mr-2" />
              {isGettingLocation ? "Getting Location..." : "Get My Location"}
            </Button>
          ) : (
            <div className="flex items-center justify-between p-3 bg-green-50 border border-green-200 rounded-lg">
              <div className="flex items-center gap-2">
                <Target className="h-4 w-4 text-green-600" />
                <span className="text-sm text-green-700 font-medium">
                  Location Found
                </span>
              </div>
              <Badge variant="outline" className="text-xs">
                {userLocation.latitude.toFixed(4)}, {userLocation.longitude.toFixed(4)}
              </Badge>
            </div>
          )}
        </div>

        {/* Filters */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">Sort By</label>
            <Select value={sortBy} onValueChange={(value: any) => setSortBy(value)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="distance">Closest First</SelectItem>
                <SelectItem value="rating">Highest Rated</SelectItem>
                <SelectItem value="name">Alphabetical</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">Max Distance</label>
            <Select value={maxDistance.toString()} onValueChange={(value) => setMaxDistance(parseInt(value))}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1">Within 1 km</SelectItem>
                <SelectItem value="2">Within 2 km</SelectItem>
                <SelectItem value="5">Within 5 km</SelectItem>
                <SelectItem value="10">Within 10 km</SelectItem>
                <SelectItem value="25">Within 25 km</SelectItem>
                <SelectItem value="50">Within 50 km</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Results Summary */}
        {userLocation && (
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>
              {storesWithDistance.length} stores within {maxDistance}km
            </span>
            {storesWithDistance.length > 0 && sortBy === "distance" && (
              <span>
                Closest: {formatDistance(storesWithDistance[0]?.distance || 0)}
              </span>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}