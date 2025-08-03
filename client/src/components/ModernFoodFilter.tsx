import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { MapPin, Clock, Star, Filter } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { getCurrentUserLocation } from "@/lib/distance";
import ProductCard from "@/components/ProductCard";
import type { Product } from "@shared/schema";

interface FoodItemWithRestaurant extends Product {
  distance: number;
  storeName: string;
  storeAddress: string;
  deliveryTime?: string;
}

interface ModernFoodFilterProps {
  searchQuery?: string;
  className?: string;
}

export default function ModernFoodFilter({ 
  searchQuery = "", 
  className = "" 
}: ModernFoodFilterProps) {
  const [userLocation, setUserLocation] = useState<{ latitude: number; longitude: number } | null>(null);
  const [isGettingLocation, setIsGettingLocation] = useState(false);
  const [radius, setRadius] = useState<number>(10); // Default 10km like modern apps
  const [spiceLevel, setSpiceLevel] = useState<string>("all");
  const [isVegetarian, setIsVegetarian] = useState<boolean>(false);
  const [sortBy, setSortBy] = useState<string>("distance");

  // Get user location
  const getUserLocation = async () => {
    setIsGettingLocation(true);
    try {
      const location = await getCurrentUserLocation();
      setUserLocation(location);
    } catch (error) {
      console.error('Failed to get user location:', error);
    } finally {
      setIsGettingLocation(false);
    }
  };

  useEffect(() => {
    getUserLocation();
  }, []);

  // Fetch food items within radius (modern food delivery style)
  const { data: foodResponse, isLoading, error } = useQuery({
    queryKey: ["/api/food/items", userLocation?.latitude, userLocation?.longitude, radius, searchQuery, spiceLevel, isVegetarian],
    queryFn: async () => {
      if (!userLocation) return { items: [], count: 0, searchRadius: 0 };
      
      const params = new URLSearchParams({
        lat: userLocation.latitude.toString(),
        lon: userLocation.longitude.toString(),
        radius: radius.toString(),
      });
      
      if (searchQuery) params.append('search', searchQuery);
      if (spiceLevel !== 'all') params.append('spiceLevel', spiceLevel);
      if (isVegetarian) params.append('isVegetarian', 'true');
      
      const response = await fetch(`/api/food/items?${params}`);
      if (!response.ok) throw new Error('Failed to fetch food items');
      
      return await response.json();
    },
    enabled: !!userLocation,
  });

  const foodItems = foodResponse?.items || [];

  // Sort food items
  const sortedFoodItems = [...foodItems].sort((a, b) => {
    switch (sortBy) {
      case "distance":
        return a.distance - b.distance;
      case "rating":
        return parseFloat(b.rating) - parseFloat(a.rating);
      case "price_low":
        return parseFloat(a.price) - parseFloat(b.price);
      case "price_high":
        return parseFloat(b.price) - parseFloat(a.price);
      case "delivery_time":
        // Extract minutes from delivery time string (e.g., "25-35 mins" -> 25)
        const getMinutes = (time?: string) => {
          if (!time) return 999;
          const match = time.match(/(\d+)/);
          return match ? parseInt(match[1]) : 999;
        };
        return getMinutes(a.deliveryTime) - getMinutes(b.deliveryTime);
      default:
        return 0;
    }
  });

  if (!userLocation && !isGettingLocation) {
    return (
      <Card className={className}>
        <CardContent className="text-center py-8">
          <MapPin className="h-12 w-12 mx-auto text-gray-400 mb-4" />
          <h3 className="text-lg font-semibold mb-2">Location Required for Food Delivery</h3>
          <p className="text-gray-600 mb-4">
            We need your location to show nearby restaurants and food items within delivery range.
          </p>
          <Button onClick={getUserLocation} disabled={isGettingLocation}>
            {isGettingLocation ? "Getting Location..." : "Enable Location"}
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className={className}>
      {/* Modern Filter Controls */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Filter className="h-5 w-5 text-orange-600" />
            Food Delivery Filters
            {userLocation && foodResponse && (
              <Badge variant="secondary" className="ml-2">
                {foodResponse.count} items within {foodResponse.searchRadius}km
              </Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Delivery Radius */}
            <div>
              <label className="text-sm font-medium mb-2 block">Delivery Radius</label>
              <Select value={radius.toString()} onValueChange={(value) => setRadius(parseInt(value))}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="5">5 km</SelectItem>
                  <SelectItem value="10">10 km (Recommended)</SelectItem>
                  <SelectItem value="15">15 km</SelectItem>
                  <SelectItem value="20">20 km</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Spice Level */}
            <div>
              <label className="text-sm font-medium mb-2 block">Spice Level</label>
              <Select value={spiceLevel} onValueChange={setSpiceLevel}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Levels</SelectItem>
                  <SelectItem value="mild">Mild</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="hot">Hot</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Dietary Preference */}
            <div>
              <label className="text-sm font-medium mb-2 block">Diet</label>
              <Select value={isVegetarian ? "vegetarian" : "all"} onValueChange={(value) => setIsVegetarian(value === "vegetarian")}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Foods</SelectItem>
                  <SelectItem value="vegetarian">Vegetarian Only</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Sort By */}
            <div>
              <label className="text-sm font-medium mb-2 block">Sort By</label>
              <Select value={sortBy} onValueChange={setSortBy}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="distance">Distance</SelectItem>
                  <SelectItem value="rating">Rating</SelectItem>
                  <SelectItem value="price_low">Price: Low to High</SelectItem>
                  <SelectItem value="price_high">Price: High to Low</SelectItem>
                  <SelectItem value="delivery_time">Delivery Time</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Loading State */}
      {isLoading && (
        <div className="text-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Finding delicious food near you...</p>
        </div>
      )}

      {/* Error State */}
      {error && (
        <Card>
          <CardContent className="text-center py-8">
            <div className="text-red-600 mb-2">Failed to load food items</div>
            <Button onClick={() => window.location.reload()} variant="outline">
              Try Again
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Food Items Grid */}
      {!isLoading && !error && sortedFoodItems.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
          {sortedFoodItems.map((item) => (
            <div key={item.id} className="relative">
              <ProductCard product={item} />
              
              {/* Modern Food Delivery Info Overlay */}
              <div className="absolute top-2 left-2 flex flex-col gap-1">
                <Badge variant="secondary" className="text-xs bg-white/90 text-gray-700">
                  <MapPin className="h-3 w-3 mr-1" />
                  {item.distance.toFixed(1)}km
                </Badge>
                {item.deliveryTime && (
                  <Badge variant="secondary" className="text-xs bg-white/90 text-gray-700">
                    <Clock className="h-3 w-3 mr-1" />
                    {item.deliveryTime}
                  </Badge>
                )}
              </div>

              {/* Restaurant Info */}
              <div className="mt-2 p-2 bg-gray-50 rounded-lg">
                <p className="text-sm font-medium text-gray-800">{item.storeName}</p>
                <p className="text-xs text-gray-600">{item.storeAddress}</p>
                <div className="flex items-center gap-2 mt-1">
                  <Star className="h-3 w-3 text-yellow-500" />
                  <span className="text-xs text-gray-600">{item.rating} • {item.totalReviews} reviews</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* No Results */}
      {!isLoading && !error && sortedFoodItems.length === 0 && userLocation && (
        <Card>
          <CardContent className="text-center py-8">
            <h3 className="text-lg font-semibold mb-2">No food items found</h3>
            <p className="text-gray-600 mb-4">
              Try increasing the delivery radius or adjusting your filters.
            </p>
            <Button onClick={() => setRadius(20)} variant="outline">
              Expand to 20km radius
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}