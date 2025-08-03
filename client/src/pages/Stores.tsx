import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Search, MapPin, Filter, Utensils, Store, RefreshCw, AlertCircle, Loader2, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import StoreCard from "@/components/StoreCard";
import StoreDistanceFilter from "@/components/StoreDistanceFilter";
import { getCurrentUserLocation } from "@/lib/distance";
import { useToast } from "@/hooks/use-toast";

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

export default function Stores() {
  const [location] = useLocation();
  const isRestaurantPage = location.includes('/restaurants');
  
  const [searchQuery, setSearchQuery] = useState("");
  const [storeTypeFilter, setStoreTypeFilter] = useState(isRestaurantPage ? "restaurant" : "all");
  const [cuisineFilter, setCuisineFilter] = useState("all");
  const [deliveryFilter, setDeliveryFilter] = useState("all");
  const [ratingFilter, setRatingFilter] = useState("all");
  const [userLocation, setUserLocation] = useState<{ latitude: number; longitude: number } | null>(null);
  const [locationEnabled, setLocationEnabled] = useState(false);
  const [distanceFilteredStores, setDistanceFilteredStores] = useState<StoreWithDistance[]>([]);
  const [showDistanceFilter, setShowDistanceFilter] = useState(false);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const { toast } = useToast();

  // Fetch all stores with comprehensive error handling
  const { data: stores = [], isLoading: storesLoading, error: storesError, refetch: refetchStores } = useQuery<Store[]>({
    queryKey: ["/api/stores"],
    retry: 3,
    staleTime: 0, // Always fetch fresh data to ensure ratings update immediately
    refetchOnWindowFocus: true, // Refetch when window regains focus
    refetchOnMount: true, // Always refetch on component mount
  });

  // Enhanced error logging
  if (storesError) {
    console.error("Stores loading failed:", {
      error: storesError,
      message: storesError instanceof Error ? storesError.message : 'Unknown error',
      timestamp: new Date().toISOString()
    });
  }

  // Get user location on component mount
  useEffect(() => {
    getCurrentUserLocation()
      .then((location) => {
        setUserLocation(location);
        setLocationEnabled(true);
      })
      .catch(() => {
        // User denied location access - this is fine, stores will just show without distance sorting
      });
  }, []);

  // Get unique cuisines for filter options
  const availableCuisines = Array.from(new Set(stores
    .filter(store => store.storeType === 'restaurant' && store.cuisineType)
    .map(store => store.cuisineType)
  )).filter(Boolean) as string[];

  // Filter stores based on all criteria and page context
  const baseFilteredStores = stores.filter((store) => {
    // Page-specific filtering: restaurants only on restaurant page, retail stores only on stores page
    if (isRestaurantPage) {
      // On restaurant page, only show restaurants
      if (store.storeType !== "restaurant") return false;
    } else {
      // On stores page, exclude restaurants (only show retail stores)
      if (store.storeType === "restaurant") return false;
    }

    const matchesSearch = store.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         store.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         store.address.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         store.cuisineType?.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesType = storeTypeFilter === "all" || store.storeType === storeTypeFilter;
    
    const matchesCuisine = cuisineFilter === "all" || store.cuisineType === cuisineFilter;
    
    const matchesDelivery = deliveryFilter === "all" || 
                           (deliveryFilter === "delivery" && store.isDeliveryAvailable) ||
                           (deliveryFilter === "pickup" && !store.isDeliveryAvailable);
    
    const matchesRating = ratingFilter === "all" || 
                         (ratingFilter === "4+" && parseFloat(store.rating) >= 4.0) ||
                         (ratingFilter === "3+" && parseFloat(store.rating) >= 3.0);
    
    return matchesSearch && matchesType && matchesCuisine && matchesDelivery && matchesRating;
  });

  // Calculate distance for all stores if location is enabled
  const calculateDistance = (lat1: number, lon1: number, lat2: number, lon2: number) => {
    const R = 6371; // Earth's radius in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = 
      Math.sin(dLat/2) * Math.sin(dLat/2) +
      Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
      Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
  };

  // Add distance to stores and sort by distance (closest first)
  const filteredStores = baseFilteredStores.map(store => {
    const distance = userLocation && store.latitude && store.longitude 
      ? calculateDistance(
          userLocation.latitude,
          userLocation.longitude,
          parseFloat(store.latitude),
          parseFloat(store.longitude)
        )
      : 0;
    return { ...store, distance };
  }).sort((a, b) => a.distance - b.distance);

  const handleGetLocation = async () => {
    try {
      const location = await getCurrentUserLocation();
      setUserLocation(location);
      setLocationEnabled(true);
      setShowDistanceFilter(true);
      toast({
        title: "Location enabled",
        description: "Stores will now show distance from your location",
      });
    } catch (error) {
      toast({
        title: "Location access denied",
        description: "Please allow location access to see distances",
        variant: "destructive",
      });
    }
  };

  // Handle distance filter updates
  const handleDistanceFilterUpdate = (filteredStores: StoreWithDistance[]) => {
    setDistanceFilteredStores(filteredStores);
  };

  if (storesLoading) {
    return (
      <div className="min-h-screen bg-muted flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading stores...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-muted">
      <div className="max-w-7xl mx-auto px-4 py-8">

        {/* Search and Filters */}
        <Card className="mb-8">
          <CardContent className="pt-6">
            <div className="space-y-4">
              {/* Primary Search and Filter Button */}
              <div className="flex flex-col md:flex-row gap-4">
                {/* Search */}
                <div className="flex-1 relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
                  <Input
                    placeholder={isRestaurantPage ? "Search restaurants..." : "Search stores..."}
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-10"
                  />
                </div>

                {/* Filter Button */}
                <Collapsible open={filtersOpen} onOpenChange={setFiltersOpen}>
                  <CollapsibleTrigger asChild>
                    <Button variant="outline" className="w-full md:w-auto">
                      <Filter className="h-4 w-4 mr-2" />
                      Filters
                      {filtersOpen ? <X className="h-4 w-4 ml-2" /> : null}
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      {/* Store Type Filter */}
                      {!isRestaurantPage && (
                        <Select value={storeTypeFilter} onValueChange={setStoreTypeFilter}>
                          <SelectTrigger>
                            <Store className="h-4 w-4 mr-2" />
                            <SelectValue placeholder="All Stores" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="all">All Stores</SelectItem>
                            <SelectItem value="retail">Retail Stores</SelectItem>
                          </SelectContent>
                        </Select>
                      )}

                      {/* Cuisine Filter (for restaurants) */}
                      {(isRestaurantPage || storeTypeFilter === "restaurant") && availableCuisines.length > 0 && (
                        <Select value={cuisineFilter} onValueChange={setCuisineFilter}>
                          <SelectTrigger>
                            <Utensils className="h-4 w-4 mr-2" />
                            <SelectValue placeholder="All Cuisines" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="all">All Cuisines</SelectItem>
                            {availableCuisines.map((cuisine) => (
                              <SelectItem key={cuisine} value={cuisine!}>
                                {cuisine}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      )}

                      {/* Delivery Filter */}
                      <Select value={deliveryFilter} onValueChange={setDeliveryFilter}>
                        <SelectTrigger>
                          <MapPin className="h-4 w-4 mr-2" />
                          <SelectValue placeholder="Delivery Options" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">All Options</SelectItem>
                          <SelectItem value="delivery">Delivery Available</SelectItem>
                          <SelectItem value="pickup">Pickup Only</SelectItem>
                        </SelectContent>
                      </Select>

                      {/* Rating Filter */}
                      <Select value={ratingFilter} onValueChange={setRatingFilter}>
                        <SelectTrigger>
                          <Filter className="h-4 w-4 mr-2" />
                          <SelectValue placeholder="Minimum Rating" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">All Ratings</SelectItem>
                          <SelectItem value="4+">4.0+ Stars</SelectItem>
                          <SelectItem value="3+">3.0+ Stars</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </CollapsibleContent>
                </Collapsible>

                {/* Location Button */}
                {!locationEnabled && (
                  <Button variant="outline" onClick={handleGetLocation}>
                    <MapPin className="h-4 w-4 mr-2" />
                    Enable Location
                  </Button>
                )}
              </div>

              {/* Location Status */}
              {locationEnabled && (
                <div className="flex items-center gap-2">
                  <MapPin className="h-4 w-4 text-green-500" />
                  <span className="text-sm text-muted-foreground">
                    Location enabled - stores sorted by distance
                  </span>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Simple header showing just stores */}
        <div className="mb-6">
          <h2 className="text-xl font-semibold">
            {isRestaurantPage ? "Restaurants" : "Stores"}
          </h2>
        </div>

        {/* Stores Grid */}
        {storesError ? (
          <Card>
            <CardContent className="pt-6 text-center">
              <Alert className="max-w-md mx-auto mb-6">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  Failed to load stores. Please try again.
                </AlertDescription>
              </Alert>
              <Button 
                onClick={() => refetchStores()} 
                variant="outline"
                disabled={storesLoading}
              >
                <RefreshCw className={`mr-2 h-4 w-4 ${storesLoading ? 'animate-spin' : ''}`} />
                Retry Loading Stores
              </Button>
            </CardContent>
          </Card>
        ) : storesLoading ? (
          <div className={`grid gap-2 sm:gap-4 ${
            isRestaurantPage || storeTypeFilter === "restaurant"
              ? "grid-cols-2 sm:grid-cols-2 md:grid-cols-2 lg:grid-cols-2" 
              : "grid-cols-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4"
          }`}>
            {Array.from({ length: 6 }).map((_, index) => (
              <Card key={index} className="animate-pulse">
                <CardContent className="p-3">
                  <div className="bg-gray-200 h-20 rounded-md mb-2"></div>
                  <div className="bg-gray-200 h-3 rounded mb-1"></div>
                  <div className="bg-gray-200 h-2 rounded w-2/3 mb-1"></div>
                  <div className="bg-gray-200 h-2 rounded w-1/2"></div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : filteredStores.length > 0 ? (
          <div className={`grid gap-2 sm:gap-4 ${
            isRestaurantPage || storeTypeFilter === "restaurant"
              ? "grid-cols-2 sm:grid-cols-2 md:grid-cols-2 lg:grid-cols-2" 
              : "grid-cols-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4"
          }`}>
            {filteredStores.map((store) => (
              <StoreCard
                key={store.id}
                store={store}
                showDistance={locationEnabled}
              />
            ))}
          </div>
        ) : (
          <Card>
            <CardContent className="pt-6 text-center">
              <div className="text-muted-foreground mb-4">
                <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-semibold mb-2">
                  {isRestaurantPage ? "No restaurants found" : "No stores found"}
                </h3>
                <p>Try adjusting your search criteria or filters to find what you're looking for</p>
              </div>
              <Button variant="outline" onClick={() => {
                setSearchQuery("");
                setStoreTypeFilter(isRestaurantPage ? "restaurant" : "all");
                setCuisineFilter("all");
                setDeliveryFilter("all");
                setRatingFilter("all");
              }}>
                Clear All Filters
              </Button>
            </CardContent>
          </Card>
        )}


      </div>
    </div>
  );
}