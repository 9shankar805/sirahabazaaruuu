import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, Filter, Clock, Star, MapPin, Utensils, ChefHat, Loader2, AlertCircle, RefreshCw, ChevronDown, ChevronUp } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import ProductCard from "@/components/ProductCard";
import { getCurrentUserLocation } from "@/lib/distance";
import { useToast } from "@/hooks/use-toast";

interface Product {
  id: number;
  name: string;
  description?: string;
  price: string;
  originalPrice?: string;
  image?: string;
  category?: string;
  storeId: number;
  storeName?: string;
  storeType?: string;
  preparationTime?: string;
  spiceLevel?: string;
  isVegetarian?: boolean;
  isVegan?: boolean;
  ingredients?: string[];
  allergens?: string[];
  rating?: string;
  totalReviews?: number;
  inStock?: boolean;
  slug: string;
  deliveryTime?: string;
  storeDistance?: number;
}

interface Store {
  id: number;
  name: string;
  storeType: string;
  latitude?: string;
  longitude?: string;
  deliveryTime?: string;
  rating?: string;
}

export default function QuickBites() {
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [storeFilter, setStoreFilter] = useState("all");
  const [spiceLevelFilter, setSpiceLevelFilter] = useState("all");
  const [dietaryFilter, setDietaryFilter] = useState("all");
  const [priceRangeFilter, setPriceRangeFilter] = useState("all");
  const [sortBy, setSortBy] = useState("name");
  const [userLocation, setUserLocation] = useState<{ latitude: number; longitude: number } | null>(null);
  const [locationEnabled, setLocationEnabled] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const { toast } = useToast();

  // Fetch all products
  const { 
    data: products = [], 
    isLoading: productsLoading, 
    error: productsError,
    refetch: refetchProducts 
  } = useQuery({
    queryKey: ["/api/products"],
  });

  // Fetch all stores to get restaurant names and details
  const { 
    data: stores = [], 
    isLoading: storesLoading, 
    error: storesError 
  } = useQuery({
    queryKey: ["/api/stores"],
  });

  // Filter products to show only food items from restaurants
  const foodProducts = products.filter((product: Product) => {
    const store = stores.find((s: Store) => s.id === product.storeId);
    return store?.storeType === 'restaurant';
  });

  // Add store information and distance to products
  const enrichedProducts = foodProducts.map((product: Product) => {
    const store = stores.find((s: Store) => s.id === product.storeId);
    let distance = undefined;
    
    if (userLocation && store?.latitude && store?.longitude) {
      const storeLatitude = parseFloat(store.latitude);
      const storeLongitude = parseFloat(store.longitude);
      
      if (!isNaN(storeLatitude) && !isNaN(storeLongitude)) {
        const R = 6371; // Earth's radius in kilometers
        const dLat = (storeLatitude - userLocation.latitude) * Math.PI / 180;
        const dLon = (storeLongitude - userLocation.longitude) * Math.PI / 180;
        const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                  Math.cos(userLocation.latitude * Math.PI / 180) * Math.cos(storeLatitude * Math.PI / 180) *
                  Math.sin(dLon/2) * Math.sin(dLon/2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
        distance = R * c;
      }
    }
    
    return {
      ...product,
      storeName: store?.name || 'Unknown Restaurant',
      storeDistance: distance,
      deliveryTime: store?.deliveryTime || '30-45 min'
    };
  });

  // Get unique categories from food products
  const availableCategories = [...new Set(
    enrichedProducts
      .map(p => p.category)
      .filter(Boolean)
  )];

  // Get unique restaurants
  const availableRestaurants = [...new Set(
    enrichedProducts
      .map(p => ({ id: p.storeId, name: p.storeName }))
      .filter(r => r.name !== 'Unknown Restaurant')
  )];

  // Apply filters
  const filteredProducts = enrichedProducts.filter((product: Product) => {
    // Search filter
    if (searchQuery && !product.name.toLowerCase().includes(searchQuery.toLowerCase()) &&
        !product.description?.toLowerCase().includes(searchQuery.toLowerCase()) &&
        !product.storeName?.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }

    // Category filter
    if (categoryFilter !== "all" && product.category !== categoryFilter) {
      return false;
    }

    // Store filter
    if (storeFilter !== "all" && product.storeId.toString() !== storeFilter) {
      return false;
    }

    // Spice level filter
    if (spiceLevelFilter !== "all" && product.spiceLevel !== spiceLevelFilter) {
      return false;
    }

    // Dietary filter
    if (dietaryFilter === "vegetarian" && !product.isVegetarian) {
      return false;
    }
    if (dietaryFilter === "vegan" && !product.isVegan) {
      return false;
    }

    // Price range filter
    if (priceRangeFilter !== "all") {
      const price = parseFloat(product.price.replace(/[^\d.]/g, ''));
      switch (priceRangeFilter) {
        case "under-100":
          if (price >= 100) return false;
          break;
        case "100-300":
          if (price < 100 || price > 300) return false;
          break;
        case "300-500":
          if (price < 300 || price > 500) return false;
          break;
        case "over-500":
          if (price <= 500) return false;
          break;
      }
    }

    return true;
  });

  // Sort products
  const sortedProducts = [...filteredProducts].sort((a, b) => {
    switch (sortBy) {
      case "name":
        return a.name.localeCompare(b.name);
      case "price-low":
        return parseFloat(a.price.replace(/[^\d.]/g, '')) - parseFloat(b.price.replace(/[^\d.]/g, ''));
      case "price-high":
        return parseFloat(b.price.replace(/[^\d.]/g, '')) - parseFloat(a.price.replace(/[^\d.]/g, ''));
      case "rating":
        return parseFloat(b.rating || "0") - parseFloat(a.rating || "0");
      case "distance":
        if (!a.storeDistance && !b.storeDistance) return 0;
        if (!a.storeDistance) return 1;
        if (!b.storeDistance) return -1;
        return a.storeDistance - b.storeDistance;
      default:
        return 0;
    }
  });

  // Handle location access
  const handleGetLocation = async () => {
    try {
      const location = await getCurrentUserLocation();
      setUserLocation(location);
      setLocationEnabled(true);
      toast({
        title: "Location enabled",
        description: "Now showing distances to restaurants",
      });
    } catch (error) {
      toast({
        title: "Location access denied",
        description: "Enable location to see distances to restaurants",
        variant: "destructive",
      });
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <ChefHat className="h-8 w-8 text-orange-500" />
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              Quick Bites
            </h1>
          </div>
          <p className="text-gray-600 dark:text-gray-300">
            Discover delicious food items from all restaurants in one place
          </p>
        </div>

        {/* Filters */}
        <Card className="mb-8">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Filter className="h-5 w-5" />
                Find Your Perfect Meal
              </CardTitle>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowFilters(!showFilters)}
                className="flex items-center gap-2"
              >
                <Filter className="h-4 w-4" />
                {showFilters ? "Hide Filters" : "Show Filters"}
                {showFilters ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Search Bar - Always Visible */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <Input
                placeholder="Search for dishes, restaurants, or ingredients..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>

            {/* Collapsible Filters */}
            {showFilters && (
              <div className="space-y-6">
                {/* Filter Row 1 */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  {/* Category Filter */}
                  <Select value={categoryFilter} onValueChange={setCategoryFilter}>
                    <SelectTrigger>
                      <Utensils className="h-4 w-4 mr-2" />
                      <SelectValue placeholder="All Categories" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Categories</SelectItem>
                      {availableCategories.map((category) => (
                        <SelectItem key={category} value={category!}>
                          {category}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>

                  {/* Restaurant Filter */}
                  <Select value={storeFilter} onValueChange={setStoreFilter}>
                    <SelectTrigger>
                      <ChefHat className="h-4 w-4 mr-2" />
                      <SelectValue placeholder="All Restaurants" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Restaurants</SelectItem>
                      {availableRestaurants.map((restaurant) => (
                        <SelectItem key={restaurant.id} value={restaurant.id.toString()}>
                          {restaurant.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>

                  {/* Spice Level Filter */}
                  <Select value={spiceLevelFilter} onValueChange={setSpiceLevelFilter}>
                    <SelectTrigger>
                      <Filter className="h-4 w-4 mr-2" />
                      <SelectValue placeholder="Spice Level" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Spice Levels</SelectItem>
                      <SelectItem value="Mild">Mild</SelectItem>
                      <SelectItem value="Medium">Medium</SelectItem>
                      <SelectItem value="Hot">Hot</SelectItem>
                      <SelectItem value="Extra Hot">Extra Hot</SelectItem>
                    </SelectContent>
                  </Select>

                  {/* Location Button */}
                  {!locationEnabled && (
                    <Button variant="outline" onClick={handleGetLocation}>
                      <MapPin className="h-4 w-4 mr-2" />
                      Enable Location
                    </Button>
                  )}
                </div>

                {/* Filter Row 2 */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Dietary Filter */}
                  <Select value={dietaryFilter} onValueChange={setDietaryFilter}>
                    <SelectTrigger>
                      <Filter className="h-4 w-4 mr-2" />
                      <SelectValue placeholder="Dietary Preferences" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Options</SelectItem>
                      <SelectItem value="vegetarian">Vegetarian</SelectItem>
                      <SelectItem value="vegan">Vegan</SelectItem>
                    </SelectContent>
                  </Select>

                  {/* Price Range Filter */}
                  <Select value={priceRangeFilter} onValueChange={setPriceRangeFilter}>
                    <SelectTrigger>
                      <Filter className="h-4 w-4 mr-2" />
                      <SelectValue placeholder="Price Range" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Prices</SelectItem>
                      <SelectItem value="under-100">Under ₹100</SelectItem>
                      <SelectItem value="100-300">₹100 - ₹300</SelectItem>
                      <SelectItem value="300-500">₹300 - ₹500</SelectItem>
                      <SelectItem value="over-500">Over ₹500</SelectItem>
                    </SelectContent>
                  </Select>

                  {/* Sort Filter */}
                  <Select value={sortBy} onValueChange={setSortBy}>
                    <SelectTrigger>
                      <Filter className="h-4 w-4 mr-2" />
                      <SelectValue placeholder="Sort By" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="name">Name A-Z</SelectItem>
                      <SelectItem value="price-low">Price: Low to High</SelectItem>
                      <SelectItem value="price-high">Price: High to Low</SelectItem>
                      <SelectItem value="rating">Highest Rated</SelectItem>
                      {locationEnabled && (
                        <SelectItem value="distance">Nearest First</SelectItem>
                      )}
                    </SelectContent>
                  </Select>
                </div>

                {/* Location Controls */}
                <div className="flex items-center justify-between">
                  {locationEnabled ? (
                    <div className="flex items-center gap-2">
                      <MapPin className="h-4 w-4 text-green-500" />
                      <span className="text-sm text-muted-foreground">
                        Location enabled - showing distances to restaurants
                      </span>
                    </div>
                  ) : (
                    <div className="flex items-center gap-4">
                      <span className="text-sm text-muted-foreground">
                        Enable location to see distances to restaurants
                      </span>
                      <Button
                        onClick={handleGetLocation}
                        variant="outline"
                        size="sm"
                        className="flex items-center gap-2"
                      >
                        <MapPin className="h-4 w-4" />
                        Enable Location
                      </Button>
                    </div>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Total Food Items
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{enrichedProducts.length}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Restaurants
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{availableRestaurants.length}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Categories
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{availableCategories.length}</div>
            </CardContent>
          </Card>
        </div>

        {/* Results Counter */}
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-semibold">
            {sortedProducts.length > 0 ? (
              <>
                {sortedProducts.length} food item{sortedProducts.length !== 1 ? "s" : ""} found
                {enrichedProducts.length !== sortedProducts.length && (
                  <span className="text-muted-foreground ml-2">
                    (filtered from {enrichedProducts.length} total)
                  </span>
                )}
              </>
            ) : (
              "No food items found"
            )}
          </h2>
        </div>

        {/* Products Grid */}
        {productsError || storesError ? (
          <Card>
            <CardContent className="pt-6 text-center">
              <Alert className="max-w-md mx-auto mb-6">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  Failed to load food items. Please try again.
                </AlertDescription>
              </Alert>
              <Button 
                onClick={() => {
                  refetchProducts();
                }} 
                variant="outline"
                disabled={productsLoading || storesLoading}
              >
                <RefreshCw className={`mr-2 h-4 w-4 ${(productsLoading || storesLoading) ? 'animate-spin' : ''}`} />
                Retry Loading
              </Button>
            </CardContent>
          </Card>
        ) : (productsLoading || storesLoading) ? (
          <div className="grid grid-cols-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 sm:gap-4">
            {Array.from({ length: 8 }).map((_, index) => (
              <Card key={index} className="animate-pulse">
                <CardContent className="p-3">
                  <div className="bg-gray-200 h-32 rounded-md mb-3"></div>
                  <div className="bg-gray-200 h-4 rounded mb-2"></div>
                  <div className="bg-gray-200 h-3 rounded w-2/3 mb-2"></div>
                  <div className="bg-gray-200 h-3 rounded w-1/2"></div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : sortedProducts.length > 0 ? (
          <div className="grid grid-cols-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 sm:gap-4">
            {sortedProducts.map((product) => (
              <div key={product.id} className="relative">
                <ProductCard product={product} />
                {/* Restaurant Badge */}
                <div className="absolute top-2 left-2">
                  <Badge variant="secondary" className="text-xs bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200">
                    {product.storeName}
                  </Badge>
                </div>
                {/* Distance Badge */}
                {locationEnabled && product.storeDistance && (
                  <div className="absolute top-2 right-2">
                    <Badge variant="outline" className="text-xs bg-white/90 dark:bg-black/90">
                      {product.storeDistance.toFixed(1)} km
                    </Badge>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <Card>
            <CardContent className="pt-6 text-center">
              <div className="text-muted-foreground mb-4">
                <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-semibold mb-2">No food items found</h3>
                <p>Try adjusting your search criteria or filters to find delicious meals</p>
              </div>
              <Button variant="outline" onClick={() => {
                setSearchQuery("");
                setCategoryFilter("all");
                setStoreFilter("all");
                setSpiceLevelFilter("all");
                setDietaryFilter("all");
                setPriceRangeFilter("all");
                setSortBy("name");
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