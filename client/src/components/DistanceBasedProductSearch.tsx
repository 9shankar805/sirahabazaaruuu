import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { MapPin, Filter, SlidersHorizontal, Utensils, ShoppingBag, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { getCurrentUserLocation } from "@/lib/distance";
import ProductCard from "@/components/ProductCard";
import { useAppMode } from "@/hooks/useAppMode";
import type { Product, Store } from "@shared/schema";

interface ProductWithDistance extends Product {
  storeDistance?: number;
  storeName?: string;
  deliveryTime?: string;
  category?: string; // Add category to match the Product type
}

interface DistanceBasedProductSearchProps {
  searchQuery?: string;
  category?: string;
  className?: string;
  isRestaurantMode?: boolean;
}

export default function DistanceBasedProductSearch({ 
  searchQuery = "", 
  category = "",
  className = "",
  isRestaurantMode = false
}: DistanceBasedProductSearchProps) {
  const { mode } = useAppMode();
  const [userLocation, setUserLocation] = useState<{ latitude: number; longitude: number } | null>(null);
  const [sortBy, setSortBy] = useState<string>("distance");
  const [maxDistance, setMaxDistance] = useState<number>(50);
  const [isGettingLocation, setIsGettingLocation] = useState(false);
  
  // Food-specific filters
  const [spiceLevelFilter, setSpiceLevelFilter] = useState<string>("all");
  const [dietaryFilter, setDietaryFilter] = useState<string>("all");
  const [priceRangeFilter, setPriceRangeFilter] = useState<string>("all");
  const [preparationTimeFilter, setPreparationTimeFilter] = useState<string>("all");
  const [restaurantFilter, setRestaurantFilter] = useState<string>("all");
  
  // Determine if we're in food mode
  const isFoodMode = mode === 'food' || isRestaurantMode;

  // Add a temporary bypass for search to show all results when searching
  const bypassModeFiltering = searchQuery && searchQuery.trim().length > 0;

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

  // Fetch products - use food-specific API when in food mode and location is available
  const { data: products = [], isLoading, error: productsError } = useQuery<Product[]>({
    queryKey: isFoodMode && userLocation 
      ? ["/api/food/items", userLocation.latitude, userLocation.longitude, { 
          search: searchQuery, 
          spiceLevel: spiceLevelFilter,
          isVegetarian: dietaryFilter === 'vegetarian',
          radius: 10 // Modern food apps use 10km default
        }]
      : ["/api/products", { search: searchQuery, category }],
    queryFn: async () => {
      try {
        // Use modern food delivery API for food items with 10km radius
        if (isFoodMode && userLocation) {
          const params = new URLSearchParams({
            lat: userLocation.latitude.toString(),
            lon: userLocation.longitude.toString(),
            radius: '10', // 10km radius like Uber Eats, DoorDash
          });
          
          if (searchQuery) params.append('search', searchQuery);
          if (spiceLevelFilter !== 'all') params.append('spiceLevel', spiceLevelFilter);
          if (dietaryFilter === 'vegetarian') params.append('isVegetarian', 'true');
          
          const response = await fetch(`/api/food/items?${params}`);
          if (!response.ok) throw new Error('Failed to fetch food items');
          
          const data = await response.json();
          console.log(`[FOOD] Found ${data.count} food items within ${data.searchRadius}km`);
          return data.items;
        }
        
        // Fallback to regular products API for non-food items
        const params = new URLSearchParams();
        if (searchQuery?.trim()) params.append('search', searchQuery.trim());
        if (category?.trim()) {
          // Convert category string to ID if it's a number, otherwise use as-is
          const categoryParam = isNaN(Number(category)) ? category.trim() : category.trim();
          params.append('category', categoryParam);
          console.log(`[CATEGORY FILTER] Searching for category: ${categoryParam}`);
        }
        
        const response = await fetch(`/api/products?${params}`);
        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(`Failed to fetch products: ${response.status} ${errorText}`);
        }
        const data = await response.json();
        console.log(`[PRODUCTS] Found ${data.length} products for category: ${category}`);
        return data;
      } catch (error) {
        console.error('Error fetching products:', error);
        throw error;
      }
    },
    retry: 1,
    retryDelay: 1000,
  });

  // Fetch stores for distance calculation
  const { data: stores = [], error: storesError } = useQuery<Store[]>({
    queryKey: ["/api/stores"],
    queryFn: async () => {
      try {
        const response = await fetch('/api/stores');
        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(`Failed to fetch stores: ${response.status} ${errorText}`);
        }
        return response.json();
      } catch (error) {
        console.error('Error fetching stores:', error);
        throw error;
      }
    },
    retry: 1,
    retryDelay: 1000,
  });

  // Debug logging for search functionality
  useEffect(() => {
    console.log("DistanceBasedProductSearch received props:", { 
      searchQuery, 
      category,
      searchQueryLength: searchQuery.length,
      searchQueryTrimmed: searchQuery.trim(),
      isEmpty: !searchQuery || searchQuery.trim() === '',
      isFoodMode,
      mode
    });
  }, [searchQuery, category, isFoodMode, mode]);

  // Debug product and store data
  useEffect(() => {
    console.log("Products and stores data:", {
      totalProducts: products.length,
      totalStores: stores.length,
      productsWithStores: products.map(p => ({
        id: p.id,
        name: p.name,
        storeId: p.storeId,
        store: stores.find(s => s.id === p.storeId)
      }))
    });
  }, [products, stores]);

  // Filter products based on app mode
  const filteredProducts = products.filter(product => {
    if (bypassModeFiltering) return true; // Show all results when searching
    if (isFoodMode) {
      return product.productType === 'food';
    } else {
      return product.productType !== 'food';
    }
  });

  // Calculate distances and enrich products
  const enrichedProducts: ProductWithDistance[] = filteredProducts.map((product) => {
    const store = stores.find((s) => s.id === product.storeId);
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
      storeDistance: distance,
      storeName: store?.name || 'Unknown Store',
      deliveryTime: store?.deliveryTime || '30-45 min'
    };
  });

  // Filter products based on mode and store type
  const modeFilteredProducts = enrichedProducts.filter((product) => {
    // If user is searching or browsing categories, bypass mode filtering to show all search results
    if (bypassModeFiltering || (category && category.trim())) {
      console.log(`Category/Search mode: Including all products for category "${category}" or search "${searchQuery}"`);
      return true;
    }

    const store = stores.find((s) => s.id === product.storeId);
    console.log(`Mode filtering for product "${product.name}":`, {
      isFoodMode,
      storeType: store?.storeType,
      storeName: store?.name,
      productId: product.id,
      storeId: product.storeId
    });
    
    if (isFoodMode) {
      // In food mode, prioritize restaurants but also include food items if store type is missing
      const isRestaurant = store?.storeType === 'restaurant';
      const isFoodItem = product.category?.toLowerCase().includes('food') || 
                        product.name?.toLowerCase().includes('food') ||
                        product.preparationTime; // Has preparation time, likely food
      const shouldInclude = isRestaurant || (!store?.storeType && isFoodItem);
      console.log(`Food mode: Product "${product.name}" ${shouldInclude ? 'INCLUDED' : 'EXCLUDED'} (store type: ${store?.storeType}, isFoodItem: ${isFoodItem})`);
      return shouldInclude;
    } else {
      // In shopping mode, include all products (don't filter by store type when browsing categories)
      console.log(`Shopping mode: Product "${product.name}" INCLUDED`);
      return true;
    }
  });

  // Filter and sort products
  const filteredAndSortedProducts = modeFilteredProducts
    .filter((product) => {
      // Filter by search query first - this should be the MAIN filter
      if (searchQuery && searchQuery.trim()) {
        const searchLower = searchQuery.toLowerCase().trim();
        const nameMatch = product.name.toLowerCase().includes(searchLower);
        const descriptionMatch = product.description?.toLowerCase().includes(searchLower);
        const categoryMatch = product.category?.toLowerCase().includes(searchLower);
        const storeNameMatch = product.storeName?.toLowerCase().includes(searchLower);
        
        console.log(`Filtering product "${product.name}" with search "${searchQuery}":`, {
          nameMatch, descriptionMatch, categoryMatch, storeNameMatch,
          name: product.name,
          description: product.description,
          category: product.category,
          storeName: product.storeName
        });
        
        // If we have a search query, ONLY show products that match it
        const matchesSearch = nameMatch || descriptionMatch || categoryMatch || storeNameMatch;
        if (!matchesSearch) {
          console.log(`❌ Product "${product.name}" filtered out - no match`);
          return false;
        }
        console.log(`✅ Product "${product.name}" included - matches search`);
      }
      
      // Filter by category if provided (secondary filter)
      if (category && category.trim()) {
        // Check if category is a number (categoryId) or name
        const categoryParam = category.trim();
        const categoryId = parseInt(categoryParam);
        
        if (!isNaN(categoryId)) {
          // Category is an ID, compare with product.categoryId
          if (product.categoryId !== categoryId) {
            console.log(`❌ Product "${product.name}" filtered out - categoryId ${product.categoryId} !== ${categoryId}`);
            return false;
          }
          console.log(`✅ Product "${product.name}" matches categoryId ${categoryId}`);
        } else {
          // Category is a name, compare with product.category
          const categoryLower = categoryParam.toLowerCase();
          if (!product.category?.toLowerCase().includes(categoryLower)) {
            console.log(`❌ Product "${product.name}" filtered out - category "${product.category}" doesn't include "${categoryLower}"`);
            return false;
          }
          console.log(`✅ Product "${product.name}" matches category name "${categoryLower}"`);
        }
      }

      // Food-specific filters (only in food mode, and only when not actively searching)
      if (isFoodMode && !bypassModeFiltering) {
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

        // Preparation time filter
        if (preparationTimeFilter !== "all") {
          const prepTime = parseInt(product.preparationTime || "0");
          switch (preparationTimeFilter) {
            case "quick":
              if (prepTime > 20) return false;
              break;
            case "medium":
              if (prepTime <= 20 || prepTime > 45) return false;
              break;
            case "slow":
              if (prepTime <= 45) return false;
              break;
          }
        }

        // Restaurant filter
        if (restaurantFilter !== "all" && product.storeId.toString() !== restaurantFilter) {
          return false;
        }
      }
      
      // Filter by distance if location is available (tertiary filter, but not during active search)
      if (userLocation && product.storeDistance !== undefined && !bypassModeFiltering && !searchQuery) {
        console.log(`Distance filter: ${product.name} at ${product.storeDistance}km vs max ${maxDistance}km`);
        return product.storeDistance <= maxDistance;
      }
      
      // If no search query, show all products (or filtered by category/distance only)
      console.log(`✅ Product "${product.name}" passed all filters`);
      return true;
    })
    .sort((a, b) => {
      switch (sortBy) {
        case "distance":
          if (!userLocation) return 0;
          const distA = a.storeDistance ?? Infinity;
          const distB = b.storeDistance ?? Infinity;
          return distA - distB;
        case "price-low":
          return Number(a.price) - Number(b.price);
        case "price-high":
          return Number(b.price) - Number(a.price);
        case "rating":
          return Number(b.rating) - Number(a.rating);
        default:
          return 0;
      }
    });

  // Debug final filtered results (simplified)
  useEffect(() => {
    if (searchQuery) {
      console.log(`Search "${searchQuery}": ${enrichedProducts.length} total → ${modeFilteredProducts.length} mode filtered → ${filteredAndSortedProducts.length} final results`);
    }
  }, [enrichedProducts, modeFilteredProducts, filteredAndSortedProducts, searchQuery]);

  // Get unique restaurants for food mode
  const availableRestaurants = modeFilteredProducts
    .reduce((acc: Array<{id: number, name: string}>, product) => {
      if (product.storeName !== 'Unknown Store' && !acc.find(r => r.id === product.storeId)) {
        acc.push({ id: product.storeId, name: product.storeName || 'Unknown Store' });
      }
      return acc;
    }, []);

  const FilterControls = () => (
    <div className="space-y-4">
      {/* Mode Indicator */}
      <div className="flex items-center gap-2 p-3 bg-blue-50 border border-blue-200 rounded-lg">
        {isFoodMode ? (
          <Utensils className="h-4 w-4 text-orange-600" />
        ) : (
          <ShoppingBag className="h-4 w-4 text-blue-600" />
        )}
        <span className="text-sm font-medium text-gray-700">
          {isFoodMode ? 'Food Mode: Restaurant Items Only' : 'Shopping Mode: Retail Items Only'}
        </span>
      </div>

      {/* Location Status */}
      <div className="space-y-2">
        <Label>Location</Label>
        {!userLocation ? (
          <Button 
            onClick={getUserLocation} 
            disabled={isGettingLocation}
            variant="outline"
            className="w-full"
          >
            <MapPin className="h-4 w-4 mr-2" />
            {isGettingLocation ? "Getting Location..." : "Get My Location"}
          </Button>
        ) : (
          <div className="flex items-center justify-between p-3 bg-green-50 border border-green-200 rounded-lg">
            <div className="flex items-center gap-2">
              <MapPin className="h-4 w-4 text-green-600" />
              <span className="text-sm text-green-700 font-medium">
                Location Found
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Distance Filter */}
      {userLocation && (
        <div className="space-y-2">
          <Label>Maximum Distance (km)</Label>
          <Select value={maxDistance.toString()} onValueChange={(value) => setMaxDistance(Number(value))}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1">Within 1 km</SelectItem>
              <SelectItem value="3">Within 3 km</SelectItem>
              <SelectItem value="5">Within 5 km</SelectItem>
              <SelectItem value="10">Within 10 km</SelectItem>
              <SelectItem value="20">Within 20 km</SelectItem>
              <SelectItem value="50">Within 50 km</SelectItem>
            </SelectContent>
          </Select>
        </div>
      )}

      {/* Food-specific filters */}
      {isFoodMode && (
        <>
          {/* Restaurant Filter */}
          <div className="space-y-2">
            <Label>Restaurant</Label>
            <Select value={restaurantFilter} onValueChange={setRestaurantFilter}>
              <SelectTrigger>
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
          </div>

          {/* Spice Level Filter */}
          <div className="space-y-2">
            <Label>Spice Level</Label>
            <Select value={spiceLevelFilter} onValueChange={setSpiceLevelFilter}>
              <SelectTrigger>
                <SelectValue placeholder="All Spice Levels" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Spice Levels</SelectItem>
                <SelectItem value="mild">Mild</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="hot">Hot</SelectItem>
                <SelectItem value="extra_hot">Extra Hot</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Dietary Filter */}
          <div className="space-y-2">
            <Label>Dietary Options</Label>
            <Select value={dietaryFilter} onValueChange={setDietaryFilter}>
              <SelectTrigger>
                <SelectValue placeholder="All Dietary Options" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Options</SelectItem>
                <SelectItem value="vegetarian">Vegetarian</SelectItem>
                <SelectItem value="vegan">Vegan</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Price Range Filter */}
          <div className="space-y-2">
            <Label>Price Range</Label>
            <Select value={priceRangeFilter} onValueChange={setPriceRangeFilter}>
              <SelectTrigger>
                <SelectValue placeholder="All Prices" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Prices</SelectItem>
                <SelectItem value="under-100">Under ₹100</SelectItem>
                <SelectItem value="100-300">₹100 - ₹300</SelectItem>
                <SelectItem value="300-500">₹300 - ₹500</SelectItem>
                <SelectItem value="over-500">Over ₹500</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Preparation Time Filter */}
          <div className="space-y-2">
            <Label>Preparation Time</Label>
            <Select value={preparationTimeFilter} onValueChange={setPreparationTimeFilter}>
              <SelectTrigger>
                <SelectValue placeholder="All Times" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Times</SelectItem>
                <SelectItem value="quick">Quick (≤20 min)</SelectItem>
                <SelectItem value="medium">Medium (21-45 min)</SelectItem>
                <SelectItem value="slow">Slow (45+ min)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </>
      )}

      {/* Sort Options */}
      <div className="space-y-2">
        <Label>Sort By</Label>
        <Select value={sortBy} onValueChange={setSortBy}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {userLocation && <SelectItem value="distance">Nearest First</SelectItem>}
            <SelectItem value="price-low">Price: Low to High</SelectItem>
            <SelectItem value="price-high">Price: High to Low</SelectItem>
            <SelectItem value="rating">Highest Rated</SelectItem>
          </SelectContent>
        </Select>
      </div>
    </div>
  );

  // Display error state
  if (productsError || storesError) {
    return (
      <div className="space-y-6">
        <div className="text-center py-12">
          <div className="text-red-500 mb-4">
            <AlertCircle className="h-12 w-12 mx-auto mb-2" />
            <h3 className="text-lg font-medium mb-2">Error Loading Data</h3>
            <p className="text-sm text-muted-foreground">
              {productsError?.message || storesError?.message || "Failed to load products or stores"}
            </p>
          </div>
          <Button 
            onClick={() => window.location.reload()} 
            variant="outline"
            className="mt-4"
          >
            Try Again
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className={className}>
      {/* Header with Filter Button */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            {isFoodMode ? (
              <Utensils className="h-5 w-5 text-orange-600" />
            ) : (
              <ShoppingBag className="h-5 w-5 text-blue-600" />
            )}
            {searchQuery ? `Search results for "${searchQuery}"` : (isFoodMode ? "Food Items" : "Products")}
          </h2>
          <p className="text-sm text-muted-foreground">
            {userLocation 
              ? `Showing ${filteredAndSortedProducts.length} ${isFoodMode ? 'food items' : 'products'} sorted by distance`
              : `Showing ${filteredAndSortedProducts.length} ${isFoodMode ? 'food items' : 'products'}`
            }
            {searchQuery && ` • Searching for: "${searchQuery}"`}
          </p>
          {isFoodMode && (
            <div className="mt-1">
              <Badge variant="outline" className="text-orange-600 border-orange-200">
                Restaurant Items Only
              </Badge>
            </div>
          )}
        </div>

        {/* Mobile Filter Sheet */}
        <Sheet>
          <SheetTrigger asChild>
            <Button variant="outline" size="sm">
              <SlidersHorizontal className="h-4 w-4 mr-2" />
              Filter & Sort
            </Button>
          </SheetTrigger>
          <SheetContent>
            <SheetHeader>
              <SheetTitle>Filter & Sort Products</SheetTitle>
            </SheetHeader>
            <div className="mt-6">
              <FilterControls />
            </div>
          </SheetContent>
        </Sheet>
      </div>

      {/* Desktop Filters Sidebar */}
      <div className="hidden lg:grid lg:grid-cols-4 gap-6">
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Filters</CardTitle>
            </CardHeader>
            <CardContent>
              <FilterControls />
            </CardContent>
          </Card>
        </div>

        {/* Products Grid */}
        <div className="lg:col-span-3">
          {isLoading ? (
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="animate-pulse">
                  <div className="bg-gray-200 h-48 rounded-lg mb-2"></div>
                  <div className="bg-gray-200 h-4 rounded mb-1"></div>
                  <div className="bg-gray-200 h-3 rounded w-3/4"></div>
                </div>
              ))}
            </div>
          ) : filteredAndSortedProducts.length > 0 ? (
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              {filteredAndSortedProducts.map((product) => (
                <ProductCard key={product.id} product={product} />
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <h3 className="text-lg font-medium mb-2">No products found</h3>
              <p className="text-muted-foreground">
                {userLocation 
                  ? "Try increasing the distance range or adjusting your search."
                  : "Try different search terms or enable location access for distance-based results."
                }
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Mobile Products Grid */}
      <div className="lg:hidden">
        {isLoading ? (
          <div className="grid grid-cols-2 gap-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="animate-pulse">
                <div className="bg-gray-200 h-32 rounded-lg mb-2"></div>
                <div className="bg-gray-200 h-4 rounded mb-1"></div>
                <div className="bg-gray-200 h-3 rounded w-3/4"></div>
              </div>
            ))}
          </div>
        ) : filteredAndSortedProducts.length > 0 ? (
          <div className="grid grid-cols-2 gap-4">
            {filteredAndSortedProducts.map((product) => (
              <ProductCard key={product.id} product={product} />
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <h3 className="text-lg font-medium mb-2">No products found</h3>
            <p className="text-muted-foreground text-sm">
              {userLocation 
                ? "Try increasing the distance range or adjusting your search."
                : "Try different search terms or enable location access for distance-based results."
              }
            </p>
          </div>
        )}
      </div>
    </div>
  );
}