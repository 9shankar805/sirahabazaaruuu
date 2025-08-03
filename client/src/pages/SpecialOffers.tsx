import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardFooter, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useLocation } from "wouter";
import { useAppMode } from "@/hooks/useAppMode";
import { useCart } from "@/hooks/useCart";
import { useToast } from "@/hooks/use-toast";
import { 
  TrendingUp, 
  Search, 
  Clock, 
  MapPin, 
  Star,
  Percent,
  Filter,
  SortAsc,
  Leaf,
  Utensils,
  Package
} from "lucide-react";
import type { Product, Store } from "@shared/schema";

interface ProductWithStore extends Product {
  store?: Store;
}

export default function SpecialOffers() {
  const [, setLocation] = useLocation();
  const { mode } = useAppMode();
  const { selectSingleItem } = useCart();
  const { toast } = useToast();
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState<"discount" | "price" | "name">("discount");

  // Fetch special offers
  const { data: specialOffers, isLoading, error } = useQuery<ProductWithStore[]>({
    queryKey: ['/api/products/special-offers'],
    queryFn: async () => {
      const response = await fetch('/api/products/special-offers');
      if (!response.ok) throw new Error('Failed to fetch special offers');
      const offers = await response.json();
      
      // Get store information for each product
      const offersWithStores = await Promise.all(
        offers.map(async (product: Product) => {
          try {
            const storeResponse = await fetch(`/api/stores/${product.storeId}`);
            if (storeResponse.ok) {
              const store = await storeResponse.json();
              return { ...product, store };
            }
          } catch (error) {
            console.error('Error fetching store:', error);
          }
          return product;
        })
      );
      
      return offersWithStores;
    },
  });

  // Filter offers based on app mode and search
  const filteredOffers = specialOffers?.filter(product => {
    const matchesMode = mode === 'food' ? 
      (product.productType === 'food' || product.store?.storeType === 'restaurant') :
      (product.productType === 'retail' || product.store?.storeType === 'retail');
    
    const matchesSearch = !searchQuery || 
      product.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      product.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      product.store?.name.toLowerCase().includes(searchQuery.toLowerCase());
    
    return matchesMode && matchesSearch;
  }) || [];

  // Sort offers
  const sortedOffers = [...filteredOffers].sort((a, b) => {
    switch (sortBy) {
      case "discount":
        return (b.offerPercentage || 0) - (a.offerPercentage || 0);
      case "price":
        return parseFloat(a.price) - parseFloat(b.price);
      case "name":
        return a.name.localeCompare(b.name);
      default:
        return 0;
    }
  });

  // Calculate discount amount
  const calculateDiscountAmount = (product: Product) => {
    if (product.originalPrice) {
      const original = parseFloat(product.originalPrice);
      const current = parseFloat(product.price);
      return (original - current).toFixed(2);
    }
    return "0.00";
  };

  // Handle product click
  const handleProductClick = (product: Product) => {
    if (product.productType === 'food' || product.store?.storeType === 'restaurant') {
      setLocation(`/food/${product.id}`);
    } else {
      setLocation(`/products/${product.id}`);
    }
  };

  if (error) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-red-600 mb-4">Error Loading Special Offers</h1>
          <p className="text-gray-600">Failed to load special offers. Please try again later.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-gradient-to-r from-red-500 to-orange-500 text-white">
        <div className="container mx-auto px-4 py-8">
          <div className="flex items-center gap-3 mb-4">
            <TrendingUp className="h-8 w-8" />
            <h1 className="text-3xl font-bold">
              {mode === 'food' ? 'Food Special Offers' : 'Shopping Special Offers'}
            </h1>
          </div>
          <p className="text-red-100 text-lg">
            {mode === 'food' 
              ? 'Amazing discounts on your favorite restaurant items' 
              : 'Incredible deals on top products - limited time only!'
            }
          </p>
          
          {/* Search and Filters */}
          <div className="flex flex-col sm:flex-row gap-4 mt-6">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                type="text"
                placeholder={`Search ${mode === 'food' ? 'food items' : 'products'}...`}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 bg-white/10 border-white/20 text-white placeholder:text-red-200"
              />
            </div>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as "discount" | "price" | "name")}
              className="px-4 py-2 rounded-md bg-white/10 border border-white/20 text-white"
            >
              <option value="discount">Sort by Discount</option>
              <option value="price">Sort by Price</option>
              <option value="name">Sort by Name</option>
            </select>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="container mx-auto px-4 py-8">
        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
            {Array.from({ length: 8 }).map((_, index) => (
              <Card key={index} className="overflow-hidden">
                <Skeleton className="h-48 w-full" />
                <CardHeader>
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-3 w-1/2" />
                </CardHeader>
                <CardContent>
                  <Skeleton className="h-6 w-1/3" />
                </CardContent>
              </Card>
            ))}
          </div>
        ) : sortedOffers.length === 0 ? (
          <div className="text-center py-12">
            <Percent className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h2 className="text-2xl font-bold text-gray-600 mb-2">No Special Offers Available</h2>
            <p className="text-gray-500">
              {searchQuery 
                ? 'No offers match your search criteria.' 
                : `No special offers available in ${mode} mode right now.`
              }
            </p>
          </div>
        ) : (
          <>
            {/* Results count */}
            <div className="flex items-center justify-between mb-6">
              <p className="text-gray-600">
                Found {sortedOffers.length} special offer{sortedOffers.length !== 1 ? 's' : ''}
                {searchQuery && ` for "${searchQuery}"`}
              </p>
              <Badge variant="secondary" className="bg-red-100 text-red-800">
                {mode === 'food' ? 'Food Offers' : 'Shopping Offers'}
              </Badge>
            </div>

            {/* Products Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
              {sortedOffers.map((product) => (
                <Card 
                  key={product.id} 
                  className="overflow-hidden hover:shadow-lg transition-all duration-300 cursor-pointer group"
                  onClick={() => handleProductClick(product)}
                >
                  <div className="relative h-48">
                    <img
                      src={(product.images && product.images[0]) || product.imageUrl || "https://images.unsplash.com/photo-1565299624946-b28f40a0ca4b?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&h=300"}
                      alt={product.name}
                      className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                      onError={(e) => {
                        e.currentTarget.src = "https://images.unsplash.com/photo-1565299624946-b28f40a0ca4b?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&h=300";
                      }}
                    />
                    
                    {/* Discount Badge */}
                    <Badge className="absolute top-2 left-2 bg-red-500 hover:bg-red-600 text-white font-bold">
                      {product.offerPercentage}% OFF
                    </Badge>
                    
                    {/* Product Type Badge */}
                    <Badge className="absolute top-2 right-2 bg-white/90 text-gray-800">
                      {product.productType === 'food' ? (
                        <><Utensils className="h-3 w-3 mr-1" /> Food</>
                      ) : (
                        <><Package className="h-3 w-3 mr-1" /> Product</>
                      )}
                    </Badge>

                    {/* Food specific badges */}
                    {product.productType === 'food' && (
                      <div className="absolute bottom-2 left-2 flex space-x-1">
                        {product.isVegetarian && (
                          <Badge className="bg-green-500 hover:bg-green-600 text-white">
                            <Leaf className="h-3 w-3" />
                          </Badge>
                        )}
                        {product.isVegan && (
                          <Badge className="bg-green-600 hover:bg-green-700 text-white">
                            Vegan
                          </Badge>
                        )}
                      </div>
                    )}
                  </div>

                  <CardHeader className="pb-2">
                    <h3 className="font-semibold text-lg text-gray-900 line-clamp-1">
                      {product.name}
                    </h3>
                    {product.store && (
                      <div className="flex items-center text-sm text-gray-600">
                        <MapPin className="h-3 w-3 mr-1" />
                        {product.store.name}
                      </div>
                    )}
                  </CardHeader>

                  <CardContent className="py-2">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xl font-bold text-green-600">
                            ₹{product.price}
                          </span>
                          {product.originalPrice && (
                            <span className="text-sm text-gray-500 line-through">
                              ₹{product.originalPrice}
                            </span>
                          )}
                        </div>
                        <div className="text-sm text-green-600 font-medium">
                          Save ₹{calculateDiscountAmount(product)}
                        </div>
                      </div>
                      {product.rating && parseFloat(product.rating) > 0 && (
                        <div className="flex items-center">
                          <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                          <span className="text-sm text-gray-600 ml-1">
                            {product.rating}
                          </span>
                        </div>
                      )}
                    </div>

                    {product.offerEndDate && (
                      <div className="flex items-center text-xs text-red-600 mt-2">
                        <Clock className="h-3 w-3 mr-1" />
                        Ends {new Date(product.offerEndDate).toLocaleDateString()}
                      </div>
                    )}
                  </CardContent>

                  <CardFooter className="pt-2">
                    <Button 
                      className="w-full bg-red-500 hover:bg-red-600 text-white"
                      onClick={async (e) => {
                        e.stopPropagation(); // Prevent card click
                        try {
                          if (mode === 'food') {
                            // Select only this item for checkout
                            await selectSingleItem(product.id);
                            toast({
                              title: "Ready for Checkout",
                              description: `${product.name} selected for checkout`,
                            });
                            setLocation("/checkout");
                          } else {
                            // For shopping items, go to product detail
                            setLocation(`/products/${product.id}`);
                          }
                        } catch (error) {
                          toast({
                            title: "Error",
                            description: "Failed to prepare item for checkout",
                            variant: "destructive",
                          });
                        }
                      }}
                    >
                      {mode === 'food' ? 'Order Now' : 'View Deal'}
                    </Button>
                  </CardFooter>
                </Card>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}