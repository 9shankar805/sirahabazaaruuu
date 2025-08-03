import { useQuery } from "@tanstack/react-query";
import { Link, useLocation } from "wouter";
import {
  ArrowRight,
  Star,
  MapPin,
  RefreshCw,
  AlertCircle,
  Loader2,
  Sparkles,
  TrendingUp,
  Eye,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import ProductCard from "@/components/ProductCard";
import StoreCard from "@/components/StoreCard";
import { useAuth } from "@/hooks/useAuth";
import { useAppMode } from "@/hooks/useAppMode";
import type { Product, Store } from "@shared/schema";
import { Swiper, SwiperSlide } from "swiper/react";
import { Navigation, Pagination, Autoplay } from "swiper/modules";
import { useEffect, useRef, useState } from "react";
import { apiRequest } from "@/lib/queryClient";

// Import Swiper CSS
import "swiper/css";
import "swiper/css/navigation";
import "swiper/css/pagination";

// Smart Recommendations Response Type
interface SmartRecommendationsResponse {
  products: Product[];
  stores: Store[];
  totalProducts: number;
  totalStores: number;
  isPersonalized: boolean;
}

// Hero slides data
const slider1 = "/assets/slider1.jpg";
const slider2 = "/assets/slider2.jpg";
const slide3 = "/assets/slide3.jpg";

export default function SmartHomepage() {
  const [, setLocation] = useLocation();
  const { user, isLoading } = useAuth();
  const { mode } = useAppMode();

  // Redirect sellers to their dashboard
  useEffect(() => {
    if (!isLoading && user?.role === "shopkeeper") {
      setLocation("/seller/dashboard");
    }
  }, [user, isLoading, setLocation]);

  // Track homepage visit for recommendations
  useEffect(() => {
    const trackVisit = async () => {
      try {
        await apiRequest('/api/recommendations/track', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            userId: user?.id || null,
            page: '/',
            action: 'homepage_visit'
          })
        });
      } catch (error) {
        console.log('Visit tracking failed (non-critical):', error);
      }
    };

    trackVisit();
  }, [user]);

  // Get smart recommendations
  const {
    data: recommendations,
    isLoading: recommendationsLoading,
    error: recommendationsError,
    refetch: refetchRecommendations,
  } = useQuery<SmartRecommendationsResponse>({
    queryKey: [`/api/recommendations/homepage`],
    queryFn: async () => {
      const params = new URLSearchParams({
        mode: mode,
        ...(user?.id && { userId: user.id.toString() })
      });
      return apiRequest(`/api/recommendations/homepage?${params}`);
    },
    retry: 3,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  const recommendedProducts = recommendations?.products || [];
  const recommendedStores = recommendations?.stores || [];
  const isPersonalized = recommendations?.isPersonalized || false;

  const categories = mode === "shopping" 
    ? [
        { name: "Electronics", icon: "📱", href: "/products?category=4" },
        { name: "Clothing", icon: "👕", href: "/products?category=5" },
        { name: "Home & Garden", icon: "🏠", href: "/products?category=3" },
        { name: "Books", icon: "📚", href: "/products?category=6" },
      ]
    : [
        { name: "Indian Cuisine", icon: "🍛", href: "/products?category=food&cuisine=indian" },
        { name: "Fast Food", icon: "🍔", href: "/products?category=food&cuisine=fast-food" },
        { name: "Pizza", icon: "🍕", href: "/products?category=food&type=pizza" },
        { name: "Desserts", icon: "🍰", href: "/products?category=food&cuisine=desserts" },
      ];

  // Error and Loading States
  const ErrorState = ({ onRetry }: { onRetry: () => void }) => (
    <Alert className="mb-6">
      <AlertCircle className="h-4 w-4" />
      <AlertDescription className="flex items-center justify-between">
        <span>Unable to load recommendations. Please try again.</span>
        <Button
          variant="outline"
          size="sm"
          onClick={onRetry}
          className="ml-4"
        >
          <RefreshCw className="h-3 w-3 mr-1" />
          Retry
        </Button>
      </AlertDescription>
    </Alert>
  );

  const LoadingState = () => (
    <div className="space-y-6">
      <div className="animate-pulse">
        <div className="h-8 bg-gray-200 rounded w-1/3 mb-4"></div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(8)].map((_, i) => (
            <div key={i} className="h-64 bg-gray-200 rounded"></div>
          ))}
        </div>
      </div>
    </div>
  );

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <div className="flex items-center justify-center py-20">
          <Loader2 className="h-8 w-8 animate-spin" />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Hero Section */}
      <section className="relative overflow-hidden bg-gradient-to-r from-blue-600 to-purple-700">
        <div className="container mx-auto px-4 py-12 sm:py-16 lg:py-20">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
            <div className="text-white space-y-6">
              <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold leading-tight">
                Welcome to Siraha Bazaar
                {isPersonalized && (
                  <Badge className="ml-3 bg-yellow-500 text-black">
                    <Sparkles className="h-3 w-3 mr-1" />
                    Personalized
                  </Badge>
                )}
              </h1>
              <p className="text-lg sm:text-xl text-blue-100 max-w-lg">
                {mode === "shopping" 
                  ? "Discover amazing products from local stores with smart recommendations tailored just for you."
                  : "Explore delicious food from the best restaurants with personalized dining suggestions."
                }
              </p>
              <div className="flex flex-col sm:flex-row gap-4">
                <Link href={mode === "shopping" ? "/products" : "/restaurants"}>
                  <Button size="lg" className="bg-white text-blue-700 hover:bg-blue-50">
                    Start {mode === "shopping" ? "Shopping" : "Ordering"}
                    <ArrowRight className="ml-2 h-4 w-4" />
                  </Button>
                </Link>
                {user && (
                  <Button variant="outline" size="lg" className="border-white text-white hover:bg-white hover:text-blue-700">
                    <Eye className="mr-2 h-4 w-4" />
                    View My Activity
                  </Button>
                )}
              </div>
            </div>
            
            {/* Hero Slider */}
            <div className="relative">
              <Swiper
                modules={[Navigation, Pagination, Autoplay]}
                spaceBetween={0}
                slidesPerView={1}
                navigation
                pagination={{ clickable: true }}
                autoplay={{ delay: 4000, disableOnInteraction: false }}
                className="rounded-xl overflow-hidden shadow-2xl"
              >
                <SwiperSlide>
                  <img 
                    src={slider1} 
                    alt="Featured Products" 
                    className="w-full h-64 sm:h-80 object-cover"
                  />
                </SwiperSlide>
                <SwiperSlide>
                  <img 
                    src={slider2} 
                    alt="Local Stores" 
                    className="w-full h-64 sm:h-80 object-cover"
                  />
                </SwiperSlide>
                <SwiperSlide>
                  <img 
                    src={slide3} 
                    alt="Fast Delivery" 
                    className="w-full h-64 sm:h-80 object-cover"
                  />
                </SwiperSlide>
              </Swiper>
            </div>
          </div>
        </div>
      </section>

      {/* Categories Section */}
      <section className="py-12 sm:py-16 bg-secondary/30">
        <div className="container mx-auto px-4">
          <h2 className="text-2xl sm:text-3xl font-bold text-center mb-8 sm:mb-12">
            Browse Categories
          </h2>
          <div className="grid grid-cols-4 sm:grid-cols-6 md:grid-cols-8 lg:grid-cols-10 xl:grid-cols-12 gap-4 sm:gap-6">
            {categories.map((category) => (
              <Link key={category.name} href={category.href}>
                <Card className="group hover:shadow-lg transition-all duration-200">
                  <CardContent className="p-6 text-center">
                    <div className="text-4xl mb-3">{category.icon}</div>
                    <h3 className="font-semibold text-sm sm:text-base group-hover:text-primary">
                      {category.name}
                    </h3>
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* Smart Recommendations Section */}
      <section className="py-12 sm:py-16">
        <div className="container mx-auto px-4">
          {recommendationsError ? (
            <ErrorState onRetry={refetchRecommendations} />
          ) : recommendationsLoading ? (
            <LoadingState />
          ) : (
            <>
              {/* Recommended Products */}
              <div className="mb-12">
                <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center mb-8 gap-4">
                  <div className="flex items-center gap-2">
                    <h2 className="text-2xl sm:text-3xl font-bold">
                      {isPersonalized ? "Recommended for You" : "Featured Products"}
                    </h2>
                    {isPersonalized && (
                      <Badge variant="secondary" className="bg-blue-100 text-blue-800">
                        <TrendingUp className="h-3 w-3 mr-1" />
                        Smart Pick
                      </Badge>
                    )}
                  </div>
                  <Link href="/products">
                    <Button variant="outline" className="border-primary text-primary hover:bg-primary hover:text-white">
                      View All ({recommendations?.totalProducts || 0})
                      <ArrowRight className="ml-2 h-4 w-4" />
                    </Button>
                  </Link>
                </div>

                {recommendedProducts.length === 0 ? (
                  <div className="text-center py-12">
                    <p className="text-muted-foreground text-lg mb-4">
                      No products available at the moment
                    </p>
                    <Button variant="outline" onClick={refetchRecommendations}>
                      <RefreshCw className="mr-2 h-4 w-4" />
                      Refresh
                    </Button>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 sm:gap-6">
                    {recommendedProducts.map((product) => (
                      <ProductCard key={product.id} product={product} />
                    ))}
                  </div>
                )}
              </div>

              {/* Recommended Stores */}
              <div>
                <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center mb-8 gap-4">
                  <div className="flex items-center gap-2">
                    <h2 className="text-2xl sm:text-3xl font-bold">
                      {isPersonalized ? "Stores You Might Like" : `Popular ${mode === "shopping" ? "Stores" : "Restaurants"}`}
                    </h2>
                    {isPersonalized && (
                      <Badge variant="secondary" className="bg-green-100 text-green-800">
                        <Sparkles className="h-3 w-3 mr-1" />
                        Curated
                      </Badge>
                    )}
                  </div>
                  <Link href={mode === "shopping" ? "/stores" : "/restaurants"}>
                    <Button variant="outline" className="border-primary text-primary hover:bg-primary hover:text-white">
                      View All ({recommendations?.totalStores || 0})
                      <ArrowRight className="ml-2 h-4 w-4" />
                    </Button>
                  </Link>
                </div>

                {recommendedStores.length === 0 ? (
                  <div className="text-center py-12">
                    <p className="text-muted-foreground text-lg mb-4">
                      No {mode === "shopping" ? "stores" : "restaurants"} available at the moment
                    </p>
                    <Button variant="outline" onClick={refetchRecommendations}>
                      <RefreshCw className="mr-2 h-4 w-4" />
                      Refresh
                    </Button>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4 sm:gap-6">
                    {recommendedStores.map((store) => (
                      <StoreCard key={store.id} store={store} />
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </section>

      {/* Call to Action Section */}
      <section className="py-12 sm:py-16 bg-gradient-to-r from-blue-600 to-purple-700">
        <div className="container mx-auto px-4 text-center text-white">
          <h2 className="text-2xl sm:text-3xl font-bold mb-4">
            Ready to Start {mode === "shopping" ? "Shopping" : "Ordering"}?
          </h2>
          <p className="text-lg text-blue-100 mb-8 max-w-2xl mx-auto">
            {mode === "shopping" 
              ? "Join thousands of happy customers shopping from local stores in Siraha with fast delivery."
              : "Join thousands of satisfied customers ordering delicious food from local restaurants with quick delivery."
            }
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link href={mode === "shopping" ? "/products" : "/restaurants"}>
              <Button size="lg" className="bg-white text-blue-700 hover:bg-blue-50">
                Browse {mode === "shopping" ? "Products" : "Menu"}
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
            {!user && (
              <Link href="/register">
                <Button variant="outline" size="lg" className="border-white text-white hover:bg-white hover:text-blue-700">
                  Create Account
                </Button>
              </Link>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}