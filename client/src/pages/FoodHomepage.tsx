import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { ArrowRight, Star, Clock, TrendingUp, ChefHat, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import FoodCard from "@/components/FoodCard";
import RestaurantCard from "@/components/RestaurantCard";
import { useAuth } from "@/hooks/useAuth";
import { useAppMode } from "@/hooks/useAppMode";
import type { Product, Store } from "@shared/schema";
import { Swiper, SwiperSlide } from 'swiper/react';
import { Navigation, Pagination, Autoplay } from 'swiper/modules';
import { useEffect } from "react";
import 'swiper/css';
import 'swiper/css/navigation';
import 'swiper/css/pagination';

// Smart Recommendations Response Type
interface SmartRecommendationsResponse {
  products: Product[];
  stores: Store[];
  totalProducts: number;
  totalStores: number;
  isPersonalized: boolean;
}

export default function FoodHomepage() {
  const { user } = useAuth();
  const { mode } = useAppMode();

  // Track homepage visit for recommendations
  useEffect(() => {
    const trackVisit = async () => {
      try {
        await fetch('/api/recommendations/track', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
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

  // Get smart recommendations for food mode
  const {
    data: recommendations,
    isLoading: recommendationsLoading,
    error: recommendationsError,
  } = useQuery<SmartRecommendationsResponse>({
    queryKey: [`/api/recommendations/homepage`, 'food', user?.id],
    queryFn: async () => {
      const params = new URLSearchParams({
        mode: 'food',
        ...(user?.id && { userId: user.id.toString() })
      });
      
      const response = await fetch(`/api/recommendations/homepage?${params}`, {
        credentials: "include",
      });
      
      if (!response.ok) {
        throw new Error(`Failed to fetch recommendations: ${response.statusText}`);
      }
      
      return response.json();
    },
    retry: 3,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  // Fallback to regular API calls if recommendations fail
  const { data: foodItems } = useQuery<Product[]>({
    queryKey: ["/api/products"],
    select: (data) => data?.filter(product => product.productType === 'food') || [],
    enabled: !recommendations?.products?.length, // Only fetch if no recommendations
  });

  const { data: restaurants } = useQuery<Store[]>({
    queryKey: ["/api/stores"],
    select: (data) => data?.filter(store => store.storeType === 'restaurant') || [],
    enabled: !recommendations?.stores?.length, // Only fetch if no recommendations
  });

  // Use recommendations if available, otherwise fallback to regular data
  const recommendedProducts = recommendations?.products || [];
  const recommendedStores = recommendations?.stores || [];
  const isPersonalized = recommendations?.isPersonalized || false;

  const featuredFood = recommendedProducts.length > 0 
    ? recommendedProducts.slice(0, 8)
    : foodItems?.filter(item => item.isOnOffer || item.isFastSell).slice(0, 8) || [];

  const popularRestaurants = recommendedStores.length > 0
    ? recommendedStores.slice(0, 6)
    : restaurants?.slice(0, 6) || [];

  const quickBites = recommendedProducts.length > 0
    ? recommendedProducts.filter(item => item.preparationTime && parseInt(item.preparationTime ?? "0") <= 20).slice(0, 6)
    : foodItems?.filter(item => item.preparationTime && parseInt(item.preparationTime ?? "0") <= 20).slice(0, 6) || [];

  return (
    <div className="min-h-screen bg-gradient-to-br from-red-50 to-orange-50 dark:from-gray-900 dark:to-gray-800">
      {/* Hero Section */}
      <section className="relative overflow-hidden bg-gradient-to-r from-red-600 via-orange-500 to-yellow-500 text-white">
        <div className="absolute inset-0 bg-black/20"></div>
        <div className="relative container mx-auto px-4 py-12 sm:py-16 lg:py-24">
          <div className="max-w-4xl mx-auto text-center">
            <h1 className="text-2xl sm:text-3xl md:text-4xl lg:text-6xl font-bold mb-4 sm:mb-6 animate-fade-in">
              Delicious Food <span className="text-yellow-300">Delivered Fast</span>
            </h1>
            <p className="text-sm sm:text-base md:text-lg lg:text-2xl mb-6 sm:mb-8 text-red-100">
              Discover amazing restaurants and get your favorite food delivered in minutes
            </p>
            <div className="flex flex-col sm:flex-row gap-3 sm:gap-4 justify-center">
              <Link href="/restaurants">
                <Button size="sm" className="bg-white text-red-600 hover:bg-red-50 font-semibold px-6 sm:px-8 text-sm sm:text-base">
                  <ChefHat className="mr-2 h-4 w-4 sm:h-5 sm:w-5" />
                  Browse Restaurants
                </Button>
              </Link>
              <Link href="/food-categories">
                <Button size="sm" variant="outline" className="border-white text-white hover:bg-white hover:text-red-600 font-semibold px-6 sm:px-8 text-sm sm:text-base">
                  Explore Categories
                  <ArrowRight className="ml-2 h-4 w-4 sm:h-5 sm:w-5" />
                </Button>
              </Link>
            </div>
          </div>
        </div>
        
        {/* Decorative food icons */}
        <div className="absolute top-10 left-10 text-6xl opacity-20 animate-bounce">🍕</div>
        <div className="absolute top-20 right-20 text-5xl opacity-20 animate-bounce delay-100">🍔</div>
        <div className="absolute bottom-20 left-20 text-4xl opacity-20 animate-bounce delay-200">🍜</div>
        <div className="absolute bottom-10 right-10 text-5xl opacity-20 animate-bounce delay-300">🍰</div>
      </section>

      {/* Quick Stats */}
      <section className="py-8 bg-white dark:bg-gray-800 shadow-sm">
        <div className="container mx-auto px-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 sm:gap-6 text-center">
            <div>
              <div className="text-xl sm:text-2xl md:text-3xl font-bold text-red-600">{restaurants?.length || 0}+</div>
              <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Restaurants</div>
            </div>
            <div>
              <div className="text-xl sm:text-2xl md:text-3xl font-bold text-orange-600">{foodItems?.length || 0}+</div>
              <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Food Items</div>
            </div>
            <div>
              <div className="text-xl sm:text-2xl md:text-3xl font-bold text-yellow-600">25 min</div>
              <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Avg Delivery</div>
            </div>
            <div>
              <div className="text-xl sm:text-2xl md:text-3xl font-bold text-green-600">4.8★</div>
              <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400">Customer Rating</div>
            </div>
          </div>
        </div>
      </section>

      <div className="container mx-auto px-4 py-8 sm:py-12 space-y-12 sm:space-y-16">
        {/* Featured Offers */}
        {featuredFood.length > 0 && (
          <section>
            <div className="flex justify-between items-start mb-8 pr-2.5">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <h2 className="text-lg sm:text-xl md:text-2xl lg:text-3xl font-bold text-gray-900 dark:text-white flex items-center">
                    <TrendingUp className="mr-2 sm:mr-3 h-5 w-5 sm:h-6 sm:w-6 md:h-8 md:w-8 text-red-500" />
                    {isPersonalized ? "Recommended for You" : "Special Offers"}
                  </h2>
                  {isPersonalized && (
                    <Badge variant="secondary" className="bg-blue-100 text-blue-800">
                      <TrendingUp className="h-3 w-3 mr-1" />
                      Smart Pick
                    </Badge>
                  )}
                </div>
                <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400">
                  {isPersonalized ? "Personalized food recommendations based on your preferences" : "Limited time deals you don't want to miss"}
                </p>
              </div>
              <Link href="/food-offers" className="flex-shrink-0 mt-1">
                <Button variant="outline" className="border-red-500 text-red-500 hover:bg-red-50 w-8 h-8 p-0">
                  <ArrowRight className="h-4 w-4" />
                </Button>
              </Link>
            </div>
            
            <Swiper
              modules={[Navigation, Pagination, Autoplay]}
              spaceBetween={20}
              slidesPerView={1}
              navigation
              pagination={{ clickable: true }}
              autoplay={{ delay: 4000 }}
              breakpoints={{
                480: { slidesPerView: 2 },
                768: { slidesPerView: 3 },
                1024: { slidesPerView: 4 }
              }}
              className="pb-12"
            >
              {featuredFood.map((food) => (
                <SwiperSlide key={food.id}>
                  <FoodCard food={food} />
                </SwiperSlide>
              ))}
            </Swiper>
          </section>
        )}

        {/* Popular Restaurants */}
        {popularRestaurants.length > 0 && (
          <section>
            <div className="flex justify-between items-start mb-8 pr-2.5">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <h2 className="text-lg sm:text-xl md:text-2xl lg:text-3xl font-bold text-gray-900 dark:text-white flex items-center">
                    <Star className="mr-2 sm:mr-3 h-5 w-5 sm:h-6 sm:w-6 md:h-8 md:w-8 text-yellow-500" />
                    {isPersonalized ? "Restaurants You Might Like" : "Top Restaurants"}
                  </h2>
                  {isPersonalized && (
                    <Badge variant="secondary" className="bg-green-100 text-green-800">
                      <Sparkles className="h-3 w-3 mr-1" />
                      Curated
                    </Badge>
                  )}
                </div>
                <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400">
                  {isPersonalized ? "Personalized restaurant recommendations based on your taste" : "Highly rated restaurants in your area"}
                </p>
              </div>
              <Link href="/restaurants" className="flex-shrink-0 mt-1">
                <Button variant="outline" className="border-orange-500 text-orange-500 hover:bg-orange-50 w-8 h-8 p-0">
                  <ArrowRight className="h-4 w-4" />
                </Button>
              </Link>
            </div>
            
            <div className="grid grid-cols-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 sm:gap-4">
              {popularRestaurants.map((restaurant) => (
                <RestaurantCard key={restaurant.id} restaurant={restaurant} />
              ))}
            </div>
          </section>
        )}

        {/* Quick Bites */}
        {quickBites.length > 0 && (
          <section>
            <div className="flex justify-between items-start mb-8 pr-2.5">
              <div className="flex-1">
                <h2 className="text-lg sm:text-xl md:text-2xl lg:text-3xl font-bold text-gray-900 dark:text-white flex items-center">
                  <Clock className="mr-2 sm:mr-3 h-5 w-5 sm:h-6 sm:w-6 md:h-8 md:w-8 text-green-500" />
                  Quick Bites
                </h2>
                <p className="text-sm sm:text-base text-gray-600 dark:text-gray-400 mt-2">
                  Ready in 20 minutes or less
                </p>
              </div>
              <Link href="/quick-bites" className="flex-shrink-0 mt-1">
                <Button variant="outline" className="border-green-500 text-green-500 hover:bg-green-50 w-8 h-8 p-0">
                  <ArrowRight className="h-4 w-4" />
                </Button>
              </Link>
            </div>
            
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-2 sm:gap-3">
              {quickBites.map((food) => (
                <FoodCard key={food.id} food={food} />
              ))}
            </div>
          </section>
        )}

        {/* Call to Action */}
        <section className="bg-gradient-to-r from-red-500 to-orange-500 rounded-2xl p-6 sm:p-8 lg:p-12 text-white text-center">
          <h2 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl font-bold mb-3 sm:mb-4">
            Hungry? We've Got You Covered!
          </h2>
          <p className="text-sm sm:text-base md:text-lg lg:text-xl mb-6 sm:mb-8 text-red-100">
            Join thousands of satisfied customers who trust us for their food delivery needs
          </p>
          {!user && (
            <div className="flex flex-col sm:flex-row gap-3 sm:gap-4 justify-center">
              <Link href="/register">
                <Button size="sm" className="bg-white text-red-600 hover:bg-red-50 font-semibold px-6 sm:px-8 text-sm sm:text-base">
                  Sign Up Now
                </Button>
              </Link>
              <Link href="/login">
                <Button size="sm" variant="outline" className="border-white text-white hover:bg-white hover:text-red-600 font-semibold px-6 sm:px-8 text-sm sm:text-base">
                  Login
                </Button>
              </Link>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}