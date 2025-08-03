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
import { Navigation, Pagination, Autoplay, FreeMode } from "swiper/modules";
import { useEffect, useRef, useState } from "react";
import { apiRequest } from "@/lib/queryClient";

// Countdown Timer Component
const CountdownTimer = () => {
  const [timeLeft, setTimeLeft] = useState({
    days: 2,
    hours: 23,
    minutes: 59,
    seconds: 59,
  });

  useEffect(() => {
    // Calculate time until next 3-day interval
    const calculateTimeLeft = () => {
      const now = new Date();
      // Get days since epoch to calculate 3-day cycle
      const daysSinceEpoch = Math.floor(now.getTime() / (1000 * 60 * 60 * 24));
      const daysInCurrentCycle = daysSinceEpoch % 3; // 0, 1, or 2
      const daysLeft = 2 - daysInCurrentCycle; // Days left in current 3-day cycle

      // Calculate hours, minutes, seconds left in current day
      const endOfDay = new Date(now);
      endOfDay.setHours(23, 59, 59, 999);

      // If it's the last day of the cycle, calculate time until midnight
      if (daysLeft === 0) {
        const diff = endOfDay.getTime() - now.getTime();
        const hours = Math.floor(
          (diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60),
        );
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((diff % (1000 * 60)) / 1000);

        setTimeLeft({
          days: 0,
          hours,
          minutes,
          seconds,
        });
      } else {
        // For other days, just show full days until reset
        setTimeLeft({
          days: daysLeft,
          hours: 23 - now.getHours(),
          minutes: 59 - now.getMinutes(),
          seconds: 59 - now.getSeconds(),
        });
      }
    };

    // Update every second
    const timer = setInterval(calculateTimeLeft, 1000);
    calculateTimeLeft(); // Initial call

    return () => clearInterval(timer);
  }, []);

  return (
    <div className="flex items-center justify-center gap-2 sm:gap-4 mt-6">
      <div className="bg-white/20 backdrop-blur-sm rounded-lg p-3 sm:p-4 text-center min-w-[60px] sm:min-w-[80px]">
        <div className="text-2xl sm:text-4xl font-bold text-white">
          {timeLeft.days.toString().padStart(2, "0")}
        </div>
        <div className="text-xs sm:text-sm opacity-80">Days</div>
      </div>
      <div className="text-2xl sm:text-4xl font-bold text-white">:</div>
      <div className="bg-white/20 backdrop-blur-sm rounded-lg p-3 sm:p-4 text-center min-w-[60px] sm:min-w-[80px]">
        <div className="text-2xl sm:text-4xl font-bold text-white">
          {timeLeft.hours.toString().padStart(2, "0")}
        </div>
        <div className="text-xs sm:text-sm opacity-80">Hours</div>
      </div>
      <div className="text-2xl sm:text-4xl font-bold text-white">:</div>
      <div className="bg-white/20 backdrop-blur-sm rounded-lg p-3 sm:p-4 text-center min-w-[60px] sm:min-w-[80px]">
        <div className="text-2xl sm:text-4xl font-bold text-white">
          {timeLeft.minutes.toString().padStart(2, "0")}
        </div>
        <div className="text-xs sm:text-sm opacity-80">Minutes</div>
      </div>
      <div className="text-2xl sm:text-4xl font-bold text-white">:</div>
      <div className="bg-white/20 backdrop-blur-sm rounded-lg p-3 sm:p-4 text-center min-w-[60px] sm:min-w-[80px]">
        <div className="text-2xl sm:text-4xl font-bold text-white">
          {timeLeft.seconds.toString().padStart(2, "0")}
        </div>
        <div className="text-xs sm:text-sm opacity-80">Seconds</div>
      </div>
    </div>
  );
};

// Import Swiper styles
import "swiper/css";
import "swiper/css/navigation";
import "swiper/css/pagination";
import "swiper/css/autoplay";

// Custom styles for categories pagination
const categoriesPaginationStyles = `
.categories-pagination .swiper-pagination-bullet {
  background: #e2e8f0 !important;
  opacity: 0.5 !important;
  width: 8px !important;
  height: 8px !important;
  margin: 0 4px !important;
  transition: all 0.3s ease !important;
}

.categories-pagination .swiper-pagination-bullet-active {
  background: #3b82f6 !important;
  opacity: 1 !important;
  transform: scale(1.2) !important;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleSheet = document.createElement('style');
  styleSheet.textContent = categoriesPaginationStyles;
  document.head.appendChild(styleSheet);
}

// Smart Recommendations Response Type
interface SmartRecommendationsResponse {
  products: Product[];
  stores: Store[];
  totalProducts: number;
  totalStores: number;
  isPersonalized: boolean;
}

// Slider image paths - using direct paths from public directory
const slider1 = "/assets/slider2.jpg";
const slider2 = "/assets/slider1.jpg";
const slider3 = "/assets/slide3.jpg"; // Using slider2 as fallback for slider3

export default function Homepage() {
  const [, setLocation] = useLocation();
  const { user, isLoading } = useAuth();
  const { mode } = useAppMode();

  // Redirect sellers to their dashboard
  useEffect(() => {
    if (!isLoading && user?.role === "shopkeeper") {
      setLocation("/seller/dashboard");
    }
  }, [user, isLoading, setLocation]);

  // Removed automatic image rotation to prevent confusion with slider movement

  const shoppingCategories = [
    { 
      name: "Electronics", 
      icon: "📱", 
      href: "/products?category=1",
      gradient: "from-blue-500 to-cyan-500",
      images: [
        "https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=300&h=200&fit=crop&auto=format"
      ]
    },
    { 
      name: "Fashion", 
      icon: "👕", 
      href: "/products?category=2",
      gradient: "from-pink-500 to-rose-500",
      images: [
        "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1445205170230-053b83016050?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1441984904996-e0b6ba687e04?w=300&h=200&fit=crop&auto=format"
      ]
    },
    { 
      name: "Home & Garden", 
      icon: "🏠", 
      href: "/products?category=3",
      gradient: "from-green-500 to-emerald-500",
      images: [
        "https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1584622650111-993a426fbf0a?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?w=300&h=200&fit=crop&auto=format"
      ]
    },
    { 
      name: "Books", 
      icon: "📚", 
      href: "/products?category=4",
      gradient: "from-amber-500 to-orange-500",
      images: [
        "https://images.unsplash.com/photo-1481627834876-b7833e8f5570?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1513475382585-d06e58bcb0e0?w=300&h=200&fit=crop&auto=format"
      ]
    },
    { 
      name: "Beauty", 
      icon: "💄", 
      href: "/products?category=5",
      gradient: "from-purple-500 to-pink-500",
      images: [
        "https://images.unsplash.com/photo-1596462502278-27bfdc403348?w=300&h=300&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1522335789203-aabd1fc54bc9?w=300&h=300&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1549298916-f52d724204b4?w=300&h=300&fit=crop&auto=format"
      ]
    },
    { 
      name: "Sports", 
      icon: "⚽", 
      href: "/products?category=6",
      gradient: "from-orange-500 to-red-500",
      images: [
        "https://images.unsplash.com/photo-1571019613454-1cb2f99b2d8b?w=300&h=300&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1544966503-7cc5ac882d5e?w=300&h=300&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1461896836934-ffe607ba8211?w=300&h=300&fit=crop&auto=format"
      ]
    },
    { 
      name: "Toys", 
      icon: "🧸", 
      href: "/products?category=7",
      gradient: "from-yellow-400 to-orange-400",
      images: [
        "https://images.unsplash.com/photo-1558060370-d644479cb6f7?w=300&h=300&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1587654780291-39c9404d746b?w=300&h=300&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1520887480574-5c2279f2c7e7?w=300&h=300&fit=crop&auto=format"
      ]
    },
    { 
      name: "Health", 
      icon: "🏥", 
      href: "/products?category=8",
      gradient: "from-teal-500 to-green-500",
      images: [
        "https://images.unsplash.com/photo-1559757175-0eb30cd8c063?w=300&h=300&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1505751172876-fa1923c5c528?w=300&h=300&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1576091160399-112ba8d25d1f?w=300&h=300&fit=crop&auto=format"
      ]
    },
    { 
      name: "Automotive", 
      icon: "🚗", 
      href: "/products?category=9",
      gradient: "from-gray-600 to-gray-800",
      images: [
        "https://images.unsplash.com/photo-1492144534655-ae79c964c9d7?w=300&h=300&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1603584173870-7f23fdae1b7a?w=300&h=300&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1517524206127-cd5d58c4f5d8?w=300&h=300&fit=crop&auto=format"
      ]
    },
    { 
      name: "Music", 
      icon: "🎵", 
      href: "/products?category=10",
      gradient: "from-indigo-500 to-purple-500",
      images: [
        "https://images.unsplash.com/photo-1493225457124-a3eb161ffa5f?w=300&h=300&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1470225620780-dba8ba36b745?w=300&h=300&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1514320291840-2e0a9bf2a9ae?w=300&h=300&fit=crop&auto=format"
      ]
    },
    { 
      name: "Baby & Kids", 
      icon: "👶", 
      href: "/products?category=11",
      gradient: "from-rose-400 to-pink-500",
      images: [
        "https://images.unsplash.com/photo-1522771739844-6a9f6d5f14af?w=300&h=200&fit=crop&auto=format"
      ]
    },
    { 
      name: "Kitchen", 
      icon: "🍳", 
      href: "/products?category=12",
      gradient: "from-red-500 to-orange-500",
      images: [
        "https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=200&fit=crop&auto=format"
      ]
    },
    { 
      name: "Gaming", 
      icon: "🎮", 
      href: "/products?category=13",
      gradient: "from-indigo-600 to-purple-600",
      images: [
        "https://images.unsplash.com/photo-1550745165-9bc0b252726f?w=300&h=200&fit=crop&auto=format"
      ]
    },
    { 
      name: "Furniture", 
      icon: "🛋️", 
      href: "/products?category=14",
      gradient: "from-amber-600 to-yellow-500",
      images: [
        "https://images.unsplash.com/photo-1586023492125-27b2c045efd7?w=300&h=200&fit=crop&auto=format"
      ]
    },
    { 
      name: "Tools", 
      icon: "🔧", 
      href: "/products?category=15",
      gradient: "from-gray-600 to-slate-700",
      images: [
        "https://images.unsplash.com/photo-1581833971358-2c8b550f87b3?w=300&h=200&fit=crop&auto=format"
      ]
    },
    { 
      name: "Jewelry", 
      icon: "💎", 
      href: "/products?category=16",
      gradient: "from-violet-500 to-purple-500",
      images: [
        "https://images.unsplash.com/photo-1515562141207-7a88fb7ce338?w=300&h=200&fit=crop&auto=format"
      ]
    },
    { 
      name: "Pet Supplies", 
      icon: "🐾", 
      href: "/products?category=17",
      gradient: "from-emerald-500 to-teal-500",
      images: [
        "https://images.unsplash.com/photo-1601758228041-f3b2795255f1?w=300&h=200&fit=crop&auto=format"
      ]
    },
    { 
      name: "Office", 
      icon: "💼", 
      href: "/products?category=18",
      gradient: "from-slate-500 to-gray-600",
      images: [
        "https://images.unsplash.com/photo-1497032628192-86f99bcd76bc?w=300&h=200&fit=crop&auto=format"
      ]
    },
  ];

  const foodCategories = [
    {
      name: "Indian Cuisine",
      icon: "🍛",
      href: "/products?category=food&cuisine=indian",
      gradient: "from-red-600 to-orange-600",
      images: [
        "https://images.unsplash.com/photo-1585937421612-70a008356fbe?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1567188040759-fb8a883dc6d8?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1574653853027-5d6f2d96c22d?w=300&h=200&fit=crop&auto=format"
      ]
    },
    {
      name: "Fast Food",
      icon: "🍔",
      href: "/products?category=food&cuisine=fast-food",
      gradient: "from-yellow-500 to-red-500",
      images: [
        "https://images.unsplash.com/photo-1571091718767-18b5b1457add?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1550547660-d9450f859349?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1565299624946-b28f40a0ca4b?w=300&h=200&fit=crop&auto=format"
      ]
    },
    { 
      name: "Pizza", 
      icon: "🍕", 
      href: "/products?category=food&type=pizza",
      gradient: "from-red-500 to-yellow-500",
      images: [
        "https://images.unsplash.com/photo-1565299624946-b28f40a0ca4b?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1574071318508-1cdbab80d002?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1590534450747-36e3ae8a9daf?w=300&h=200&fit=crop&auto=format"
      ]
    },
    {
      name: "Desserts",
      icon: "🍰",
      href: "/products?category=food&cuisine=desserts",
      gradient: "from-pink-500 to-purple-500",
      images: [
        "https://images.unsplash.com/photo-1551024506-0bccd828d307?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1563729784474-d77dbb933a9e?w=300&h=200&fit=crop&auto=format",
        "https://images.unsplash.com/photo-1578985545062-69928b1d9587?w=300&h=200&fit=crop&auto=format"
      ]
    },
    {
      name: "Chinese",
      icon: "🥢",
      href: "/products?category=food&cuisine=chinese",
      gradient: "from-red-700 to-yellow-600"
    },
    {
      name: "Italian",
      icon: "🍝",
      href: "/products?category=food&cuisine=italian",
      gradient: "from-green-600 to-red-600"
    },
    {
      name: "Mexican",
      icon: "🌮",
      href: "/products?category=food&cuisine=mexican",
      gradient: "from-green-500 to-red-500"
    },
    {
      name: "Beverages",
      icon: "🥤",
      href: "/products?category=food&type=beverages",
      gradient: "from-blue-500 to-cyan-400"
    },
    {
      name: "Biryani",
      icon: "🍚",
      href: "/products?category=food&type=biryani",
      gradient: "from-orange-600 to-yellow-500"
    },
    {
      name: "Healthy",
      icon: "🥗",
      href: "/products?category=food&type=healthy",
      gradient: "from-green-400 to-lime-500"
    },
    {
      name: "Seafood",
      icon: "🦐",
      href: "/products?category=food&type=seafood",
      gradient: "from-cyan-500 to-blue-500"
    },
    {
      name: "BBQ & Grill",
      icon: "🍖",
      href: "/products?category=food&type=bbq",
      gradient: "from-red-600 to-orange-600"
    },
    {
      name: "Sweets",
      icon: "🍭",
      href: "/products?category=food&type=sweets",
      gradient: "from-pink-400 to-purple-400"
    },
    {
      name: "Coffee",
      icon: "☕",
      href: "/products?category=food&type=coffee",
      gradient: "from-amber-700 to-yellow-600"
    },
    {
      name: "Ice Cream",
      icon: "🍦",
      href: "/products?category=food&type=ice-cream",
      gradient: "from-blue-300 to-cyan-300"
    },
    {
      name: "Bakery",
      icon: "🥖",
      href: "/products?category=food&type=bakery",
      gradient: "from-yellow-600 to-orange-500"
    },
    {
      name: "Sandwiches",
      icon: "🥪",
      href: "/products?category=food&type=sandwiches",
      gradient: "from-green-500 to-yellow-500"
    },
    {
      name: "Noodles",
      icon: "🍜",
      href: "/products?category=food&type=noodles",
      gradient: "from-red-500 to-orange-500"
    },
  ];

  const categories = mode === "shopping" ? shoppingCategories : foodCategories;

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
    queryKey: [`/api/recommendations/homepage`, mode, user?.id],
    queryFn: async () => {
      const params = new URLSearchParams({
        mode: mode,
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
    retry: 1,
    staleTime: 15 * 60 * 1000, // 15 minutes
    refetchOnWindowFocus: false,
    refetchOnMount: false
  });

  // Fallback to regular API calls if recommendations fail
  const {
    data: products,
    isLoading: productsLoading,
    error: productsError,
    refetch: refetchProducts,
  } = useQuery<Product[]>({
    queryKey: ["/api/products"],
    retry: 1,
    staleTime: 15 * 60 * 1000, // 15 minutes
    refetchOnWindowFocus: false,
    refetchOnMount: false,
    enabled: !recommendations?.products?.length, // Only fetch if no recommendations
  });

  const {
    data: stores,
    isLoading: storesLoading,
    error: storesError,
    refetch: refetchStores,
  } = useQuery<Store[]>({
    queryKey: ["/api/stores"],
    retry: 1,
    staleTime: 5 * 60 * 1000, // 5 minutes
    refetchOnWindowFocus: false,
    refetchOnMount: false,
    enabled: !recommendations?.stores?.length, // Only fetch if no recommendations
  });

  // Fetch active flash sales
  const { data: activeFlashSales } = useQuery<any[]>({
    queryKey: ["/api/flash-sales/active"],
    staleTime: 2 * 60 * 1000, // 2 minutes
  });

  // Slider data
  const slides = [
    {
      id: 1,
      title: "From Click to Doorstep — In Just One Hour",
      description: "Shop fast. Get it faster.",
      buttonText: "Shop Now",
      url: "/products",
      image: slider1,
      overlay: "rgba(0, 0, 0, 0.4)",
    },
    {
      id: 2,
      title: "Hot & Fresh – Tasty Food at Your Doorstep",
      description: "Delicious meals delivered fast",
      buttonText: "Order Now",
      url: "/restaurants",
      image: slider2,
      overlay: "rgba(0, 0, 0, 0.4)",
    },
    {
      id: 3,
      title: "Flash Sale! Limited Time Offer",
      description: "Hurry! These deals end in",
      buttonText: "Shop Now",
      url: "/flash-sales",
      image: slider3,
      overlay: "rgba(0, 0, 0, 0.5)",
      showTimer: true,
    },
  ];

  // Enhanced error logging with more context
  if (productsError) {
    console.error("Products loading failed:", {
      error: productsError,
      message:
        productsError instanceof Error
          ? productsError.message
          : "Unknown error",
      timestamp: new Date().toISOString(),
    });
  }
  if (storesError) {
    console.error("Stores loading failed:", {
      error: storesError,
      message:
        storesError instanceof Error ? storesError.message : "Unknown error",
      timestamp: new Date().toISOString(),
    });
  }
  if (products) console.log("Products loaded:", products.length);
  if (stores) console.log("Stores loaded:", stores.length);

  // Use recommendations if available, otherwise fallback to regular products
  const recommendedProducts = recommendations?.products || [];
  const recommendedStores = recommendations?.stores || [];
  const isPersonalized = recommendations?.isPersonalized || false;

  const featuredProducts = recommendedProducts.length > 0 
    ? recommendedProducts.slice(0, 20)
    : products
        ?.filter((product) =>
          mode === "shopping"
            ? product.productType !== "food"
            : product.productType === "food",
        )
        .slice(0, 20) || [];

  const popularStores = recommendedStores.length > 0
    ? recommendedStores.slice(0, 10)
    : stores
        ?.filter((store) =>
          mode === "shopping"
            ? store.storeType !== "restaurant"
            : store.storeType === "restaurant",
        )
        .slice(0, 10) || [];

  // Determine loading states
  const isProductsLoading = recommendationsLoading || (productsLoading && !recommendedProducts.length);
  const isStoresLoading = recommendationsLoading || (storesLoading && !recommendedStores.length);
  const productsHaveError = recommendationsError && productsError;
  const storesHaveError = recommendationsError && storesError;

  // Error handling component for products
  const ProductsErrorState = () => (
    <div className="text-center py-12">
      <Alert className="max-w-md mx-auto">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          Failed to load products. Please try again.
        </AlertDescription>
      </Alert>
      <Button
        onClick={() => refetchProducts()}
        variant="outline"
        className="mt-4"
        disabled={productsLoading}
      >
        <RefreshCw
          className={`mr-2 h-4 w-4 ${productsLoading ? "animate-spin" : ""}`}
        />
        Retry
      </Button>
    </div>
  );

  // Loading state component for products
  const ProductsLoadingState = () => (
    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3 sm:gap-4">
      {Array.from({ length: 6 }).map((_, index) => (
        <Card key={index} className="animate-pulse">
          <CardContent className="p-4">
            <div className="bg-gray-200 h-32 rounded-md mb-3"></div>
            <div className="bg-gray-200 h-4 rounded mb-2"></div>
            <div className="bg-gray-200 h-3 rounded w-3/4"></div>
          </CardContent>
        </Card>
      ))}
    </div>
  );

  // Error handling component for stores
  const StoresErrorState = () => (
    <div className="text-center py-12">
      <Alert className="max-w-md mx-auto">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>
          Failed to load stores. Please try again.
        </AlertDescription>
      </Alert>
      <Button
        onClick={() => refetchStores()}
        variant="outline"
        className="mt-4"
        disabled={storesLoading}
      >
        <RefreshCw
          className={`mr-2 h-4 w-4 ${storesLoading ? "animate-spin" : ""}`}
        />
        Retry
      </Button>
    </div>
  );

  // Loading state component for stores
  const StoresLoadingState = () => (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6 lg:gap-8">
      {Array.from({ length: 4 }).map((_, index) => (
        <Card key={index} className="animate-pulse">
          <CardContent className="p-6">
            <div className="bg-gray-200 h-24 rounded-md mb-4"></div>
            <div className="bg-gray-200 h-5 rounded mb-2"></div>
            <div className="bg-gray-200 h-4 rounded w-2/3 mb-2"></div>
            <div className="bg-gray-200 h-3 rounded w-1/2"></div>
          </CardContent>
        </Card>
      ))}
    </div>
  );

  return (
    <div className="min-h-screen">
      {/* Hero Slider Section */}
      <section className="relative w-full h-[50vh] min-h-[300px]">
        <Swiper
          modules={[Navigation, Pagination, Autoplay]}
          spaceBetween={0}
          slidesPerView={1}
          navigation
          pagination={{
            clickable: true,
            el: ".swiper-pagination",
            type: "bullets",
          }}
          autoplay={{
            delay: 4000,
            disableOnInteraction: false,
          }}
          className="h-full w-full m-0 p-0"
          style={{
            "--swiper-navigation-color": "#ffffff",
            "--swiper-pagination-color": "#ffffff",
            "--swiper-pagination-bullet-inactive-color":
              "rgba(255, 255, 255, 0.5)",
            "--swiper-pagination-bullet-inactive-opacity": "1",
            "--swiper-pagination-bullet-size": "10px",
            "--swiper-pagination-bullet-horizontal-gap": "6px",
          } as React.CSSProperties}
        >
          {slides.map((slide) => (
            <SwiperSlide key={slide.id}>
              <div
                className="relative w-full h-full flex items-center justify-center p-0 m-0"
                style={{
                  background: `url(${slide.image}) center/cover no-repeat`,
                  position: "relative",
                  height: "100%",
                  width: "100%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                {/* Dark overlay */}
                <div className="absolute inset-0 bg-black/40"></div>

                {/* Content */}
                <div className="relative z-10 max-w-4xl px-4 sm:px-6 lg:px-8 text-center text-white">
                  <h1 className="text-3xl sm:text-4xl md:text-5xl font-bold mb-4 leading-tight drop-shadow-lg">
                    {slide.title}
                  </h1>
                  <p className="text-lg sm:text-xl mb-6 opacity-90 max-w-2xl mx-auto drop-shadow">
                    {slide.description}
                  </p>
                  {slide.showTimer && <CountdownTimer />}
                  <Link href={slide.url} className="mt-6 inline-block">
                    <Button
                      size="lg"
                      className="bg-white text-gray-900 hover:bg-gray-100 text-base sm:text-lg px-8 py-6 rounded-full font-semibold shadow-lg hover:shadow-xl transition-all duration-200 transform hover:-translate-y-0.5"
                    >
                      {slide.buttonText}
                      <ArrowRight className="ml-2 h-5 w-5" />
                    </Button>
                  </Link>
                </div>
              </div>
            </SwiperSlide>
          ))}

          {/* Custom pagination */}
          <div className="swiper-pagination !bottom-6"></div>

          {/* Navigation buttons */}
          <div className="swiper-button-next after:hidden">
            <div className="h-12 w-12 rounded-full bg-white/20 backdrop-blur-sm flex items-center justify-center">
              <svg
                className="w-6 h-6 text-white"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 5l7 7-7 7"
                />
              </svg>
            </div>
          </div>
          <div className="swiper-button-prev after:hidden">
            <div className="h-12 w-12 rounded-full bg-white/20 backdrop-blur-sm flex items-center justify-center">
              <svg
                className="w-6 h-6 text-white"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M15 19l-7-7 7-7"
                />
              </svg>
            </div>
          </div>
        </Swiper>
      </section>

      {/* Categories/Menu Section */}
      <section className="py-1 bg-background relative" style={{ minHeight: '11.5vh', maxHeight: '11.5vh' }}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-full">
          <div className="mb-1 sm:mb-2">
            <h2 className="text-lg sm:text-xl lg:text-2xl font-bold text-foreground">
              {mode === "shopping" ? "Categories" : "Menu"}
            </h2>
          </div>
          
          {/* Mobile Horizontal Slider - Noon-style */}
          <div className="block sm:hidden categories-section mb-0 pb-0" style={{ marginBottom: 0, paddingBottom: 0 }}>
            <Swiper
              modules={[FreeMode, Pagination]}
              spaceBetween={15}
              slidesPerView={5}
              freeMode={{
                enabled: true,
                sticky: true,
                momentumBounce: false,
                momentumRatio: 0.8,
                momentumVelocityRatio: 0.8,
              }}
              grabCursor={true}
              touchRatio={1}
              touchAngle={45}
              threshold={5}
              longSwipesRatio={0.5}
              longSwipesMs={300}
              shortSwipes={true}
              followFinger={true}
              autoplay={false}
              loop={false}
              effect="slide"
              resistance={true}
              resistanceRatio={0.85}
              preventInteractionOnTransition={false}
              allowTouchMove={true}
              simulateTouch={true}
              touchStartPreventDefault={true}
              touchStartForcePreventDefault={false}
              touchMoveStopPropagation={true}
              pagination={{
                clickable: true,
                el: '.mobile-categories-pagination',
                type: 'bullets',
                dynamicBullets: true,
                dynamicMainBullets: 3,
                renderBullet: function (index, className) {
                  return '<span class="' + className + ' mobile-category-bullet" data-index="' + index + '"></span>';
                },
              }}
              className="mobile-categories-swiper !overflow-visible !pb-2"
              style={{
                paddingLeft: '16px',
                paddingRight: '16px',
                overflow: 'visible',
                touchAction: 'pan-x',
                userSelect: 'none',
                WebkitUserSelect: 'none',
                WebkitTouchCallout: 'none'
              }}
              breakpoints={{
                280: {
                  slidesPerView: 4,
                  spaceBetween: 12,
                },
                320: {
                  slidesPerView: 4.5,
                  spaceBetween: 12,
                },
                360: {
                  slidesPerView: 5,
                  spaceBetween: 15,
                },
                375: {
                  slidesPerView: 5,
                  spaceBetween: 15,
                },
                414: {
                  slidesPerView: 5.5,
                  spaceBetween: 15,
                },
                480: {
                  slidesPerView: 6,
                  spaceBetween: 18,
                },
              }}
            >
              {categories.map((category, index) => (
                <SwiperSlide key={category.name} className="!w-auto">
                  <Link href={category.href}>
                    <div className="mobile-category-item">
                      {/* Round Category Image */}
                      <div className="mobile-category-icon">
                        {category.images && category.images[0] ? (
                          <img
                            src={category.images[0]}
                            alt={category.name}
                            className="w-full h-full object-cover"
                            loading="lazy"
                          />
                        ) : (
                          <>
                            <div className={`absolute inset-0 rounded-full bg-gradient-to-br ${category.gradient} opacity-90`} />
                            <div className="absolute inset-0 rounded-full flex items-center justify-center">
                              <span className="text-lg">
                                {category.icon}
                              </span>
                            </div>
                          </>
                        )}
                      </div>
                      {/* Category Name */}
                      <span className="mobile-category-name">
                        {category.name}
                      </span>
                    </div>
                  </Link>
                </SwiperSlide>
              ))}
              
              {/* View All Button - Last slide */}
              <SwiperSlide className="!w-auto">
                <Link href={mode === "shopping" ? "/categories" : "/food-categories"}>
                  <div className="mobile-category-item mobile-view-all-category">
                    <div className="mobile-category-icon mobile-view-all-icon">
                      <div className="absolute inset-0 rounded-full flex items-center justify-center">
                        <svg 
                          className="w-5 h-5 text-primary" 
                          fill="none" 
                          stroke="currentColor" 
                          viewBox="0 0 24 24"
                        >
                          <path 
                            strokeLinecap="round" 
                            strokeLinejoin="round" 
                            strokeWidth={2} 
                            d="M4 6h16M4 12h16M4 18h16" 
                          />
                        </svg>
                      </div>
                    </div>
                    <span className="mobile-category-name mobile-view-all-name">
                      View All
                    </span>
                  </div>
                </Link>
              </SwiperSlide>
            </Swiper>
            
            {/* Pagination Dots - Noon Style */}
            <div className="mobile-categories-pagination" style={{
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              marginTop: '12px',
              marginBottom: '16px',
              minHeight: '20px',
              padding: '8px 0'
            }}>
              {/* Fallback dots if Swiper pagination doesn't render */}
              {Array.from({ length: Math.ceil(categories.length / 5) }).map((_, index) => (
                <span 
                  key={index}
                  className="fallback-pagination-dot"
                  style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    backgroundColor: index === 0 ? '#000000' : 'rgba(0,0,0,0.3)',
                    margin: '0 4px',
                    display: 'inline-block',
                    transition: 'all 0.3s ease'
                  }}
                />
              ))}
            </div>
          </div>

          {/* Desktop Row Layout - Fixed width categories in proper grid */}
          <div className="hidden sm:block overflow-x-auto">
            <div className="flex gap-4 lg:gap-6 min-w-fit px-2">
              {categories.map((category, index) => (
                <Link key={category.name} href={category.href}>
                  <div className="group flex flex-col items-center p-2 lg:p-3 rounded-xl hover:bg-secondary/50 transition-colors flex-shrink-0">
                    {/* Round Category Image */}
                    <div className="relative w-16 h-16 lg:w-20 lg:h-20 mb-2 overflow-hidden rounded-full shadow-lg">
                      {category.images && category.images[0] ? (
                        <img
                          src={category.images[0]}
                          alt={category.name}
                          className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-300"
                          loading="lazy"
                        />
                      ) : (
                        <>
                          <div className={`absolute inset-0 rounded-full bg-gradient-to-br ${category.gradient} opacity-90 group-hover:opacity-100 transition-opacity`} />
                          <div className="absolute inset-0 rounded-full flex items-center justify-center">
                            <span className="text-2xl lg:text-3xl drop-shadow-sm group-hover:scale-110 transition-transform">
                              {category.icon}
                            </span>
                          </div>
                        </>
                      )}
                    </div>
                    {/* Category Name */}
                    <span className="text-xs lg:text-sm font-medium text-foreground text-center leading-tight group-hover:text-primary transition-colors w-20 lg:w-24">
                      {category.name}
                    </span>
                  </div>
                </Link>
              ))}
              
              {/* View All Button */}
              <Link href={mode === "shopping" ? "/categories" : "/food-categories"}>
                <div className="group flex flex-col items-center p-2 lg:p-3 rounded-xl hover:bg-secondary/50 transition-colors flex-shrink-0">
                  <div className="relative w-16 h-16 lg:w-20 lg:h-20 mb-2 overflow-hidden rounded-full shadow-lg bg-gradient-to-br from-gray-100 to-gray-200 dark:from-gray-700 dark:to-gray-800">
                    <div className="absolute inset-0 rounded-full flex items-center justify-center">
                      <svg 
                        className="w-6 h-6 lg:w-8 lg:h-8 text-primary group-hover:scale-110 transition-transform" 
                        fill="none" 
                        stroke="currentColor" 
                        viewBox="0 0 24 24"
                      >
                        <path 
                          strokeLinecap="round" 
                          strokeLinejoin="round" 
                          strokeWidth={2} 
                          d="M4 6h16M4 12h16M4 18h16" 
                        />
                      </svg>
                    </div>
                  </div>
                  <span className="text-xs lg:text-sm font-medium text-foreground text-center leading-tight group-hover:text-primary transition-colors w-20 lg:w-24">
                    View All
                  </span>
                </div>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Featured Products */}
      <section className="py-8 sm:py-12 lg:py-16 bg-secondary/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-start mb-6 sm:mb-10 pr-2.5">
            <div className="flex items-center gap-2 flex-1">
              <h2 className="text-lg sm:text-xl md:text-2xl lg:text-3xl font-bold text-foreground">
                {isPersonalized ? "Recommended for You" : "Featured Products"}
              </h2>
              {isPersonalized && (
                <Badge variant="secondary" className="bg-blue-100 text-blue-800">
                  <TrendingUp className="h-3 w-3 mr-1" />
                  Smart Pick
                </Badge>
              )}
            </div>
            <Link href="/products" className="flex-shrink-0 mt-1">
              <Button
                variant="outline"
                className="border-primary text-primary hover:bg-primary hover:text-white w-8 h-8 p-0"
              >
                <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
          </div>
          {productsHaveError ? (
            <ProductsErrorState />
          ) : isProductsLoading ? (
            <ProductsLoadingState />
          ) : featuredProducts.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-muted-foreground text-lg">
                No featured products available at the moment
              </p>
              <p className="text-muted-foreground text-sm mt-2">
                Check back later for new arrivals
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3 sm:gap-4">
              {featuredProducts.map((product: any) => (
                <ProductCard key={product.id} product={product} />
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Popular Stores */}
      <section className="py-8 sm:py-12 lg:py-16 bg-background">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-start mb-6 sm:mb-10 pr-2.5">
            <div className="flex items-center gap-2 flex-1">
              <h2 className="text-lg sm:text-xl md:text-2xl lg:text-3xl font-bold text-foreground">
                {isPersonalized ? "Stores You Might Like" : `Popular ${mode === "shopping" ? "Stores" : "Restaurants"}`}
              </h2>
              {isPersonalized && (
                <Badge variant="secondary" className="bg-green-100 text-green-800">
                  <Sparkles className="h-3 w-3 mr-1" />
                  Curated
                </Badge>
              )}
            </div>
            <Link href={mode === "shopping" ? "/stores" : "/restaurants"} className="flex-shrink-0 mt-1">
              <Button
                variant="outline"
                className="border-primary text-primary hover:bg-primary hover:text-white w-8 h-8 p-0"
              >
                <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
          </div>
          {storesHaveError ? (
            <StoresErrorState />
          ) : isStoresLoading ? (
            <StoresLoadingState />
          ) : popularStores.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-muted-foreground text-lg">
                No stores available at the moment
              </p>
              <p className="text-muted-foreground text-sm mt-2">
                Check back later for new stores
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 sm:gap-4 md:gap-6">
              {popularStores.map((store: any) => (
                <StoreCard key={store.id} store={store} />
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Flash Deals Banner */}
      {activeFlashSales && activeFlashSales.length > 0 && (
        <section className="py-8 bg-accent">
          <div className="max-w-7xl mx-auto px-4 text-center">
            <div className="text-white">
              <h2 className="text-2xl font-bold mb-2">
                ⚡ Flash Sale - {activeFlashSales[0].discountPercentage}% Off!
              </h2>
              <p className="text-lg mb-2">
                {activeFlashSales[0].title}
              </p>
              {activeFlashSales[0].description && (
                <p className="text-base mb-4 opacity-90">
                  {activeFlashSales[0].description}
                </p>
              )}
              <p className="text-sm mb-4 opacity-75">
                Ends: {new Date(activeFlashSales[0].endsAt).toLocaleString()}
              </p>
              <Link href="/flash-sales">
                <Button
                  variant="outline"
                  className="bg-white text-accent hover:bg-gray-100"
                >
                  View Flash Sales
                </Button>
              </Link>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
