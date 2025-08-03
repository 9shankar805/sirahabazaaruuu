import { useEffect } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import type { Store } from "@shared/schema";

export default function DashboardRouter() {
  const { user } = useAuth();
  const [, setLocation] = useLocation();

  // Fetch user's store to determine dashboard type
  const { data: stores = [] } = useQuery<Store[]>({
    queryKey: [`/api/stores/user/${user?.id}`],
    enabled: !!user?.id && user?.role === 'shopkeeper',
  });

  useEffect(() => {
    if (!user || user.role !== 'shopkeeper') return;
    
    // If user has stores, check the type
    if (stores.length > 0) {
      const userStore = stores[0]; // Get first store
      
      // Check if store is restaurant by storeType or name detection
      const isRestaurant = userStore.storeType === 'restaurant' || 
                          isRestaurantByName(userStore.name);
      
      if (isRestaurant) {
        // Redirect to restaurant dashboard
        setLocation('/restaurant/dashboard');
      } else {
        // Stay on seller dashboard for retail stores
        setLocation('/seller/dashboard');
      }
    }
  }, [user, stores, setLocation]);

  return null; // This component doesn't render anything
}

// Helper function to detect restaurant by name
function isRestaurantByName(storeName: string): boolean {
  const restaurantKeywords = [
    'restaurant', 'cafe', 'food', 'kitchen', 'dining', 'eatery', 'bistro',
    'pizzeria', 'burger', 'pizza', 'chicken', 'biryani', 'dosa', 'samosa',
    'chinese', 'indian', 'nepali', 'thai', 'continental', 'fast food',
    'dhaba', 'hotel', 'canteen', 'mess', 'tiffin', 'sweet', 'bakery',
    'tyres' // Your specific restaurant name
  ];
  
  const lowerName = storeName.toLowerCase();
  return restaurantKeywords.some(keyword => lowerName.includes(keyword));
}