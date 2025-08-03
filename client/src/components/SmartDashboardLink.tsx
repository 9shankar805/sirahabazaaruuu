import { useQuery } from "@tanstack/react-query";
import { Link } from "wouter";
import { useAuth } from "@/hooks/useAuth";
import { Home, ChefHat } from "lucide-react";
import type { Store } from "@shared/schema";

export default function SmartDashboardLink() {
  const { user } = useAuth();

  // Fetch user's store to determine dashboard type
  const { data: stores = [] } = useQuery<Store[]>({
    queryKey: [`/api/stores/user/${user?.id}`],
    enabled: !!user?.id && user?.role === 'shopkeeper',
  });

  // Determine if user has a restaurant
  const hasRestaurant = stores.some(store => 
    store.storeType === 'restaurant' || isRestaurantByName(store.name)
  );

  if (hasRestaurant) {
    return (
      <Link href="/restaurant/dashboard" className="flex items-center space-x-1 hover:text-accent transition-colors">
        <ChefHat className="h-4 w-4" />
        <span>Restaurant Dashboard</span>
      </Link>
    );
  }

  return (
    <Link href="/seller/dashboard" className="flex items-center space-x-1 hover:text-accent transition-colors">
      <Home className="h-4 w-4" />
      <span>Dashboard</span>
    </Link>
  );
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