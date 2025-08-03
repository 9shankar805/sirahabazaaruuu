import { useState, useEffect } from "react";
import { Link } from "wouter";
import { Star, Clock, MapPin, Bike } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { calculateDistance, formatDistance, getCurrentUserLocation } from "@/lib/distance";
import type { Store } from "@shared/schema";

interface RestaurantCardProps {
  restaurant: Store;
  showDistance?: boolean;
}

export default function RestaurantCard({ restaurant, showDistance = true }: RestaurantCardProps) {
  const [distance, setDistance] = useState<number | null>(null);
  const [isCalculatingDistance, setIsCalculatingDistance] = useState(false);
  
  const deliveryFee = restaurant.deliveryFee ? `₹${restaurant.deliveryFee}` : "Free";
  const minimumOrder = restaurant.minimumOrder ? `₹${restaurant.minimumOrder}` : "";

  useEffect(() => {
    if (showDistance && restaurant.latitude && restaurant.longitude) {
      setIsCalculatingDistance(true);
      getCurrentUserLocation()
        .then((location) => {
          const dist = calculateDistance(
            location,
            { latitude: parseFloat(restaurant.latitude!), longitude: parseFloat(restaurant.longitude!) }
          );
          setDistance(dist);
          setIsCalculatingDistance(false);
        })
        .catch(() => {
          setIsCalculatingDistance(false);
        });
    }
  }, [restaurant.latitude, restaurant.longitude, showDistance]);

  return (
    <Link href={`/restaurant/${restaurant.id}`}>
      <Card className="overflow-hidden hover:shadow-lg transition-all duration-300 cursor-pointer group">
        <div className="relative h-48">
          <img
            src={restaurant.coverImage || "https://images.unsplash.com/photo-1517248135467-4c7edcad34c4?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&h=300"}
            alt={restaurant.name}
            className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
            onError={(e) => {
              e.currentTarget.src = "https://images.unsplash.com/photo-1517248135467-4c7edcad34c4?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&h=300";
            }}
          />
          {restaurant.featured && (
            <Badge className="absolute top-2 left-2 bg-red-500 hover:bg-red-600">
              Featured
            </Badge>
          )}
          {restaurant.isDeliveryAvailable && (
            <Badge className="absolute top-2 right-2 bg-green-500 hover:bg-green-600">
              <Bike className="h-3 w-3 mr-1" />
              Delivery
            </Badge>
          )}
        </div>

        <CardContent className="p-3 sm:p-4">
          <div className="flex items-start justify-between mb-2">
            <h3 className="font-semibold text-sm sm:text-base md:text-lg group-hover:text-red-600 transition-colors line-clamp-1">
              {restaurant.name}
            </h3>
            <div className="flex items-center space-x-1 flex-shrink-0">
              <Star className="h-3 w-3 sm:h-4 sm:w-4 text-yellow-400 fill-current" />
              <span className="text-xs sm:text-sm font-medium">{restaurant.rating}</span>
            </div>
          </div>

          <p className="text-gray-600 dark:text-gray-400 text-xs sm:text-sm mb-2 sm:mb-3 line-clamp-2">
            {restaurant.description || `Delicious ${restaurant.cuisineType || 'multi-cuisine'} food delivered to your doorstep`}
          </p>

          {restaurant.cuisineType && (
            <Badge variant="outline" className="mb-3">
              {restaurant.cuisineType}
            </Badge>
          )}

          <div className="flex items-center justify-between text-xs sm:text-sm text-gray-600 dark:text-gray-400 mb-2">
            <div className="flex items-center space-x-1">
              <Clock className="h-3 w-3 sm:h-4 sm:w-4" />
              <span>{restaurant.deliveryTime || "25-35 mins"}</span>
            </div>
            <div className="flex items-center space-x-1">
              <Bike className="h-3 w-3 sm:h-4 sm:w-4" />
              <span>{deliveryFee}</span>
            </div>
          </div>

          {/* Distance and Address Row */}
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center space-x-1 text-xs text-gray-500 flex-1 min-w-0">
              <MapPin className="h-3 w-3 flex-shrink-0" />
              <span className="truncate">{restaurant.address}</span>
            </div>
            
            {/* Distance Badge */}
            {showDistance && (
              <div className="flex-shrink-0">
                {isCalculatingDistance ? (
                  <Badge variant="outline" className="text-xs animate-pulse">
                    <MapPin className="h-3 w-3 mr-1" />
                    ...
                  </Badge>
                ) : distance !== null ? (
                  <Badge 
                    variant={distance <= 1 ? "default" : distance <= 5 ? "secondary" : "outline"} 
                    className="text-xs font-medium bg-blue-50 text-blue-700 border-blue-200"
                  >
                    {formatDistance(distance)}
                  </Badge>
                ) : null}
              </div>
            )}
          </div>

          {minimumOrder && (
            <div className="mt-2 text-xs text-gray-500">
              Min order: {minimumOrder}
            </div>
          )}
        </CardContent>
      </Card>
    </Link>
  );
}