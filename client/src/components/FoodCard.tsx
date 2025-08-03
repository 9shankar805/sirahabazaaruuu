import { Heart, Plus, Clock, Leaf } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useCart } from "@/hooks/useCart";
import { useWishlist } from "@/hooks/useWishlist";
import { useAuth } from "@/hooks/useAuth";
import { Link } from "wouter";
import { useAppSounds } from "@/hooks/useSoundEffects";
import type { Product } from "@shared/schema";

interface FoodCardProps {
  food: Product;
}

export default function FoodCard({ food }: FoodCardProps) {
  const { addToCart } = useCart();
  const { addToWishlist, removeFromWishlist, isInWishlist } = useWishlist();
  const { user } = useAuth();
  const appSounds = useAppSounds();
  
  const inWishlist = user ? isInWishlist(food.id) : false;
  const discountedPrice = (food.isOnOffer && food.offerPercentage)
    ? (parseFloat(food.price) * (1 - food.offerPercentage / 100)).toFixed(2)
    : food.price;

  const handleAddToCart = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (user) {
      addToCart(food.id, 1);
      appSounds.onCartAdd();
    }
  };

  const handleWishlistToggle = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (user) {
      if (inWishlist) {
        removeFromWishlist(food.id);
        appSounds.onCartRemove();
      } else {
        addToWishlist(food.id);
        appSounds.onProductLike();
      }
    }
  };

  return (
    <Link href={`/food/${food.id}`}>
      <Card className="overflow-hidden hover:shadow-lg transition-all duration-300 cursor-pointer group">
        <div className="relative h-48">
          <img
            src={food.imageUrl || (food.images && food.images[0]) || "https://images.unsplash.com/photo-1565299624946-b28f40a0ca4b?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&h=300"}
            alt={food.name}
            className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
            onError={(e) => {
              e.currentTarget.src = "https://images.unsplash.com/photo-1565299624946-b28f40a0ca4b?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&h=300";
            }}
          />
          
          {food.isOnOffer && food.offerPercentage && (
            <Badge className="absolute top-2 left-2 bg-red-500 hover:bg-red-600">
              {food.offerPercentage}% OFF
            </Badge>
          )}
          
          <div className="absolute top-2 right-2 flex space-x-1">
            {food.isVegetarian && (
              <Badge className="bg-green-500 hover:bg-green-600">
                <Leaf className="h-3 w-3" />
              </Badge>
            )}
            {food.isVegan && (
              <Badge className="bg-green-600 hover:bg-green-700">
                Vegan
              </Badge>
            )}
          </div>

          {user && (
            <Button
              variant="ghost"
              size="sm"
              className="absolute bottom-2 right-2 bg-white/90 hover:bg-white"
              onClick={handleWishlistToggle}
            >
              <Heart 
                className={`h-4 w-4 ${inWishlist ? 'text-red-500 fill-current' : 'text-gray-600'}`} 
              />
            </Button>
          )}
        </div>
        
        <CardContent className="p-3 sm:p-4">
          <div className="flex items-start justify-between mb-2">
            <h3 className="font-semibold text-sm sm:text-base md:text-lg group-hover:text-red-600 transition-colors line-clamp-1">
              {food.name}
            </h3>
            <div className="flex flex-col items-end">
              <span className="font-bold text-sm sm:text-base md:text-lg text-red-600">
                ₹{discountedPrice}
              </span>
              {food.isOnOffer && food.offerPercentage && (
                <span className="text-xs sm:text-sm text-gray-500 line-through">
                  ₹{food.price}
                </span>
              )}
            </div>
          </div>
          
          <p className="text-gray-600 dark:text-gray-400 text-xs sm:text-sm mb-2 sm:mb-3 line-clamp-2">
            {food.description}
          </p>
          
          <div className="flex items-center justify-between mb-2 sm:mb-3">
            {food.preparationTime && (
              <div className="flex items-center space-x-1 text-xs sm:text-sm text-gray-600">
                <Clock className="h-3 w-3 sm:h-4 sm:w-4" />
                <span>{food.preparationTime}</span>
              </div>
            )}
            
            {food.spiceLevel && (
              <Badge variant="outline" className="text-xs">
                🌶️ {food.spiceLevel}
              </Badge>
            )}
          </div>
          
          {food.rating && parseFloat(food.rating) > 0 && (
            <div className="flex items-center space-x-1 mb-2 sm:mb-3">
              <div className="flex">
                {[...Array(5)].map((_, i) => (
                  <span
                    key={i}
                    className={`text-xs sm:text-sm ${
                      i < Math.floor(parseFloat(food.rating ?? "0"))
                        ? 'text-yellow-400'
                        : 'text-gray-300'
                    }`}
                  >
                    ★
                  </span>
                ))}
              </div>
              <span className="text-xs sm:text-sm text-gray-600">
                ({food.totalReviews} reviews)
              </span>
            </div>
          )}
          
          {user && (
            <Button 
              onClick={handleAddToCart}
              className="w-full bg-red-500 hover:bg-red-600 text-white"
              size="sm"
            >
              <Plus className="h-4 w-4 mr-1" />
              Add to Cart
            </Button>
          )}
        </CardContent>
      </Card>
    </Link>
  );
}