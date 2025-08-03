import { useState, useRef, useEffect } from "react";
import { Link } from "wouter";
import { Star, ShoppingCart, Heart, MapPin, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useCart } from "@/hooks/useCart";
import { useWishlist } from "@/hooks/useWishlist";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import type { Product } from "@shared/schema";
import { getProductImages, getProductFallbackImage } from "@/utils/imageUtils";

interface ProductCardProps {
  product: Product & {
    storeDistance?: number;
    storeName?: string;
    deliveryTime?: string;
    category?: string | { id: string; name: string };
  };
  className?: string;
  showStoreInfo?: boolean;
  showQuickAdd?: boolean;
  showWishlist?: boolean;
  showCategory?: boolean;
  showDescription?: boolean;
  showRating?: boolean;
  showStockStatus?: boolean;
  showDiscountBadge?: boolean;
  showCompare?: boolean;
  showQuickView?: boolean;
  showAddToCart?: boolean;
  showHoverEffect?: boolean;
  showImageCountBadge?: boolean;
  showShareButton?: boolean;
  showDeliveryInfo?: boolean;
  showReturnPolicy?: boolean;
  showCashOnDelivery?: boolean;
  showInstallmentOption?: boolean;
  showWarrantyInfo?: boolean;
}

export default function ProductCard({
  product,
  className,
  showStoreInfo,
  showQuickAdd,
  showWishlist,
  showCategory,
  showDescription,
  showRating,
  showStockStatus,
  showDiscountBadge,
  showCompare,
  showQuickView,
  showAddToCart,
  showHoverEffect,
  showImageCountBadge,
  showShareButton,
  showDeliveryInfo,
  showReturnPolicy,
  showCashOnDelivery,
  showInstallmentOption,
  showWarrantyInfo,
}: ProductCardProps) {
  const { addToCart } = useCart();
  const { toggleWishlist, isInWishlist } = useWishlist();
  const { user } = useAuth();
  const { toast } = useToast();

  // Image scrolling state
  const [currentImageIndex, setCurrentImageIndex] = useState(0);
  const [isHovering, setIsHovering] = useState(false);
  const [touchStart, setTouchStart] = useState<number | null>(null);
  const [touchEnd, setTouchEnd] = useState<number | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const images = getProductImages(product);
  const hasMultipleImages = images.length > 1;

  // Minimum swipe distance for mobile
  const minSwipeDistance = 50;

  const handleAddToCart = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();

    // Allow adding to cart even without login
    addToCart(product.id, 1);
    toast({
      title: "Added to cart",
      description: `${product.name} has been added to your cart.`,
    });
  };

  const handleWishlistToggle = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();

    if (!user) {
      toast({
        title: "Login required",
        description: "Please login to add items to your wishlist.",
        variant: "destructive",
      });
      return;
    }

    const wasInWishlist = isInWishlist(product.id);
    await toggleWishlist(product.id);

    toast({
      title: wasInWishlist ? "Removed from wishlist" : "Added to wishlist",
      description: `${product.name} has been ${wasInWishlist ? "removed from" : "added to"} your wishlist.`,
    });
  };

  const discount = product.originalPrice
    ? Math.round(((Number(product.originalPrice) - Number(product.price)) / Number(product.originalPrice)) * 100)
    : 0;

  // Auto-scroll functionality on hover (desktop only)
  useEffect(() => {
    if (!hasMultipleImages || !isHovering) return;

    // Only enable auto-scroll on desktop (hover support)
    const isDesktop = window.matchMedia("(hover: hover)").matches;
    if (!isDesktop) return;

    const interval = setInterval(() => {
      setCurrentImageIndex((prev) => (prev + 1) % images.length);
    }, 2000); // Slower on desktop for better UX

    return () => clearInterval(interval);
  }, [isHovering, hasMultipleImages, images.length]);

  // Scroll to specific image
  const scrollToImage = (index: number) => {
    setCurrentImageIndex(index);
    if (scrollRef.current) {
      const scrollLeft = index * scrollRef.current.offsetWidth;
      scrollRef.current.scrollTo({
        left: scrollLeft,
        behavior: "smooth",
      });
    }
  };

  // Touch handlers for mobile swiping
  const handleTouchStart = (e: React.TouchEvent) => {
    setTouchEnd(null);
    setTouchStart(e.targetTouches[0].clientX);
  };

  const handleTouchMove = (e: React.TouchEvent) => {
    setTouchEnd(e.targetTouches[0].clientX);
  };

  const handleTouchEnd = () => {
    if (!touchStart || !touchEnd) return;

    const distance = touchStart - touchEnd;
    const isLeftSwipe = distance > minSwipeDistance;
    const isRightSwipe = distance < -minSwipeDistance;

    if (isLeftSwipe) {
      // Swipe left - next image
      const newIndex = currentImageIndex < images.length - 1 ? currentImageIndex + 1 : 0;
      scrollToImage(newIndex);
    }

    if (isRightSwipe) {
      // Swipe right - previous image
      const newIndex = currentImageIndex > 0 ? currentImageIndex - 1 : images.length - 1;
      scrollToImage(newIndex);
    }
  };

  return (
    <Link href={`/products/${product.id}`}>
      <div className={`product-card overflow-hidden group ${className}`}>
        <div
          className="relative overflow-hidden touch-pan-y"
          onMouseEnter={() => setIsHovering(true)}
          onMouseLeave={() => setIsHovering(false)}
          onTouchStart={handleTouchStart}
          onTouchMove={handleTouchMove}
          onTouchEnd={handleTouchEnd}
        >
          {/* Image Container with Horizontal Scroll */}
          <div
            ref={scrollRef}
            className="flex transition-transform duration-500 ease-in-out"
            style={{ transform: `translateX(-${currentImageIndex * 100}%)` }}
          >
            {images.map((image, index) => (
              <img
                key={index}
                src={image}
                alt={`${product.name} ${index + 1}`}
                className="w-full h-40 sm:h-48 md:h-56 lg:h-60 object-cover flex-shrink-0"
                onError={(e) => {
                  const target = e.target as HTMLImageElement;
                  if (!target.src.includes("unsplash")) {
                    target.src = getProductFallbackImage(product);
                  }
                }}
                loading="lazy"
              />
            ))}
          </div>



          {/* Pagination Dots - Using inline styles */}
          {hasMultipleImages && (
            <div className="absolute bottom-1 left-1/2 -translate-x-1/2 flex gap-1.5 z-10" style={{ transform: 'translateX(-50%)' }}>
              {images.map((_, index) => (
                <button
                  key={index}
                  style={{
                    width: currentImageIndex === index ? '8px' : '6px',
                    height: currentImageIndex === index ? '8px' : '6px',
                    minWidth: currentImageIndex === index ? '8px' : '6px',
                    minHeight: currentImageIndex === index ? '8px' : '6px',
                    flex: '0 0 auto'
                  }}
                  className={`transition-all duration-200 touch-manipulation rounded-full ${
                    currentImageIndex === index 
                      ? 'bg-white/90' 
                      : 'bg-white/50 hover:bg-white/70'
                  }`}
                  onClick={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    scrollToImage(index);
                  }}
                  aria-label={`Go to image ${index + 1}`}
                />
              ))}
            </div>
          )}

          {/* Discount Badge */}
          {discount > 0 && (
            <Badge className="absolute top-2 left-2 bg-red-500 text-white z-10">
              {discount}% OFF
            </Badge>
          )}

          {/* Multiple Images Indicator - Better positioned for mobile */}
          {hasMultipleImages && (
            <div className="absolute top-2 right-2 bg-black/70 text-white text-xs px-2 py-1 rounded-full shadow-sm backdrop-blur-sm">
              {currentImageIndex + 1}/{images.length}
            </div>
          )}


        </div>

        <div className="p-2">
          <h3 className="font-medium text-foreground text-[10px] mb-1 line-clamp-2">
            {product.name}
          </h3>

          {/* Restaurant name and distance info for food items */}
          {product.storeName && (
            <div className="text-[9px] text-muted-foreground mb-1 flex items-center justify-between">
              <span className="truncate">{product.storeName}</span>
              {product.storeDistance !== undefined && (
                <div className="flex items-center gap-1 text-[8px] text-blue-600">
                  <MapPin className="h-2 w-2" />
                  <span>{product.storeDistance.toFixed(1)}km</span>
                </div>
              )}
            </div>
          )}

          {/* Delivery time for food items */}
          {product.deliveryTime && (
            <div className="text-[8px] text-muted-foreground mb-1 flex items-center gap-1">
              <Clock className="h-2 w-2" />
              <span>{product.deliveryTime}</span>
            </div>
          )}

          {/* Rating display */}
          {product.rating && parseFloat(product.rating) > 0 && (
            <div className="flex items-center gap-1 mb-1">
              <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
              <span className="text-[10px] text-gray-600">
                {parseFloat(product.rating).toFixed(1)}
              </span>
            </div>
          )}

          <div className="flex items-center space-x-1 mb-2">
            <span className="text-xs font-bold text-foreground">
              ₹{Number(product.price).toLocaleString()}
            </span>
            {product.originalPrice && (
              <span className="text-[10px] text-muted-foreground line-through">
                ₹{Number(product.originalPrice).toLocaleString()}
              </span>
            )}
          </div>

          <div className="flex gap-2">
            <Button
              onClick={handleAddToCart}
              className="flex-1 btn-secondary text-xs py-1 h-8"
              size="sm"
            >
              <ShoppingCart className="h-3 w-3" />
            </Button>
            <Button
              onClick={handleWishlistToggle}
              variant="outline"
              className="text-xs py-1 h-8 w-8 p-0"
              size="sm"
            >
              <Heart 
                className={`h-3 w-3 transition-colors ${
                  isInWishlist(product.id) 
                    ? "fill-red-500 text-red-500" 
                    : "text-gray-600 hover:text-red-400"
                }`}
              />
            </Button>
          </div>
        </div>
      </div>
    </Link>
  );
}