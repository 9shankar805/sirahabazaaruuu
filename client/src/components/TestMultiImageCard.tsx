import { useState, useRef, useEffect } from "react";
import { Link } from "wouter";
import { Star, ShoppingCart, Heart, ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// Test component to demonstrate mobile-focused horizontal image scrolling
export default function TestMultiImageCard() {
  // Mock product with multiple images for testing
  const mockProduct = {
    id: 999,
    name: "iPhone 15 Pro Max - Test Product",
    price: "149900",
    originalPrice: "159900",
    rating: "4.8",
    images: [
      "https://images.unsplash.com/photo-1695048133142-1a20484d2569?w=400&h=300&fit=crop&auto=format",
      "https://images.unsplash.com/photo-1695048059149-ac4c4d585cdc?w=400&h=300&fit=crop&auto=format", 
      "https://images.unsplash.com/photo-1695048576165-56c8259a41e6?w=400&h=300&fit=crop&auto=format",
      "https://images.unsplash.com/photo-1695048374656-6b2ae6c96e3a?w=400&h=300&fit=crop&auto=format"
    ]
  };

  // Image scrolling state
  const [currentImageIndex, setCurrentImageIndex] = useState(0);
  const [isHovering, setIsHovering] = useState(false);
  const [touchStart, setTouchStart] = useState<number | null>(null);
  const [touchEnd, setTouchEnd] = useState<number | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const images = mockProduct.images;
  const hasMultipleImages = images.length > 1;

  // Minimum swipe distance for mobile
  const minSwipeDistance = 50;

  const discount = mockProduct.originalPrice 
    ? Math.round(((Number(mockProduct.originalPrice) - Number(mockProduct.price)) / Number(mockProduct.originalPrice)) * 100)
    : 0;

  // Auto-scroll functionality on hover (desktop only)
  useEffect(() => {
    if (!hasMultipleImages || !isHovering) return;
    
    // Only enable auto-scroll on desktop (hover support)
    const isDesktop = window.matchMedia('(hover: hover)').matches;
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
        behavior: 'smooth'
      });
    }
  };

  // Handle manual navigation
  const handlePrevImage = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const newIndex = currentImageIndex > 0 ? currentImageIndex - 1 : images.length - 1;
    scrollToImage(newIndex);
  };

  const handleNextImage = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const newIndex = currentImageIndex < images.length - 1 ? currentImageIndex + 1 : 0;
    scrollToImage(newIndex);
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
    <div className="w-full max-w-sm mx-auto">
      <Link href={`/products/${mockProduct.id}`}>
        <div className="product-card overflow-hidden group">
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
                  alt={`${mockProduct.name} ${index + 1}`}
                  className="w-full h-40 sm:h-48 md:h-56 lg:h-60 object-cover flex-shrink-0"
                  loading="lazy"
                />
              ))}
            </div>

            {/* Navigation Arrows - Always visible on mobile, show on hover for desktop */}
            {hasMultipleImages && (
              <>
                <Button
                  variant="ghost"
                  size="sm"
                  className="absolute left-1 top-1/2 -translate-y-1/2 bg-black/60 hover:bg-black/80 backdrop-blur-sm p-1 h-7 w-7 rounded-full shadow-lg transition-all md:opacity-0 md:group-hover:opacity-100 opacity-70 active:scale-95"
                  onClick={handlePrevImage}
                >
                  <ChevronLeft className="h-3 w-3 text-white" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="absolute right-1 top-1/2 -translate-y-1/2 bg-black/60 hover:bg-black/80 backdrop-blur-sm p-1 h-7 w-7 rounded-full shadow-lg transition-all md:opacity-0 md:group-hover:opacity-100 opacity-70 active:scale-95"
                  onClick={handleNextImage}
                >
                  <ChevronRight className="h-3 w-3 text-white" />
                </Button>
              </>
            )}

            {/* Pagination Dots - Larger and more visible on mobile */}
            {hasMultipleImages && (
              <div className="absolute bottom-1 left-1/2 -translate-x-1/2 flex gap-1 px-2 py-1 rounded-full bg-black/20 backdrop-blur-sm">
                {images.map((_, index) => (
                  <button
                    key={index}
                    className={`transition-all duration-300 touch-manipulation ${
                      currentImageIndex === index 
                        ? 'w-3 h-1 bg-white rounded-full shadow-sm sm:w-6 sm:h-2' 
                        : 'w-1 h-1 bg-white/60 rounded-full hover:bg-white/80 sm:w-2 sm:h-2'
                    }`}
                    onClick={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      scrollToImage(index);
                    }}
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
              {mockProduct.name}
            </h3>
            
            {/* Rating display */}
            {mockProduct.rating && parseFloat(mockProduct.rating) > 0 && (
              <div className="flex items-center gap-1 mb-1">
                <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
                <span className="text-[10px] text-gray-600">
                  {parseFloat(mockProduct.rating).toFixed(1)}
                </span>
              </div>
            )}
            
            <div className="flex items-center space-x-1 mb-2">
              <span className="text-xs font-bold text-foreground">
                ₹{Number(mockProduct.price).toLocaleString()}
              </span>
              {mockProduct.originalPrice && (
                <span className="text-[10px] text-muted-foreground line-through">
                  ₹{Number(mockProduct.originalPrice).toLocaleString()}
                </span>
              )}
            </div>
            
            <div className="flex gap-2">
              <Button
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  alert('Added to cart (demo)');
                }}
                className="flex-1 btn-secondary text-xs py-1 h-8"
                size="sm"
              >
                <ShoppingCart className="h-3 w-3" />
              </Button>
              <Button
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  alert('Added to wishlist (demo)');
                }}
                variant="outline"
                className="text-xs py-1 h-8 w-8 p-0"
                size="sm"
              >
                <Heart className="h-3 w-3 text-gray-600 hover:text-red-400" />
              </Button>
            </div>


          </div>
        </div>
      </Link>
    </div>
  );
}