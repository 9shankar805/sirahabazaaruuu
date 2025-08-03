import { useState, useEffect, useRef } from "react";
import { useParams, Link, useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { 
  Star, 
  ShoppingCart, 
  Heart, 
  Minus, 
  Plus, 
  MapPin, 
  Store, 
  ArrowLeft,
  Share2
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { useCart } from "@/hooks/useCart";
import { useWishlist } from "@/hooks/useWishlist";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useAppMode } from "@/hooks/useAppMode";
import { ProductReviews } from "@/components/ProductReviews";
import type { Product, Store as StoreType } from "@shared/schema";
import { getProductImages, getProductFallbackImage } from "@/utils/imageUtils";

export default function ModernProductDetail() {
  const { id } = useParams();
  const [, setLocation] = useLocation();
  const [quantity, setQuantity] = useState(1);
  const [showFullDescription, setShowFullDescription] = useState(false);
  const [showShareModal, setShowShareModal] = useState(false);
  const { addToCart } = useCart();
  const { toggleWishlist, isInWishlist } = useWishlist();
  const { user } = useAuth();
  const { toast } = useToast();
  const [userLocation, setUserLocation] = useState<{lat: number, lon: number} | null>(null);
  const [storeDistance, setStoreDistance] = useState<string | null>(null);
  const { mode } = useAppMode();
  const [locationError, setLocationError] = useState<string | null>(null);

  // Get user location for distance calculation
  useEffect(() => {
    if (!navigator.geolocation) {
      setLocationError('Geolocation is not supported by your browser');
      return;
    }

    const handleSuccess = (position: GeolocationPosition) => {
      setUserLocation({
        lat: position.coords.latitude,
        lon: position.coords.longitude
      });
      setLocationError(null);
    };

    const handleError = (error: GeolocationPositionError) => {
      console.error('Location access error:', error);
      setLocationError('Unable to retrieve your location');
      // Fallback to default location or handle the error appropriately
    };

    navigator.geolocation.getCurrentPosition(
      handleSuccess,
      handleError,
      { 
        timeout: 10000, 
        enableHighAccuracy: false,
        maximumAge: 5 * 60 * 1000 // 5 minutes
      }
    );
  }, []);

  const { data: product, isLoading } = useQuery<Product>({
    queryKey: [`/api/products/${id}`],
    enabled: !!id,
  });

  const { data: store } = useQuery<StoreType>({
    queryKey: [`/api/stores/${product?.storeId}`],
    enabled: !!product?.storeId,
  });

  const { data: allRelatedProducts = [] } = useQuery<Product[]>({
    queryKey: [`/api/products`, { category: product?.categoryId }],
    enabled: !!product?.categoryId,
  });

  // Calculate distance when store and user location are available
  useEffect(() => {
    if (store?.latitude && store?.longitude && userLocation) {
      const calculateDistance = (lat1: number, lon1: number, lat2: number, lon2: number) => {
        const R = 6371; // Earth's radius in kilometers
        const dLat = (lat2 - lat1) * Math.PI / 180;
        const dLon = (lon2 - lon1) * Math.PI / 180;
        const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                  Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
                  Math.sin(dLon/2) * Math.sin(dLon/2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
        return R * c;
      };

      const distance = calculateDistance(
        userLocation.lat, 
        userLocation.lon, 
        Number(store.latitude), 
        Number(store.longitude)
      );

      if (distance < 1) {
        setStoreDistance(`${Math.round(distance * 1000)}m away`);
      } else {
        setStoreDistance(`${distance.toFixed(1)}km away`);
      }
    }
  }, [store, userLocation]);

  // Image carousel state
  const [currentImageIndex, setCurrentImageIndex] = useState(0);
  const images = product ? getProductImages(product) : [];
  const isWishlisted = product ? isInWishlist(product.id) : false;

  const handleNextImage = () => {
    setCurrentImageIndex((prevIndex) => 
      prevIndex === images.length - 1 ? 0 : prevIndex + 1
    );
  };

  const handlePrevImage = () => {
    setCurrentImageIndex((prevIndex) =>
      prevIndex === 0 ? images.length - 1 : prevIndex - 1
    );
  };

  const handleThumbnailClick = (index: number) => {
    setCurrentImageIndex(index);
  };

  const handleAddToCart = async () => {
    if (!product) return;
    
    try {
      await addToCart(product.id, quantity);
      toast({
        title: "Added to cart",
        description: `${quantity} ${product.name} added to your cart.`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to add item to cart. Please try again.",
        variant: "destructive",
      });
    }
  };

  const handleWishlistToggle = async () => {
    if (!product) return;

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

  const handleShare = async () => {
    if (!product) return;

    const shareData = {
      title: product.name,
      text: `Check out ${product.name} on our store!`,
      url: window.location.href,
    };

    try {
      if (navigator.share) {
        await navigator.share(shareData);
      } else {
        setShowShareModal(true);
      }
    } catch (err) {
      console.error('Error sharing:', err);
      await copyToClipboard(window.location.href);
      toast({
        title: "Link copied to clipboard!",
        variant: "default",
      });
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (err) {
      console.error('Failed to copy text: ', err);
      return false;
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-white flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-orange-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-600">Loading product...</p>
        </div>
      </div>
    );
  }

  if (!product) {
    return (
      <div className="min-h-screen bg-white flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-orange-500"></div>
      </div>
    );
  }

  const discount = product.originalPrice 
    ? Math.round(((Number(product.originalPrice) - Number(product.price)) / Number(product.originalPrice)) * 100)
    : 0;

  // Filter related products based on app mode
  const relatedProducts = allRelatedProducts.filter((relatedProduct: Product) => {
    if (mode === "shopping") {
      // In shopping mode, exclude food items
      return relatedProduct.productType !== "food";
    } else {
      // In food mode, show only food items
      return relatedProduct.productType === "food";
    }
  }).filter((relatedProduct: Product) => relatedProduct.id !== product?.id); // Exclude current product

  // Debug icon rendering
  console.log('Rendering ModernProductDetail, icons should be visible');
  console.log('ArrowLeft, Share2, Heart icons from lucide-react');

  return (
    <div className="min-h-screen bg-white modern-product-detail" style={{ paddingBottom: '144px', overflowX: 'hidden' }}>
      {/* Share and Wishlist Icons - Above Product Image */}
      <div className="flex justify-between items-center gap-2 px-4 pt-4 pb-2">
        {/* Back Button */}
        <button
          onClick={() => {
            console.log('Back button clicked');
            setLocation('/products');
          }}
          className="flex items-center justify-center p-3 hover:bg-gray-100 rounded-full transition-colors border border-gray-200 bg-white shadow-sm"
          style={{ minWidth: '44px', minHeight: '44px' }}
          title="Go Back"
        >
          <ArrowLeft className="h-6 w-6 text-gray-700" strokeWidth={2} />
          <span className="sr-only">Back</span>
        </button>
        
        <div className="flex items-center gap-2">
        {/* Share Button */}
        <Button 
          variant="outline" 
          size="icon" 
          className="rounded-full w-12 h-12"
          onClick={handleShare}
          aria-label="Share product"
        >
          <Share2 className="h-5 w-5" />
        </Button>
        
        {/* Wishlist Button */}
        <button 
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            console.log('Wishlist button clicked');
            handleWishlistToggle();
          }}
          className="flex items-center justify-center p-3 hover:bg-gray-100 rounded-full transition-colors border border-gray-200 bg-white shadow-sm"
          style={{ minWidth: '44px', minHeight: '44px' }}
          title={isWishlisted ? "Remove from Wishlist" : "Add to Wishlist"}
        >
          <Heart 
            className={`h-6 w-6 ${
              isWishlisted 
                ? "fill-red-500 text-red-500" 
                : "text-gray-700"
            } `}
            strokeWidth={2}
          />
          <span className="sr-only">{isWishlisted ? "Remove from Wishlist" : "Add to Wishlist"}</span>
        </button>
        </div>
      </div>

      {/* Product Image Gallery */}
      <div className="relative overflow-hidden">
        {/* Main Image */}
        <div className="relative w-full h-80 sm:h-96 bg-gray-50">
          <img
            src={images[currentImageIndex] || getProductFallbackImage(product)}
            alt={`${product.name} - Image ${currentImageIndex + 1}`}
            className="w-full h-full object-cover"
            onError={(e) => {
              const target = e.target as HTMLImageElement;
              target.src = getProductFallbackImage(product);
            }}
            loading="lazy"
          />

          {/* Navigation Arrows - Only show if there are multiple images */}
          {images.length > 1 && (
            <>
              <button 
                onClick={(e) => {
                  e.stopPropagation();
                  handlePrevImage();
                }}
                className="absolute left-2 top-1/2 -translate-y-1/2 bg-black/30 text-white rounded-full p-2 hover:bg-black/50 transition-colors"
                aria-label="Previous image"
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M15 18l-6-6 6-6" />
                </svg>
              </button>
              <button 
                onClick={(e) => {
                  e.stopPropagation();
                  handleNextImage();
                }}
                className="absolute right-2 top-1/2 -translate-y-1/2 bg-black/30 text-white rounded-full p-2 hover:bg-black/50 transition-colors"
                aria-label="Next image"
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M9 18l6-6-6-6" />
                </svg>
              </button>
            </>
          )}

          {/* Discount Badge */}
          {discount > 0 && (
            <Badge className="absolute top-4 left-4 bg-red-500 text-white px-3 py-1 text-sm font-semibold">
              {discount}% OFF
            </Badge>
          )}
        </div>

        {/* Thumbnail Navigation - Only show if there are multiple images */}
        {images.length > 1 && (
          <div className="flex gap-2 p-2 overflow-x-auto hide-scrollbar">
            {images.map((img, index) => (
              <button
                key={index}
                onClick={() => handleThumbnailClick(index)}
                className={`flex-shrink-0 w-16 h-16 rounded-md overflow-hidden border-2 ${
                  index === currentImageIndex 
                    ? 'border-orange-500' 
                    : 'border-transparent hover:border-gray-300'
                } transition-colors`}
                aria-label={`View image ${index + 1}`}
              >
                <img
                  src={img}
                  alt={`${product.name} thumbnail ${index + 1}`}
                  className="w-full h-full object-cover"
                  onError={(e) => {
                    const target = e.target as HTMLImageElement;
                    target.src = getProductFallbackImage(product);
                  }}
                  loading="lazy"
                />
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="px-4 py-6 pb-24">
        {/* Product Details */}
        {/* Product Name & Rating */}
        <div className="mb-4">
          <h1 className="text-xl font-bold text-gray-900 leading-tight mb-2">
            {product.name}
          </h1>

          {product.rating && parseFloat(product.rating) > 0 && (
            <div className="flex items-center gap-2 mb-2">
              <div className="flex items-center gap-1">
                <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                <span className="text-sm font-medium text-gray-900">
                  {parseFloat(product.rating).toFixed(1)}
                </span>
              </div>
              <span className="text-sm text-gray-500">
                (245 reviews)
              </span>
            </div>
          )}
        </div>

        {/* Price */}
        <div className="flex items-center gap-3 mb-6">
          <span className="text-2xl font-bold text-gray-900">
            ₹{Number(product.price).toLocaleString()}
          </span>
          {product.originalPrice && (
            <>
              <span className="text-lg text-gray-400 line-through">
                ₹{Number(product.originalPrice).toLocaleString()}
              </span>
              <Badge variant="secondary" className="bg-green-100 text-green-700">
                Save ₹{(Number(product.originalPrice) - Number(product.price)).toLocaleString()}
              </Badge>
            </>
          )}
        </div>

        {/* Store Info with Visit Store Button */}
        {store && (
          <div className="bg-gray-50 rounded-lg p-4 mb-6">
            <div className="flex items-start gap-3">
              <Store className="h-5 w-5 text-gray-600 mt-0.5" />
              <div className="flex-1">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1">
                    <p className="font-medium text-gray-900">{store.name}</p>
                    <p className="text-sm text-gray-600">{store.address}</p>
                  </div>
                  {store.rating && (
                    <div className="flex items-center gap-1 bg-green-100 px-2 py-1 rounded">
                      <Star className="h-3 w-3 fill-green-600 text-green-600" />
                      <span className="text-xs font-medium text-green-700">{store.rating}</span>
                    </div>
                  )}
                </div>

                {/* Distance and Store Info */}
                <div className="flex items-center gap-4 mb-3">
                  {storeDistance && (
                    <div className="flex items-center gap-1 text-xs text-gray-500">
                      <MapPin className="h-3 w-3" />
                      <span>{storeDistance}</span>
                    </div>
                  )}
                  {store.deliveryTime && (
                    <div className="flex items-center gap-1 text-xs text-gray-500">
                      <span>🚚 {store.deliveryTime}</span>
                    </div>
                  )}
                  {store.minimumOrder && (
                    <div className="flex items-center gap-1 text-xs text-gray-500">
                      <span>Min: ₹{store.minimumOrder}</span>
                    </div>
                  )}
                </div>
                <Link href={`/stores/${store.id}`}>
                  <Button 
                    variant="outline" 
                    size="sm"
                    className="text-orange-600 border-orange-600 hover:bg-orange-50"
                  >
                    <Store className="h-4 w-4 mr-2" />
                    Visit Store
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        )}

        {/* Quantity Selector */}
        <div className="mb-6">
          <p className="text-sm font-medium text-gray-900 mb-3">Quantity</p>
          <div className="flex items-center gap-3">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setQuantity(Math.max(1, quantity - 1))}
              disabled={quantity <= 1}
              className="h-10 w-10 p-0"
            >
              <Minus className="h-4 w-4" />
            </Button>
            <span className="text-lg font-medium w-12 text-center">
              {quantity}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setQuantity(quantity + 1)}
              className="h-10 w-10 p-0"
            >
              <Plus className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {/* Description */}
        {product.description && (
          <div className="mb-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">Description</h3>
            <div className="text-gray-700 leading-relaxed">
              {showFullDescription ? (
                <p>{product.description}</p>
              ) : (
                <p className="line-clamp-3">{product.description}</p>
              )}
              {product.description.length > 150 && (
                <button
                  onClick={() => setShowFullDescription(!showFullDescription)}
                  className="text-orange-500 hover:text-orange-600 mt-2 text-sm font-medium"
                >
                  {showFullDescription ? 'Show less' : 'Read more'}
                </button>
              )}
            </div>
          </div>
        )}

        {/* Food-specific Info */}
        {product.productType === 'food' && (
          <div className="space-y-4 mb-6">
            {product.preparationTime && (
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-gray-900">Prep Time:</span>
                <span className="text-sm text-gray-600">{product.preparationTime}</span>
              </div>
            )}

            {product.spiceLevel && (
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-gray-900">Spice Level:</span>
                <Badge variant="outline" className="capitalize">
                  {product.spiceLevel}
                </Badge>
              </div>
            )}

            <div className="flex gap-2">
              {product.isVegetarian && (
                <Badge className="bg-green-100 text-green-700">Vegetarian</Badge>
              )}
              {product.isVegan && (
                <Badge className="bg-green-100 text-green-700">Vegan</Badge>
              )}
            </div>
          </div>
        )}

        {/* Product Reviews Section */}
        <div className="mb-6">
          <div className="border-t border-gray-100 pt-6">
            <ProductReviews productId={parseInt(id || '0')} productName={product.name} />

          </div>
        </div>
      </div>

      {/* Related Products Section */}
      {relatedProducts.length > 0 && (
        <div className="px-4 pb-6 mb-20">
          <div className="border-t border-gray-100 pt-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">You might also like</h3>
            <div className="grid grid-cols-2 gap-4">
              {relatedProducts.map((relatedProduct) => (
                <Link
                  key={relatedProduct.id}
                  href={`/products/${relatedProduct.id}`}
                  className="group bg-white rounded-lg border border-gray-100 overflow-hidden hover:shadow-md transition-shadow"
                >
                  <div className="aspect-square overflow-hidden bg-gray-50">
                    <img
                      src={getProductImages(relatedProduct)[0]}
                      alt={relatedProduct.name}
                      className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                    />
                  </div>
                  <div className="p-3">
                    <h4 className="font-medium text-gray-900 text-sm line-clamp-2 mb-1">
                      {relatedProduct.name}
                    </h4>
                    <div className="flex items-center gap-2">
                      <span className="text-orange-600 font-bold text-sm">
                        ₹{Number(relatedProduct.price).toLocaleString()}
                      </span>
                      {relatedProduct.originalPrice && (
                        <span className="text-gray-400 line-through text-xs">
                          ₹{Number(relatedProduct.originalPrice).toLocaleString()}
                        </span>
                      )}
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Fixed Bottom Cart Button - Above Bottom Navbar */}
      <div className="fixed left-0 right-0 bg-white border-t border-gray-100 p-4 z-[999] fixed-bottom-cart" style={{ position: 'fixed', bottom: '64px', left: 0, right: 0, zIndex: 999 }}>
        <div className="flex items-center gap-3">
          <div className="flex-1">
            <p className="text-xs text-gray-500">Total</p>
            <p className="text-lg font-bold text-gray-900">
              ₹{(Number(product.price) * quantity).toLocaleString()}
            </p>
          </div>
          <Button
            onClick={(e) => {
              console.log('Add to Cart button clicked on mobile');
              handleAddToCart();
            }}
            className="flex-1 modern-cart-button text-white h-12 text-base font-semibold rounded-lg"
            size="lg"
            style={{ 
              minHeight: '48px',
              fontSize: '16px',
              touchAction: 'manipulation',
              WebkitTouchCallout: 'none'
            }}
          >
            <ShoppingCart className="h-5 w-5 mr-2" />
            Add to Cart
          </Button>
        </div>
      </div>

      {/* Share Modal */}
      {showShareModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={() => setShowShareModal(false)}>
          <div className="bg-white rounded-lg w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-semibold mb-4">Share Product</h3>
            <div className="space-y-3">
              <Button 
                variant="outline" 
                className="w-full justify-start gap-3"
                onClick={async () => {
                  await copyToClipboard(window.location.href);
                  setShowShareModal(false);
                  toast({
                    title: "Link copied to clipboard!",
                    variant: "default",
                  });
                }}
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
                Copy Link
              </Button>
              
              {/* WhatsApp */}
              <Button 
                variant="outline" 
                className="w-full justify-start gap-3 text-green-600 hover:text-green-700"
                onClick={() => {
                  window.open(`https://wa.me/?text=${encodeURIComponent(`Check out ${product.name}: ${window.location.href}`)}`, '_blank');
                  setShowShareModal(false);
                }}
              >
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M17.5 14.4c-.3 0-.5.1-.7.2-.3 0-.5.2-.6.4-.1.1-.1.3-.2.4-.2.3-.4.6-.6.9-.1.1-.2.2-.4.2-.2 0-.4 0-.6-.1-.2-.1-.4-.2-.7-.3-1.2-.6-2.2-1.4-3-2.4-.8-1-1.4-2.1-1.8-3.3 0-.2 0-.4.1-.6 0-.1.1-.3.2-.4.2-.3.4-.5.6-.7.2-.2.3-.4.3-.6 0-.2 0-.4-.1-.6-.1-.2-.2-.4-.4-.5-.2-.2-.4-.3-.6-.4-.2 0-.4-.1-.6-.1H8.4c-.2 0-.4 0-.6.1-.4.1-.7.3-.9.6-.2.3-.3.6-.4 1-.1.3-.2.6-.2.9 0 .3 0 .6.1.9.1.3.2.6.4.9.2.3.3.6.5.9.1.3.3.5.4.8.1.3.2.4.4.7.1.2.2.4.3.7.1.2.1.4.2.7 0 .3 0 .5-.1.8 0 .2-.1.4-.3.6-.1.2-.3.3-.5.4-.2.1-.4.1-.6.1-.2 0-.4 0-.6-.1-.2 0-.4-.1-.6-.2-.2-.1-.4-.1-.6-.2-.2 0-.4 0-.6.1-.2 0-.4.1-.6.2-.2.1-.3.2-.5.4-.1.1-.3.2-.4.4-.1.2-.2.3-.3.5 0 .1-.1.3-.1.4 0 .1 0 .3.1.4.1.3.2.5.4.7.2.2.4.4.6.6.2.2.4.3.7.4.3.1.5.3.8.4.3.1.5.2.8.3.3.1.6.2.9.3.3.1.6.1.9.1.3 0 .6 0 .9-.1.3 0 .6-.1.9-.2.3-.1.6-.2.9-.4.3-.1.5-.3.8-.5.3-.2.5-.4.7-.7.2-.3.4-.5.5-.8.1-.3.2-.6.2-.9 0-.1 0-.2.1-.3 0-.1 0-.2.1-.3 0-.1.1-.2.1-.3 0-.1.1-.2.1-.3 0-.1.1-.2.1-.3.1-.2.2-.5.2-.7 0-.3-.1-.5-.3-.7-.2-.2-.4-.3-.6-.4z"></path>
                </svg>
                Share via WhatsApp
              </Button>
              
              {/* Facebook */}
              <Button 
                variant="outline" 
                className="w-full justify-start gap-3 text-blue-600 hover:text-blue-700"
                onClick={() => {
                  window.open(`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(window.location.href)}`, '_blank');
                  setShowShareModal(false);
                }}
              >
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M18 2h-3a5 5 0 0 0-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 0 1 1-1h3z"></path>
                </svg>
                Share on Facebook
              </Button>
              
              {/* Twitter */}
              <Button 
                variant="outline" 
                className="w-full justify-start gap-3 text-sky-500 hover:text-sky-600"
                onClick={() => {
                  window.open(`https://twitter.com/intent/tweet?url=${encodeURIComponent(window.location.href)}&text=${encodeURIComponent(`Check out ${product.name}`)}`, '_blank');
                  setShowShareModal(false);
                }}
              >
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M23 3a10.9 10.9 0 0 1-3.14 1.53 4.48 4.48 0 0 0-7.86 3v1A10.66 10.66 0 0 1 3 4s-4 9 5 13a11.64 11.64 0 0 1-7 2c9 5 20 0 20-11.5a4.5 4.5 0 0 0-.08-.83A7.72 7.72 0 0 0 23 3z"></path>
                </svg>
                Share on Twitter
              </Button>
            </div>
            <div className="mt-6 flex justify-end">
              <Button 
                variant="ghost" 
                onClick={() => setShowShareModal(false)}
              >
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}