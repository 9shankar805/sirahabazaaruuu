import { useState, useEffect } from "react";
import { useParams, Link, useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Star, ShoppingCart, Heart, Minus, Plus, MapPin, Store } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import ProductCard from "@/components/ProductCard";
import { ProductReviews } from "@/components/ProductReviews";
import { useCart } from "@/hooks/useCart";
import { useToast } from "@/hooks/use-toast";
import { useAppMode } from "@/hooks/useAppMode";
import { getCurrentUserLocation } from "@/lib/distance";
import type { Product, Store as StoreType } from "@shared/schema";
import { getProductImages, getProductFallbackImage } from "@/utils/imageUtils";

export default function ProductDetail() {
  const { id } = useParams();
  const [, setLocation] = useLocation();
  const [quantity, setQuantity] = useState(1);
  const [selectedImage, setSelectedImage] = useState(0);
  const [userLocation, setUserLocation] = useState<{ latitude: number; longitude: number } | null>(null);
  const [storeDistance, setStoreDistance] = useState<number | null>(null);
  const { addToCart, selectSingleItem } = useCart();
  const { toast } = useToast();
  const { mode } = useAppMode();

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

  // Get user location and calculate distance to store
  useEffect(() => {
    const getUserLocationAndCalculateDistance = async () => {
      try {
        const location = await getCurrentUserLocation();
        setUserLocation(location);
        
        if (store?.latitude && store?.longitude) {
          const storeLatitude = parseFloat(store.latitude);
          const storeLongitude = parseFloat(store.longitude);
          
          if (!isNaN(storeLatitude) && !isNaN(storeLongitude)) {
            // Calculate distance using Haversine formula
            const R = 6371; // Earth's radius in kilometers
            const dLat = (storeLatitude - location.latitude) * Math.PI / 180;
            const dLon = (storeLongitude - location.longitude) * Math.PI / 180;
            const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                      Math.cos(location.latitude * Math.PI / 180) * Math.cos(storeLatitude * Math.PI / 180) *
                      Math.sin(dLon/2) * Math.sin(dLon/2);
            const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
            const distance = R * c;
            
            setStoreDistance(distance);
          }
        }
      } catch (error) {
        // Location access denied or not available
        setStoreDistance(null);
      }
    };

    if (store) {
      getUserLocationAndCalculateDistance();
    }
  }, [store]);

  const handleAddToCart = async () => {
    if (!product) return;
    
    try {
      await addToCart(product.id, quantity);
      toast({
        title: "Added to cart",
        description: `${quantity} ${product.name}(s) added to your cart.`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to add to cart",
        variant: "destructive",
      });
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-muted flex items-center justify-center">
        <div>Loading product...</div>
      </div>
    );
  }

  if (!product) {
    return (
      <div className="min-h-screen bg-muted flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold mb-4">Product not found</h2>
          <Link href="/products">
            <Button>Back to Products</Button>
          </Link>
        </div>
      </div>
    );
  }

  const discount = product.originalPrice 
    ? Math.round(((Number(product.originalPrice) - Number(product.price)) / Number(product.originalPrice)) * 100)
    : 0;

  const images = getProductImages(product);
  const relatedProductsFiltered = relatedProducts.filter(p => p.id !== product.id).slice(0, 4);

  return (
    <div className="min-h-screen bg-muted">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="bg-card rounded-lg p-4 sm:p-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 lg:gap-8">
            {/* Product Images */}
            <div>
              <div className="mb-3">
                <img
                  src={images[selectedImage]}
                  alt={product.name}
                  className="w-full h-64 sm:h-80 lg:h-96 object-cover rounded-lg shadow-lg"
                  onError={(e) => {
                    const target = e.target as HTMLImageElement;
                    if (!target.src.includes('unsplash')) {
                      target.src = getProductFallbackImage(product);
                    }
                  }}
                  loading="lazy"
                />
              </div>
              
              {/* Mobile-optimized thumbnail selection */}
              {images.length > 1 && (
                <div className="mb-4">
                  {/* Mobile view - horizontal scroll */}
                  <div className="md:hidden">
                    <div className="flex gap-2 overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-gray-300">
                      {images.map((image, index) => (
                        <img
                          key={index}
                          src={image}
                          alt={`${product.name} ${index + 1}`}
                          className={`flex-shrink-0 w-16 h-16 object-cover rounded-lg cursor-pointer border-2 transition-all duration-200 ${
                            selectedImage === index 
                              ? "border-primary ring-2 ring-primary/20 scale-105" 
                              : "border-gray-200 hover:border-gray-300"
                          }`}
                          onClick={() => setSelectedImage(index)}
                        />
                      ))}
                    </div>
                  </div>
                  
                  {/* Desktop view - grid layout */}
                  <div className="hidden md:grid grid-cols-4 gap-2">
                    {images.map((image, index) => (
                      <img
                        key={index}
                        src={image}
                        alt={`${product.name} ${index + 1}`}
                        className={`w-full h-20 object-cover rounded cursor-pointer border-2 transition-all duration-200 ${
                          selectedImage === index 
                            ? "border-primary ring-2 ring-primary/20" 
                            : "border-border hover:border-gray-300"
                        }`}
                        onClick={() => setSelectedImage(index)}
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Product Info */}
            <div>
              <h1 className="text-2xl font-bold text-foreground mb-4">{product.name}</h1>
              
              <div className="flex items-center mb-4">
                <div className="flex text-yellow-400 mr-2">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <Star
                      key={i}
                      className={`h-4 w-4 ${
                        i < Math.floor(Number(product.rating)) ? "fill-current" : ""
                      }`}
                    />
                  ))}
                </div>
                <span className="text-muted-foreground">
                  ({product.rating}) • {product.totalReviews} reviews
                </span>
              </div>

              <div className="flex items-center gap-4 mb-6">
                <span className="text-3xl font-bold text-foreground">
                  ₹{Number(product.price).toLocaleString()}
                </span>
                {product.originalPrice && (
                  <>
                    <span className="text-xl text-muted-foreground line-through">
                      ₹{Number(product.originalPrice).toLocaleString()}
                    </span>
                    <Badge variant="destructive">{discount}% OFF</Badge>
                  </>
                )}
              </div>

              {product.description && (
                <div className="mb-6">
                  <h3 className="font-semibold mb-2">Product Description</h3>
                  <p className="text-muted-foreground">{product.description}</p>
                </div>
              )}

              {/* Quantity Selector */}
              <div className="mb-6">
                <h3 className="font-semibold mb-2">Quantity</h3>
                <div className="flex items-center space-x-4">
                  <div className="flex items-center border rounded">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setQuantity(Math.max(1, quantity - 1))}
                      disabled={quantity <= 1}
                    >
                      <Minus className="h-4 w-4" />
                    </Button>
                    <span className="px-4 py-2 border-l border-r">{quantity}</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setQuantity(quantity + 1)}
                      disabled={quantity >= (product.stock || 0)}
                    >
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>
                  <span className="text-sm text-muted-foreground">
                    In Stock: {product.stock} units
                  </span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex gap-4 mb-6">
                <Button onClick={handleAddToCart} className="flex-1 btn-secondary">
                  <ShoppingCart className="h-4 w-4 mr-2" />
                  Add to Cart
                </Button>
                <Button className="flex-1 btn-primary" onClick={async () => {
                  try {
                    // Select only this item for checkout
                    await selectSingleItem(product.id);
                    // Show success message
                    toast({
                      title: "Ready for Checkout",
                      description: `${product.name} selected for checkout`,
                    });
                    // Navigate to checkout with only this item selected
                    setLocation("/checkout");
                  } catch (error) {
                    toast({
                      title: "Error",
                      description: "Failed to prepare item for checkout",
                      variant: "destructive",
                    });
                  }
                }}>
                  Buy Now
                </Button>
                <Button variant="outline" size="icon">
                  <Heart className="h-4 w-4" />
                </Button>
              </div>

              {/* Store Info */}
              {store && (
                <div className="border-t pt-6">
                  <h3 className="font-semibold mb-3">Sold by</h3>
                  <div className="flex items-center space-x-3">
                    <div className="w-12 h-12 bg-gray-200 rounded-full flex items-center justify-center">
                      <Store className="h-6 w-6" />
                    </div>
                    <div className="flex-1">
                      <p className="font-medium">{store.name}</p>
                      <div className="flex items-center text-sm text-muted-foreground">
                        <MapPin className="h-3 w-3 mr-1" />
                        <span>
                          {storeDistance !== null 
                            ? `${storeDistance.toFixed(1)} km away` 
                            : "Distance unavailable"
                          } • {store.rating || "0.00"} ⭐ ({store.totalReviews || 0} reviews)
                        </span>
                      </div>
                    </div>
                    <Link href={`/stores/${store.id}`}>
                      <Button variant="outline" size="sm">
                        Visit Store
                      </Button>
                    </Link>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Product Reviews */}
          <div className="mt-8">
            <Separator className="mb-8" />
            <ProductReviews 
              productId={product.id} 
              productName={product.name}
            />
          </div>

          {/* Related Products */}
          {relatedProductsFiltered.length > 0 && (
            <div className="mt-12">
              <Separator className="mb-8" />
              <h2 className="text-2xl font-bold text-foreground mb-6">Related Products</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {relatedProductsFiltered.map((relatedProduct) => (
                  <ProductCard key={relatedProduct.id} product={relatedProduct} />
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
