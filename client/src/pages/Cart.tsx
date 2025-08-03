import { Link } from "wouter";
import { Minus, Plus, X, ShoppingBag, MapPin, Calculator, Navigation } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { useCart } from "@/hooks/useCart";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useState, useEffect, useRef } from "react";
import { calculateDistance, getCoordinatesFromAddress, geocodeAddressWithValidation, formatDistance, getCurrentUserLocation } from "@/lib/distance";
import { useQuery } from "@tanstack/react-query";

export default function Cart() {
  const { 
    cartItems, 
    updateCartItem, 
    removeFromCart, 
    totalAmount, 
    totalItems, 
    isLoading,
    selectedItems,
    setSelectedItems,
    getSelectedCartItems,
    getSelectedTotals,
    resetSelectionState
  } = useCart();
  const { user } = useAuth();
  const { toast } = useToast();
  const [deliveryAddress, setDeliveryAddress] = useState("");
  const [showManualAddress, setShowManualAddress] = useState(false);
  const [userLocation, setUserLocation] = useState<{latitude: number, longitude: number} | null>(null);
  const [deliveryFee, setDeliveryFee] = useState(0);
  const [deliveryDistance, setDeliveryDistance] = useState(0);
  const [isCalculatingFee, setIsCalculatingFee] = useState(false);
  const [isGettingLocation, setIsGettingLocation] = useState(false);
  const [deliveryInfo, setDeliveryInfo] = useState<{
    zone: any;
    estimatedTime: number;
  } | null>(null);
  const [addressSuggestions, setAddressSuggestions] = useState<any[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [selectedSuggestionIndex, setSelectedSuggestionIndex] = useState(-1);
  const suggestionsRef = useRef<HTMLDivElement>(null);

  const { data: deliveryZones = [] } = useQuery({
    queryKey: ["/api/delivery-zones"],
  });

  // Selection helper functions
  const toggleSelectItem = (itemId: number) => {
    const newSelected = new Set(selectedItems);
    if (newSelected.has(itemId)) {
      newSelected.delete(itemId);
    } else {
      newSelected.add(itemId);
    }
    // Mark that user has made manual selections
    localStorage.setItem('cartHasSelections', 'true');
    setSelectedItems(newSelected);
  };

  const toggleSelectAll = () => {
    if (selectedItems.size === cartItems.length) {
      setSelectedItems(new Set());
    } else {
      setSelectedItems(new Set(cartItems.map(item => item.id)));
    }
    // Mark that user has made manual selections
    localStorage.setItem('cartHasSelections', 'true');
  };

  // Get selected totals
  const { amount: selectedTotalAmount, items: selectedTotalItems } = getSelectedTotals();

  // Debounced address suggestion fetching
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      if (deliveryAddress && !userLocation) {
        fetchAddressSuggestions(deliveryAddress);
      }
    }, 300);

    return () => clearTimeout(timeoutId);
  }, [deliveryAddress, userLocation]);

  // Convert coordinates to address using HERE Maps Reverse Geocoding API
  const reverseGeocode = async (lat: number, lng: number): Promise<string> => {
    try {
      const apiKey = import.meta.env.VITE_HERE_API_KEY;
      if (!apiKey) {
        throw new Error('HERE Maps API key not configured');
      }

      const response = await fetch(
        `https://revgeocode.search.hereapi.com/v1/revgeocode?at=${lat},${lng}&apikey=${apiKey}`
      );

      if (!response.ok) {
        throw new Error('Failed to reverse geocode location');
      }

      const data = await response.json();
      
      if (data.items && data.items.length > 0) {
        const address = data.items[0];
        return address.title || `${lat.toFixed(6)}, ${lng.toFixed(6)}`;
      }
      
      return `${lat.toFixed(6)}, ${lng.toFixed(6)}`;
    } catch (error) {
      console.error('Reverse geocoding error:', error);
      return `${lat.toFixed(6)}, ${lng.toFixed(6)}`;
    }
  };

  // Fetch address suggestions from HERE Maps
  const fetchAddressSuggestions = async (query: string) => {
    if (!query.trim() || query.length < 3) {
      setAddressSuggestions([]);
      setShowSuggestions(false);
      return;
    }

    try {
      const apiKey = import.meta.env.VITE_HERE_API_KEY;
      if (!apiKey) {
        console.warn('HERE Maps API key not configured');
        return;
      }

      const response = await fetch(
        `https://autosuggest.search.hereapi.com/v1/autosuggest?q=${encodeURIComponent(query)}&apikey=${apiKey}&lang=en&limit=5&resultTypes=address,place`
      );

      if (!response.ok) {
        throw new Error('Failed to fetch suggestions');
      }

      const data = await response.json();
      
      if (data.items && data.items.length > 0) {
        setAddressSuggestions(data.items);
        setShowSuggestions(true);
        setSelectedSuggestionIndex(-1);
      } else {
        setAddressSuggestions([]);
        setShowSuggestions(false);
      }
    } catch (error) {
      console.error('Error fetching address suggestions:', error);
      setAddressSuggestions([]);
      setShowSuggestions(false);
    }
  };

  // Handle suggestion selection
  const handleSuggestionSelect = (suggestion: any) => {
    const address = suggestion.title || suggestion.address?.label || '';
    setDeliveryAddress(address);
    setShowSuggestions(false);
    setSelectedSuggestionIndex(-1);
    
    // Set coordinates if available
    if (suggestion.position) {
      setUserLocation({
        latitude: suggestion.position.lat,
        longitude: suggestion.position.lng
      });
    }
  };

  // Handle keyboard navigation for suggestions
  const handleAddressKeyDown = (e: React.KeyboardEvent) => {
    if (!showSuggestions || addressSuggestions.length === 0) return;

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedSuggestionIndex(prev => 
          prev < addressSuggestions.length - 1 ? prev + 1 : 0
        );
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedSuggestionIndex(prev => 
          prev > 0 ? prev - 1 : addressSuggestions.length - 1
        );
        break;
      case 'Enter':
        e.preventDefault();
        if (selectedSuggestionIndex >= 0) {
          handleSuggestionSelect(addressSuggestions[selectedSuggestionIndex]);
        }
        break;
      case 'Escape':
        setShowSuggestions(false);
        setSelectedSuggestionIndex(-1);
        break;
    }
  };

  const handleUpdateQuantity = async (cartItemId: number, newQuantity: number) => {
    try {
      await updateCartItem(cartItemId, newQuantity);
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to update quantity",
        variant: "destructive",
      });
    }
  };

  const handleRemoveItem = async (cartItemId: number) => {
    try {
      await removeFromCart(cartItemId);
      toast({
        title: "Item removed",
        description: "Item has been removed from your cart",
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to remove item",
        variant: "destructive",
      });
    }
  };

  const getMyLocation = async () => {
    setIsGettingLocation(true);
    try {
      const location = await getCurrentUserLocation();
      setUserLocation(location);
      
      // Convert coordinates to readable address
      const address = await reverseGeocode(location.latitude, location.longitude);
      setDeliveryAddress(address);
      setShowManualAddress(true); // Show the address input after getting location
      
      toast({
        title: "Location Found",
        description: `Your location has been set to: ${address}`,
      });
      
      // Automatically calculate delivery fee
      await calculateDeliveryFeeWithLocation(location);
      
    } catch (error) {
      console.error("Error getting location:", error);
      toast({
        title: "Location Error",
        description: error instanceof Error ? error.message : "Failed to get your location. Please ensure location permission is granted.",
        variant: "destructive",
      });
    } finally {
      setIsGettingLocation(false);
    }
  };

  const calculateDeliveryFeeWithLocation = async (location: {latitude: number, longitude: number}) => {
    if (cartItems.length === 0) return;

    setIsCalculatingFee(true);
    try {
      // Get store address from first item (assuming single store for now)
      const firstItem = cartItems[0];
      if (!firstItem?.product) {
        throw new Error("Product information not available");
      }

      // Get actual store coordinates from product's store
      const storeResponse = await fetch(`/api/stores/${firstItem.product.storeId}`);
      if (!storeResponse.ok) {
        throw new Error("Failed to fetch store information");
      }
      const store = await storeResponse.json();
      
      if (!store.latitude || !store.longitude) {
        throw new Error("Store location not available");
      }

      const storeCoords = { 
        latitude: parseFloat(store.latitude), 
        longitude: parseFloat(store.longitude) 
      };

      // Calculate distance
      const distance = calculateDistance(storeCoords, location);
      setDeliveryDistance(distance);

      // Calculate fee using API
      const response = await fetch("/api/calculate-delivery-fee", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ distance }),
      });

      if (!response.ok) {
        throw new Error("Failed to calculate delivery fee");
      }

      const result = await response.json();
      setDeliveryFee(result.fee);
      setDeliveryInfo({
        zone: result.zone,
        estimatedTime: Math.round(30 + (distance * 10)) // Base 30min + 10min per km
      });

      toast({
        title: "Delivery Fee Calculated",
        description: `₹${result.fee} for ${formatDistance(distance)} delivery`,
      });

    } catch (error) {
      console.error("Error calculating delivery fee:", error);
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to calculate delivery fee",
        variant: "destructive",
      });
    } finally {
      setIsCalculatingFee(false);
    }
  };

  const calculateDeliveryFee = async () => {
    if (userLocation) {
      await calculateDeliveryFeeWithLocation(userLocation);
      return;
    }

    if (!deliveryAddress.trim() || cartItems.length === 0) return;

    setIsCalculatingFee(true);
    try {
      // Get store address from first item (assuming single store for now)
      const firstItem = cartItems[0];
      if (!firstItem?.product) {
        throw new Error("Product information not available");
      }

      // Get actual store coordinates from product's store
      const storeResponse = await fetch(`/api/stores/${firstItem.product.storeId}`);
      if (!storeResponse.ok) {
        throw new Error("Failed to fetch store information");
      }
      const store = await storeResponse.json();
      
      if (!store.latitude || !store.longitude) {
        throw new Error("Store location not available");
      }

      const storeCoords = { 
        latitude: parseFloat(store.latitude), 
        longitude: parseFloat(store.longitude) 
      };
      
      // Use enhanced geocoding with validation
      const geocodingResult = await geocodeAddressWithValidation(deliveryAddress);

      if (!geocodingResult?.coordinates) {
        // Show Google Maps link for manual verification
        toast({
          title: "Address Not Found",
          description: "Could not locate the address. Please verify on Google Maps and try again.",
          variant: "destructive",
          action: (
            <Button 
              variant="outline" 
              size="sm" 
              onClick={() => window.open(geocodingResult?.googleMapsLink, '_blank')}
            >
              View on Google Maps
            </Button>
          ),
        });
        return;
      }

      const customerCoords = geocodingResult.coordinates;

      // Show confidence level to user
      if (geocodingResult.confidence === 'low') {
        toast({
          title: "Address Match Found",
          description: `Found: ${geocodingResult.formattedAddress || deliveryAddress}. Please verify this is correct.`,
          action: (
            <Button 
              variant="outline" 
              size="sm" 
              onClick={() => window.open(geocodingResult.googleMapsLink, '_blank')}
            >
              Verify on Maps
            </Button>
          ),
        });
      }

      // Calculate distance
      const distance = calculateDistance(storeCoords, customerCoords);
      setDeliveryDistance(distance);

      // Calculate fee using API
      const response = await fetch("/api/calculate-delivery-fee", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ distance }),
      });

      if (!response.ok) {
        throw new Error("Failed to calculate delivery fee");
      }

      const result = await response.json();
      setDeliveryFee(result.fee);
      setDeliveryInfo({
        zone: result.zone,
        estimatedTime: Math.round(30 + (distance * 10)) // Base 30min + 10min per km
      });

      toast({
        title: "Delivery Fee Calculated",
        description: `₹${result.fee} for ${formatDistance(distance)} delivery to ${geocodingResult.formattedAddress || deliveryAddress}`,
      });

    } catch (error) {
      console.error("Error calculating delivery fee:", error);
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to calculate delivery fee",
        variant: "destructive",
      });
    } finally {
      setIsCalculatingFee(false);
    }
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-muted flex items-center justify-center">
        <Card className="w-full max-w-md mx-4">
          <CardContent className="pt-6 text-center">
            <ShoppingBag className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
            <h2 className="text-xl font-semibold mb-2">Please Login</h2>
            <p className="text-muted-foreground mb-4">
              You need to login to view your cart
            </p>
            <Link href="/login">
              <Button className="w-full">Login</Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-muted flex items-center justify-center">
        <div>Loading cart...</div>
      </div>
    );
  }

  if (cartItems.length === 0) {
    return (
      <div className="min-h-screen bg-muted">
        <div className="max-w-4xl mx-auto px-4 py-8">
          <Card>
            <CardContent className="pt-6 text-center">
              <ShoppingBag className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
              <h2 className="text-xl font-semibold mb-2">Your cart is empty</h2>
              <p className="text-muted-foreground mb-4">
                Looks like you haven't added anything to your cart yet
              </p>
              <Link href="/products">
                <Button>Continue Shopping</Button>
              </Link>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-muted">
      <div className="max-w-6xl mx-auto px-4 py-8">
        <h1 className="text-2xl font-bold text-foreground mb-8">Shopping Cart</h1>
        
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 lg:gap-8">
          {/* Cart Items */}
          <div className="lg:col-span-2">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle>Cart Items ({totalItems})</CardTitle>
                  <div className="flex items-center space-x-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        resetSelectionState();
                        toast({
                          title: "Selection Reset",
                          description: "Cart selection state has been reset. Try selecting items now.",
                        });
                      }}
                      className="text-xs"
                    >
                      Reset Selection
                    </Button>
                    <Checkbox
                      id="select-all"
                      checked={selectedItems.size === cartItems.length && cartItems.length > 0}
                      onCheckedChange={toggleSelectAll}
                    />
                    <Label htmlFor="select-all" className="text-sm font-medium">
                      Select All
                    </Label>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {cartItems.map((item) => (
                  <div key={item.id} className="flex flex-col sm:flex-row items-start sm:items-center space-y-3 sm:space-y-0 sm:space-x-4 p-3 sm:p-4 border rounded-lg">
                    <div className="flex items-center space-x-3 w-full sm:w-auto">
                      <Checkbox
                        id={`item-${item.id}`}
                        checked={selectedItems.has(item.id)}
                        onCheckedChange={() => toggleSelectItem(item.id)}
                        className="flex-shrink-0"
                      />
                      <img
                        src={item.product?.images?.[0] || "https://images.unsplash.com/photo-1560472354-b33ff0c44a43?ixlib=rb-4.0.3&auto=format&fit=crop&w=100&h=100"}
                        alt={item.product?.name || "Product"}
                        className="w-16 h-16 sm:w-20 sm:h-20 object-cover rounded-lg flex-shrink-0"
                      />
                      
                      <div className="flex-1 min-w-0">
                        <h3 className="font-medium text-foreground text-sm sm:text-base line-clamp-2">
                          {item.product?.name || "Unknown Product"}
                        </h3>
                        <p className="text-primary font-semibold text-sm sm:text-base">
                          ₹{item.product ? Number(item.product.price).toLocaleString() : 0}
                        </p>
                      </div>
                      
                      {/* Mobile Remove Button */}
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleRemoveItem(item.id)}
                        className="text-destructive hover:text-destructive sm:hidden"
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    </div>
                    
                    <div className="flex items-center justify-between w-full sm:w-auto sm:justify-end sm:space-x-4">
                      <div className="flex items-center space-x-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleUpdateQuantity(item.id, item.quantity - 1)}
                          disabled={item.quantity <= 1}
                          className="h-8 w-8 p-0"
                        >
                          <Minus className="h-3 w-3" />
                        </Button>
                        <span className="w-8 text-center text-sm font-medium">{item.quantity}</span>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleUpdateQuantity(item.id, item.quantity + 1)}
                          disabled={item.quantity >= (item.product?.stock || 0)}
                          className="h-8 w-8 p-0"
                        >
                          <Plus className="h-3 w-3" />
                        </Button>
                      </div>
                      
                      <div className="flex items-center space-x-3">
                        <p className="font-semibold text-sm sm:text-base">
                          ₹{item.product ? (Number(item.product.price) * item.quantity).toLocaleString() : 0}
                        </p>
                        
                        {/* Desktop Remove Button */}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleRemoveItem(item.id)}
                          className="text-destructive hover:text-destructive hidden sm:flex"
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {/* Order Summary */}
          <div>
            <Card className="sticky top-24">
              <CardHeader>
                <CardTitle>Order Summary</CardTitle>
              </CardHeader>
              <CardContent>
                {/* Delivery Address Input */}
                <div className="space-y-3 mb-4">
                  <div>
                    <Label htmlFor="delivery-address" className="text-sm font-medium">
                      Delivery Address
                    </Label>
                    <div className="flex flex-wrap gap-2 mt-1">
                      <Button
                        onClick={getMyLocation}
                        disabled={isGettingLocation}
                        size="sm"
                        variant="outline"
                        className="flex items-center gap-2"
                      >
                        {isGettingLocation ? (
                          <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
                        ) : (
                          <Navigation className="h-4 w-4" />
                        )}
                        {isGettingLocation ? "Getting Location..." : "Get My Location"}
                      </Button>
                      <Button
                        onClick={() => setShowManualAddress(!showManualAddress)}
                        size="sm"
                        variant="outline"
                        className="flex items-center gap-2"
                      >
                        <MapPin className="h-4 w-4" />
                        Manual Address
                      </Button>
                      {(showManualAddress || userLocation || deliveryAddress.trim()) && (
                        <Button
                          onClick={calculateDeliveryFee}
                          disabled={isCalculatingFee || (!deliveryAddress.trim() && !userLocation)}
                          size="sm"
                          variant="outline"
                          className="flex items-center gap-2"
                        >
                          <Calculator className="h-4 w-4" />
                          {isCalculatingFee ? "Calculating..." : "Calculate Fee"}
                        </Button>
                      )}
                    </div>
                    {userLocation && (
                      <p className="text-xs text-green-600 mt-1">
                        <MapPin className="h-3 w-3 inline mr-1" />
                        Using your current location
                      </p>
                    )}
                    {deliveryDistance > 0 && (
                      <p className="text-xs text-muted-foreground mt-1">
                        Distance: {formatDistance(deliveryDistance)}
                        {deliveryInfo && ` • Est. ${deliveryInfo.estimatedTime} mins`}
                      </p>
                    )}
                    {showManualAddress && (
                      <div className="relative mt-2">
                        <Input
                          id="delivery-address"
                          placeholder="Enter your complete delivery address"
                          value={deliveryAddress}
                          onChange={(e) => {
                            setDeliveryAddress(e.target.value);
                            // Clear user location when manually typing
                            if (e.target.value !== deliveryAddress) {
                              setUserLocation(null);
                            }
                          }}
                          onKeyDown={handleAddressKeyDown}
                          onFocus={() => {
                            if (addressSuggestions.length > 0) {
                              setShowSuggestions(true);
                            }
                          }}
                          onBlur={() => {
                            // Delay hiding suggestions to allow for clicks
                            setTimeout(() => setShowSuggestions(false), 200);
                          }}
                        />
                        
                        {/* Address Suggestions Dropdown */}
                        {showSuggestions && addressSuggestions.length > 0 && (
                          <div 
                            ref={suggestionsRef}
                            className="absolute z-50 w-full mt-1 bg-background border border-border rounded-md shadow-lg max-h-60 overflow-y-auto"
                          >
                            {addressSuggestions.map((suggestion, index) => (
                              <div
                                key={index}
                                className={`px-3 py-2 cursor-pointer text-sm hover:bg-muted transition-colors ${
                                  index === selectedSuggestionIndex ? 'bg-muted' : ''
                                }`}
                                onClick={() => handleSuggestionSelect(suggestion)}
                                onMouseEnter={() => setSelectedSuggestionIndex(index)}
                              >
                                <div className="font-medium">
                                  {suggestion.title}
                                </div>
                                {suggestion.address?.label && suggestion.address.label !== suggestion.title && (
                                  <div className="text-xs text-muted-foreground">
                                    {suggestion.address.label}
                                  </div>
                                )}
                                {suggestion.resultType && (
                                  <div className="text-xs text-primary mt-1">
                                    {suggestion.resultType === 'place' ? '📍 Place' : '🏠 Address'}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                <Separator className="my-4" />

                <div className="space-y-3 mb-4">
                  {selectedItems.size < cartItems.length && (
                    <div className="text-xs text-muted-foreground p-2 bg-muted rounded">
                      Selected {selectedItems.size} of {cartItems.length} items
                    </div>
                  )}
                  <div className="flex justify-between">
                    <span>Subtotal ({selectedTotalItems} items)</span>
                    <span>₹{selectedTotalAmount.toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Delivery Fee</span>
                    <span className={deliveryFee > 0 ? "text-foreground" : "text-muted-foreground"}>
                      {deliveryFee > 0 ? `₹${deliveryFee.toLocaleString()}` : "Enter address to calculate"}
                    </span>
                  </div>
                  {deliveryInfo?.zone && (
                    <div className="text-xs text-muted-foreground">
                      Zone: {deliveryInfo.zone.name}
                    </div>
                  )}
                  <Separator />
                  <div className="flex justify-between font-semibold text-lg">
                    <span>Total</span>
                    <span>
                      {deliveryFee > 0 || (userLocation || deliveryAddress.trim()) ? 
                        `₹${(selectedTotalAmount + deliveryFee).toLocaleString()}` : 
                        "Enter address for total"
                      }
                    </span>
                  </div>
                </div>
                
                <Link href="/checkout">
                  <Button 
                    className="w-full btn-primary" 
                    disabled={selectedItems.size === 0}
                  >
                    Proceed to Checkout ({selectedItems.size} items)
                  </Button>
                </Link>
                {selectedItems.size === 0 && (
                  <p className="text-xs text-muted-foreground text-center">
                    Select at least one item to proceed
                  </p>
                )}
                
                <Link href="/products">
                  <Button variant="outline" className="w-full mt-3">
                    Continue Shopping
                  </Button>
                </Link>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
