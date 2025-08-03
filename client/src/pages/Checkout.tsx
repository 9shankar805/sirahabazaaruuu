import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { CreditCard, Truck, MapPin, Navigation, Calculator } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { useCart } from "@/hooks/useCart";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { apiPost } from "@/lib/queryClient";
import { DeliveryCalculator } from "@/components/DeliveryCalculator";
import { calculateDistance, getCoordinatesFromAddress, geocodeAddressWithValidation, getCurrentUserLocation, formatDistance } from "@/lib/distance";
import { useQuery } from "@tanstack/react-query";
import { useRef } from "react";
import { useAppSounds } from "@/hooks/useSoundEffects";

const checkoutSchema = z.object({
  customerName: z.string().min(1, "Name is required"),
  phone: z.string().min(10, "Valid phone number is required"),
  shippingAddress: z.string().min(10, "Address is required"),
  paymentMethod: z.enum(["cod", "card", "upi"]),
  latitude: z.number().optional(),
  longitude: z.number().optional(),
});

type CheckoutForm = z.infer<typeof checkoutSchema>;

export default function Checkout() {
  const [isLoading, setIsLoading] = useState(false);
  const [isGettingLocation, setIsGettingLocation] = useState(false);
  const [isCalculatingFee, setIsCalculatingFee] = useState(false);
  const [showManualAddress, setShowManualAddress] = useState(true);
  const [deliveryFee, setDeliveryFee] = useState(0);
  const [deliveryDistance, setDeliveryDistance] = useState(0);
  const [estimatedDeliveryTime, setEstimatedDeliveryTime] = useState(0);
  const [userLocation, setUserLocation] = useState<{latitude: number, longitude: number} | null>(null);
  const [deliveryInfo, setDeliveryInfo] = useState<{
    zone: any;
    estimatedTime: number;
  } | null>(null);
  const [addressSuggestions, setAddressSuggestions] = useState<any[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [selectedSuggestionIndex, setSelectedSuggestionIndex] = useState(-1);
  const suggestionsRef = useRef<HTMLDivElement>(null);
  const [, setLocation] = useLocation();
  const { cartItems, totalAmount, clearCart, clearSelectedItems, getSelectedCartItems, getSelectedTotals } = useCart();
  const { user } = useAuth();
  const { toast } = useToast();
  const appSounds = useAppSounds();

  // Use selected items for checkout
  const selectedCartItems = getSelectedCartItems();
  const { amount: selectedTotalAmount, items: selectedTotalItems } = getSelectedTotals();

  const { data: deliveryZones = [] } = useQuery({
    queryKey: ["/api/delivery-zones"],
  });

  const form = useForm<CheckoutForm>({
    resolver: zodResolver(checkoutSchema),
    defaultValues: {
      customerName: user?.fullName || "",
      phone: user?.phone || "",
      shippingAddress: "",
      paymentMethod: "cod",
      latitude: undefined,
      longitude: undefined,
    },
  });

  // Watch for address changes to fetch suggestions
  const currentAddress = form.watch("shippingAddress");
  
  // Debounced address suggestion fetching
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      if (currentAddress && !userLocation) {
        fetchAddressSuggestions(currentAddress);
      }
    }, 300);

    return () => clearTimeout(timeoutId);
  }, [currentAddress, userLocation]);

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
    form.setValue("shippingAddress", address);
    setShowSuggestions(false);
    setSelectedSuggestionIndex(-1);
    
    // Set coordinates if available
    if (suggestion.position) {
      setUserLocation({
        latitude: suggestion.position.lat,
        longitude: suggestion.position.lng
      });
      form.setValue("latitude", suggestion.position.lat);
      form.setValue("longitude", suggestion.position.lng);
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

  const handleGetLocation = async () => {
    setIsGettingLocation(true);
    try {
      const location = await getCurrentUserLocation();
      setUserLocation(location);
      
      // Set coordinates in form
      form.setValue("latitude", location.latitude);
      form.setValue("longitude", location.longitude);
      
      // Convert coordinates to readable address using HERE Maps
      const address = await reverseGeocode(location.latitude, location.longitude);
      form.setValue("shippingAddress", address);
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
    if (selectedCartItems.length === 0) return;

    setIsCalculatingFee(true);
    try {
      // Get store address from first item (assuming single store for now)
      const firstItem = selectedCartItems[0];
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
    const shippingAddress = form.getValues("shippingAddress");
    
    if (userLocation) {
      await calculateDeliveryFeeWithLocation(userLocation);
      return;
    }

    if (!shippingAddress.trim() || selectedCartItems.length === 0) return;

    setIsCalculatingFee(true);
    try {
      // Get store address from first item (assuming single store for now)
      const firstItem = selectedCartItems[0];
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
      const geocodingResult = await geocodeAddressWithValidation(shippingAddress);

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

      // Show confidence level to user and update form with formatted address
      if (geocodingResult.formattedAddress && geocodingResult.formattedAddress !== shippingAddress) {
        form.setValue("shippingAddress", geocodingResult.formattedAddress);
        toast({
          title: "Address Formatted",
          description: `Updated to: ${geocodingResult.formattedAddress}`,
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

      if (geocodingResult.confidence === 'low') {
        toast({
          title: "Address Match Found",
          description: "Please verify this location is correct before proceeding.",
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
        description: `₹${result.fee} for ${formatDistance(distance)} delivery to ${geocodingResult.formattedAddress || shippingAddress}`,
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

  const onSubmit = async (data: CheckoutForm) => {
    if (selectedCartItems.length === 0) return;

    setIsLoading(true);
    try {
      const finalTotal = selectedTotalAmount + deliveryFee;
      const orderData = {
        customerId: user?.id || null,
        totalAmount: finalTotal.toString(),
        deliveryFee: deliveryFee.toString(),
        status: "pending",
        ...data,
      };

      const orderItems = selectedCartItems.map(item => ({
        productId: item.productId,
        quantity: item.quantity,
        price: item.product?.price || "0",
        storeId: item.product?.storeId || 0,
      }));

      const response = await apiPost("/api/orders", {
        order: orderData,
        items: orderItems,
      }) as { order?: { id: number }, items?: any[] };

      // Store order ID for tracking
      if (response.order?.id) {
        localStorage.setItem('lastOrderId', response.order.id.toString());
      }

      await clearSelectedItems();
      
      // Play payment success sound
      appSounds.onPaymentSuccess();
      
      toast({
        title: "Order placed successfully!",
        description: "You will receive a confirmation email shortly.",
      });

      // Redirect with order ID in URL
      const orderParam = response.order?.id ? `?orderId=${response.order.id}` : '';
      setLocation(`/order-confirmation${orderParam}`);
    } catch (error) {
      // Play error sound for failed orders
      appSounds.onError();
      
      toast({
        title: "Error",
        description: "Failed to place order. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Redirect to login only if no user and no guest cart items
  if (!user && cartItems.length === 0) {
    setLocation("/login");
    return null;
  }

  if (selectedCartItems.length === 0) {
    setLocation("/cart");
    return null;
  }

  return (
    <div className="min-h-screen bg-muted">
      <div className="max-w-6xl mx-auto px-4 py-8">
        <h1 className="text-2xl font-bold text-foreground mb-8">Checkout</h1>
        
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 lg:gap-8">
          {/* Checkout Form */}
          <div className="lg:col-span-2">
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                {/* Delivery Address */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <MapPin className="h-5 w-5 mr-2" />
                      Delivery Address
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <FormField
                        control={form.control}
                        name="customerName"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Full Name</FormLabel>
                            <FormControl>
                              <Input placeholder="Enter your full name" {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={form.control}
                        name="phone"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Phone Number</FormLabel>
                            <FormControl>
                              <Input placeholder="Enter your phone number" {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>
                    
                    <FormField
                      control={form.control}
                      name="shippingAddress"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Complete Address</FormLabel>
                          <div className="space-y-3">
                            <div className="flex flex-wrap gap-2">
                              <Button
                                type="button"
                                variant="outline"
                                onClick={handleGetLocation}
                                disabled={isGettingLocation}
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
                                type="button"
                                variant="outline"
                                onClick={() => setShowManualAddress(!showManualAddress)}
                                className="flex items-center gap-2"
                              >
                                <MapPin className="h-4 w-4" />
                                Manual Address
                              </Button>
                              {(showManualAddress || userLocation || field.value?.trim()) && (
                                <Button
                                  type="button"
                                  variant="outline"
                                  onClick={calculateDeliveryFee}
                                  disabled={isCalculatingFee || (!field.value?.trim() && !userLocation)}
                                  className="flex items-center gap-2"
                                >
                                  <Calculator className="h-4 w-4" />
                                  {isCalculatingFee ? "Calculating..." : "Calculate Fee"}
                                </Button>
                              )}
                            </div>
                            {userLocation && (
                              <p className="text-xs text-green-600">
                                <MapPin className="h-3 w-3 inline mr-1" />
                                Using your current location
                              </p>
                            )}
                            {deliveryDistance > 0 && (
                              <p className="text-xs text-muted-foreground">
                                Distance: {formatDistance(deliveryDistance)}
                                {deliveryInfo && ` • Est. ${deliveryInfo.estimatedTime} mins`}
                              </p>
                            )}
                            {(showManualAddress || !userLocation) && (
                              <div className="relative">
                                <FormControl>
                                  <Textarea 
                                    placeholder="Enter your complete delivery address"
                                    className="min-h-20"
                                    {...field}
                                    onChange={(e) => {
                                      field.onChange(e);
                                      // Clear user location when manually typing
                                      if (e.target.value !== field.value) {
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
                                </FormControl>
                                
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
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </CardContent>
                </Card>

                {/* Payment Method */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center">
                      <CreditCard className="h-5 w-5 mr-2" />
                      Payment Method
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <FormField
                      control={form.control}
                      name="paymentMethod"
                      render={({ field }) => (
                        <FormItem>
                          <FormControl>
                            <RadioGroup
                              onValueChange={field.onChange}
                              value={field.value}
                              className="space-y-3"
                            >
                              <div className="flex items-center space-x-3 p-3 border rounded-lg cursor-pointer hover:bg-muted">
                                <RadioGroupItem value="cod" id="cod" />
                                <Label htmlFor="cod" className="flex-1 cursor-pointer">
                                  <div className="flex items-center">
                                    <Truck className="h-5 w-5 mr-3 text-green-600" />
                                    <div>
                                      <div className="font-medium">Cash on Delivery</div>
                                      <div className="text-sm text-muted-foreground">
                                        Pay when you receive your order
                                      </div>
                                    </div>
                                  </div>
                                </Label>
                              </div>
                              
                              <div className="flex items-center space-x-3 p-3 border rounded-lg cursor-pointer hover:bg-muted">
                                <RadioGroupItem value="card" id="card" />
                                <Label htmlFor="card" className="flex-1 cursor-pointer">
                                  <div className="flex items-center">
                                    <CreditCard className="h-5 w-5 mr-3 text-blue-600" />
                                    <div>
                                      <div className="font-medium">Credit/Debit Card</div>
                                      <div className="text-sm text-muted-foreground">
                                        Pay with your card securely
                                      </div>
                                    </div>
                                  </div>
                                </Label>
                              </div>
                              
                              <div className="flex items-center space-x-3 p-3 border rounded-lg cursor-pointer hover:bg-muted">
                                <RadioGroupItem value="upi" id="upi" />
                                <Label htmlFor="upi" className="flex-1 cursor-pointer">
                                  <div className="flex items-center">
                                    <div className="h-5 w-5 mr-3 bg-purple-600 rounded flex items-center justify-center text-white text-xs font-bold">
                                      U
                                    </div>
                                    <div>
                                      <div className="font-medium">UPI Payment</div>
                                      <div className="text-sm text-muted-foreground">
                                        Pay using UPI apps like eSewa, Khalti
                                      </div>
                                    </div>
                                  </div>
                                </Label>
                              </div>
                            </RadioGroup>
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </CardContent>
                </Card>

                <Button 
                  type="submit" 
                  className="w-full btn-primary"
                  disabled={isLoading || (!userLocation && !form.getValues("shippingAddress")?.trim()) || (deliveryFee === 0 && deliveryDistance === 0)}
                >
                  {isLoading ? "Placing Order..." : 
                   (!userLocation && !form.getValues("shippingAddress")?.trim()) ? "Enter Delivery Address" :
                   (deliveryFee === 0 && deliveryDistance === 0) ? "Calculate Delivery Fee" :
                   "Place Order"}
                </Button>
              </form>
            </Form>
          </div>

          {/* Order Summary */}
          <div>
            <Card className="sticky top-24">
              <CardHeader>
                <CardTitle>Order Summary</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 mb-4">
                  {selectedCartItems.map((item) => (
                    <div key={item.id} className="flex justify-between text-sm">
                      <div className="flex-1">
                        <span>{item.product?.name || "Unknown Product"}</span>
                        <span className="text-muted-foreground"> x{item.quantity}</span>
                      </div>
                      <span>₹{item.product ? (Number(item.product.price) * item.quantity).toLocaleString() : 0}</span>
                    </div>
                  ))}
                  
                  <Separator />
                  
                  <div className="flex justify-between">
                    <span>Subtotal</span>
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
                  
                  <div className="flex justify-between">
                    <span>Tax</span>
                    <span>₹0</span>
                  </div>
                  
                  <Separator />
                  
                  <div className="flex justify-between font-semibold text-lg">
                    <span>Total</span>
                    <span>
                      {deliveryFee > 0 || (userLocation || form.getValues("shippingAddress")?.trim()) ? 
                        `₹${(selectedTotalAmount + deliveryFee).toLocaleString()}` : 
                        "Enter address for total"
                      }
                    </span>
                  </div>
                </div>
                
                <div className="text-xs text-muted-foreground">
                  By placing this order, you agree to our Terms of Service and Privacy Policy.
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
