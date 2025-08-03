import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { 
  Package,
  ShoppingCart,
  DollarSign,
  Star,
  Plus,
  Edit,
  Trash2,
  Eye,
  TrendingUp,
  Users,
  Clock,
  MapPin,
  UtensilsCrossed,
  Navigation,
  Send,
  Bell,
  CheckCircle,
  AlertCircle,
  Timer,
  Truck,
  Phone,
  Store,
  Home,
  Archive,
  X,
  Upload,
  Camera,
  Calculator as CalculatorIcon,
} from "lucide-react";
import { Calculator } from "@/components/Calculator";
import type { CalculatorProduct } from "@/types/calculator";
// Using the existing Product interface from the file
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { apiGet, apiPost, apiPut, apiDelete } from "@/lib/queryClient";
import { queryClient } from "@/lib/queryClient";
import ImageUpload from "@/components/ImageUpload";
import { UnifiedImageUpload } from "@/components/UnifiedImageUpload";
import { LocationPicker } from "@/components/LocationPicker";
import type {
  Product,
  Order as BaseOrder,
  OrderItem as BaseOrderItem,
  Store as StoreType,
  Category,
} from "@shared/schema";

// Extended OrderItem interface to include product details from API
interface OrderItem extends BaseOrderItem {
  product?: {
    id: number;
    name: string;
    price: number | string;
    imageUrl?: string;
    images?: string[];
    description?: string;
    category?: string;
  };
}

interface DeliveryPartner {
  id: number;
  name: string;
  phone: string;
  email?: string;
}

interface Order extends BaseOrder {
  deliveryPartner?: DeliveryPartner;
  items?: OrderItem[];
  [key: string]: any; // For any additional properties
}

import { LeafletDeliveryMap } from "@/components/tracking/LeafletDeliveryMap";
import { LocationTracker } from "@/components/LocationTracker";
import { DeliveryTrackingMap } from "@/components/tracking/DeliveryTrackingMap";

const productSchema = z.object({
  name: z.string().min(1, "Product name is required"),
  description: z.string().optional(),
  price: z.string().min(1, "Price is required"),
  originalPrice: z.string().optional(),
  categoryId: z.number().min(1, "Category is required"),
  stock: z.number().min(0, "Stock must be 0 or greater"),
  imageUrl: z.string().optional(),
  images: z
    .array(z.string())
    .min(1, "At least 1 image is required")
    .max(6, "Maximum 6 images allowed"),
  isFastSell: z.boolean().default(false),
  isOnOffer: z.boolean().default(false),
  offerPercentage: z.number().min(0).max(100).default(0),
  offerEndDate: z.string().optional(),
  productType: z.enum(["retail", "food"]).default("retail"),
  // Food-specific fields
  preparationTime: z.string().optional(),
  ingredients: z.array(z.string()).default([]),
  allergens: z.array(z.string()).default([]),
  spiceLevel: z.string().optional(),
  isVegetarian: z.boolean().default(false),
  isVegan: z.boolean().default(false),
  nutritionInfo: z.string().optional(),
});

const storeSchema = z.object({
  name: z.string().min(1, "Store name is required"),
  description: z.string().optional(),
  address: z.string().min(1, "Address is required"),
  latitude: z.string().optional(),
  longitude: z.string().optional(),
  phone: z.string().optional(),
  website: z.string().url().optional().or(z.literal("")),
  logo: z.string().optional(),
  coverImage: z.string().optional(),
  storeType: z.enum(["retail", "restaurant"]).default("retail"),
  cuisineType: z.string().optional(),
  deliveryTime: z.string().optional(),
  minimumOrder: z.string().optional(),
  deliveryFee: z.string().optional(),
  isDeliveryAvailable: z.boolean().default(false),
  openingHours: z.string().optional(),
});

type ProductForm = z.infer<typeof productSchema>;
type StoreForm = z.infer<typeof storeSchema>;

export default function ShopkeeperDashboard() {
  const [activeTab, setActiveTab] = useState("overview");
  const [editingProduct, setEditingProduct] = useState<Product | null>(null);
  const [storeLocation, setStoreLocation] = useState<{
    latitude: number;
    longitude: number;
  } | null>(null);
  const [locationLoading, setLocationLoading] = useState(false);
  const [notificationHistory, setNotificationHistory] = useState<any[]>([]);
  const [pendingDeliveries, setPendingDeliveries] = useState<any[]>([]);
  const [showAddProductModal, setShowAddProductModal] = useState(false);
  const [ingredients, setIngredients] = useState<string[]>([]);
  const [allergens, setAllergens] = useState<string[]>([]);
  const [newIngredient, setNewIngredient] = useState("");
  const [newAllergen, setNewAllergen] = useState("");
  const [isEditStoreOpen, setIsEditStoreOpen] = useState(false);
  const [isCalculatorOpen, setIsCalculatorOpen] = useState(false);
  const [calculatorProducts, setCalculatorProducts] = useState<CalculatorProduct[]>([]);
  const { toast } = useToast();
  const { user } = useAuth();

  // Helper functions for ingredients and allergens
  const handleAddIngredient = () => {
    if (newIngredient.trim() && !ingredients.includes(newIngredient.trim())) {
      const updated = [...ingredients, newIngredient.trim()];
      setIngredients(updated);
      form.setValue("ingredients", updated);
      setNewIngredient("");
    }
  };

  const handleRemoveIngredient = (ingredient: string) => {
    const updated = ingredients.filter(i => i !== ingredient);
    setIngredients(updated);
    form.setValue("ingredients", updated);
  };

  const handleAddAllergen = () => {
    if (newAllergen.trim() && !allergens.includes(newAllergen.trim())) {
      const updated = [...allergens, newAllergen.trim()];
      setAllergens(updated);
      form.setValue("allergens", updated);
      setNewAllergen("");
    }
  };

  const handleRemoveAllergen = (allergen: string) => {
    const updated = allergens.filter(a => a !== allergen);
    setAllergens(updated);
    form.setValue("allergens", updated);
  };





  // Queries
  const { data: stores = [] } = useQuery<StoreType[]>({
    queryKey: ['stores', user?.id],
    queryFn: async () => {
      if (!user?.id) return [];
      const response = await fetch(`/api/stores/owner/${user.id}`);
      if (!response.ok) throw new Error("Failed to fetch stores");
      const data = await response.json();
      return Array.isArray(data) ? data : [];
    },
    enabled: !!user,
  });

  const currentStore = stores[0]; // Assuming one store per shopkeeper

  // Fetch products with React Query for the calculator
  const { data: productsData, isLoading: isLoadingProducts } = useQuery<Product[]>({
    // Note: It's better to type the query itself.
    queryKey: ['all-products-for-calculator', currentStore?.id],
    queryFn: async () => {
      if (!currentStore?.id) return [];
      try {
        console.log(`Fetching products for calculator from /api/products/store/${currentStore.id}`);
        const data = await apiGet(`/api/products/store/${currentStore.id}`);
        console.log('Calculator products API response:', data);
        // The store products endpoint returns the array directly
        return Array.isArray(data) ? data : [];
      } catch (error) {
        console.error('Error fetching products for calculator:', error);
        toast({
          title: 'Error Loading Products',
          description: 'Could not fetch products for the calculator. Please try again.',
          variant: 'destructive',
        });
        return [];
      }
    },
    enabled: !!currentStore?.id, // Only run query if currentStore is available
  });

  useEffect(() => {
    if (productsData) {
      console.log('productsData in SellerDashboard changed:', {
        sample: productsData.slice(0, 3)
      });
    }
  }, [productsData]);

  useEffect(() => {
    if (productsData && productsData.length > 0) {
      console.log('Formatting products for calculator:', productsData);
      try {
        const formattedProducts = productsData.map((product) => ({
          id: product.id,
          name: product.name || 'Unnamed Product',
          price: typeof product.price === 'string' ? parseFloat(product.price) : product.price || 0,
          description: product.description || '',
          stock: product.stock || 0,
          taxRate: (product as any).taxRate || 0, // Handle missing taxRate
          imageUrl: product.imageUrl || (product.images && product.images[0]) || '',
        }));
        console.log('Formatted products for calculator:', formattedProducts);
        setCalculatorProducts(formattedProducts);
      } catch (error) {
        console.error('Error formatting products for calculator:', error);
      }
    } else {
      console.log('No products data available for calculator');
      setCalculatorProducts([]);
    }
  }, [productsData]);

  // Enhanced restaurant detection
  const isRestaurant = currentStore?.storeType === 'restaurant' || 
    (currentStore?.name && currentStore.name.toLowerCase().includes('restaurant'));

  const { data: products = [] } = useQuery<Product[]>({
    queryKey: ['store-products', currentStore?.id],
    queryFn: async () => {
      if (!currentStore?.id) return [];
      const response = await fetch(`/api/products/store/${currentStore.id}`);
      if (!response.ok) throw new Error("Failed to fetch store products");
      const data = await response.json();
      return Array.isArray(data) ? data : [];
    },
    enabled: !!currentStore?.id,
  });

  const { data: orders = [] } = useQuery<(Order & { items: OrderItem[] })[]>({
    queryKey: ['store-orders', currentStore?.id],
    queryFn: async () => {
      if (!currentStore?.id) return [];
      const response = await fetch(`/api/orders/store/${currentStore.id}`);
      if (!response.ok) throw new Error("Failed to fetch store orders");
      const data = await response.json();
      return Array.isArray(data) ? data : [];
    },
    enabled: !!currentStore?.id,
    refetchInterval: 30000, // Refetch every 30 seconds
    refetchOnWindowFocus: true,
  });

  const { data: categories = [] } = useQuery<Category[]>({
    queryKey: ["/api/categories"],
  });

  // Get available delivery partners with user details
  const { data: deliveryPartners = [] } = useQuery({
    queryKey: ["/api/delivery-partners"],
    queryFn: async () => {
      const response = await fetch("/api/delivery-partners");
      if (!response.ok) throw new Error("Failed to fetch delivery partners");
      const partners = await response.json();

      // Get user details for each partner
      const usersResponse = await fetch("/api/users");
      const users = usersResponse.ok ? await usersResponse.json() : [];

      return partners.map((partner: any) => {
        const user = users.find((u: any) => u.id === partner.userId);
        return {
          ...partner,
          name: user?.fullName || `Partner ${partner.id}`,
          email: user?.email || "No email",
        };
      });
    },
  });

  // Form for adding/editing products
  const form = useForm<ProductForm>({
    resolver: zodResolver(productSchema),
    defaultValues: {
      name: "",
      description: "",
      price: "",
      originalPrice: "",
      categoryId: 1,
      stock: 0,
      imageUrl: "",
      images: [],
      isFastSell: false,
      isOnOffer: false,
      offerPercentage: 0,
      offerEndDate: "",
      preparationTime: "",
      ingredients: [],
      allergens: [],
      spiceLevel: "",
      isVegetarian: false,
      isVegan: false,
      nutritionInfo: "",
    },
  });

  // Get user's current location for store
  const getMyLocation = () => {
    if (navigator.geolocation) {
      setLocationLoading(true);
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const location = {
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
          };
          setStoreLocation(location);
          setLocationLoading(false);
          toast({
            title: "Location captured successfully",
            description: `Lat: ${location.latitude.toFixed(6)}, Lon: ${location.longitude.toFixed(6)}`,
          });
        },
        (error) => {
          setLocationLoading(false);
          toast({
            title: "Location access denied",
            description:
              "Please enable location access or enter coordinates manually",
            variant: "destructive",
          });
          console.error("Error getting location:", error);
        },
      );
    } else {
      toast({
        title: "Location not supported",
        description: "Your browser doesn't support geolocation",
        variant: "destructive",
      });
    }
  };

  // Form for creating stores
  const storeForm = useForm<StoreForm>({
    resolver: zodResolver(storeSchema),
    defaultValues: {
      name: "",
      description: "",
      address: "",
      latitude: "",
      longitude: "",
      phone: "",
      website: "",
      logo: "",
      coverImage: "",
      storeType: "retail",
      cuisineType: "",
      deliveryTime: "",
      minimumOrder: "",
      deliveryFee: "",
      isDeliveryAvailable: false,
      openingHours: "",
    },
  });

  const editStoreForm = useForm<StoreForm>({
    resolver: zodResolver(storeSchema),
    defaultValues: {
      name: "",
      description: "",
      address: "",
      latitude: "",
      longitude: "",
      phone: "",
      website: "",
      logo: "",
      coverImage: "",
      storeType: "retail",
      cuisineType: "",
      deliveryTime: "",
      minimumOrder: "",
      deliveryFee: "",
      isDeliveryAvailable: false,
      openingHours: "",
    },
  });

  // Stats calculations
  const totalOrders = orders.length;
  const totalProducts = products.length;
  const totalRevenue = orders.reduce(
    (sum, order) => sum + Number(order.totalAmount),
    0,
  );
  const pendingOrders = orders.filter(
    (order) => order.status === "pending",
  ).length;

  const handleAddProduct = async (data: ProductForm) => {
    if (!currentStore) return;

    try {
      const productData = {
        ...data,
        storeId: currentStore.id,
        price: data.price,
        originalPrice: data.originalPrice || undefined,
        images: data.images || [],
        imageUrl: data.images?.[0] || undefined,
        isFastSell: data.isFastSell || false,
        isOnOffer: data.isOnOffer || false,
        offerPercentage: data.offerPercentage || 0,
        offerEndDate: data.offerEndDate || undefined,
        productType: (currentStore?.storeType === 'restaurant' || 
          (currentStore?.name && currentStore.name.toLowerCase().includes('restaurant'))) ? "food" : "retail",
        // Food-specific fields for restaurants
        preparationTime: (currentStore?.storeType === 'restaurant' || 
          (currentStore?.name && currentStore.name.toLowerCase().includes('restaurant'))) ? data.preparationTime || null : null,
        ingredients: (currentStore?.storeType === 'restaurant' || 
          (currentStore?.name && currentStore.name.toLowerCase().includes('restaurant'))) ? ingredients : [],
        allergens: (currentStore?.storeType === 'restaurant' || 
          (currentStore?.name && currentStore.name.toLowerCase().includes('restaurant'))) ? allergens : [],
        spiceLevel: (currentStore?.storeType === 'restaurant' || 
          (currentStore?.name && currentStore.name.toLowerCase().includes('restaurant'))) ? data.spiceLevel || null : null,
        isVegetarian: (currentStore?.storeType === 'restaurant' || 
          (currentStore?.name && currentStore.name.toLowerCase().includes('restaurant'))) ? data.isVegetarian || false : false,
        isVegan: (currentStore?.storeType === 'restaurant' || 
          (currentStore?.name && currentStore.name.toLowerCase().includes('restaurant'))) ? data.isVegan || false : false,
        nutritionInfo: (currentStore?.storeType === 'restaurant' || 
          (currentStore?.name && currentStore.name.toLowerCase().includes('restaurant'))) ? data.nutritionInfo || null : null,
      };

      if (editingProduct) {
        await apiPut(`/api/products/${editingProduct.id}`, productData);
        toast({ title: "Product updated successfully" });
      } else {
        await apiPost("/api/products", productData);
        toast({ title: "Product added successfully" });
      }

      form.reset();
      setEditingProduct(null);
      setShowAddProductModal(false);
      // Invalidate queries to refresh data
      queryClient.invalidateQueries({
        queryKey: [`/api/products/store/${currentStore.id}`],
      });
      queryClient.invalidateQueries({ queryKey: ["/api/products"] });
    } catch (error) {
      toast({
        title: "Error",
        description:
          error instanceof Error ? error.message : "Failed to save product",
        variant: "destructive",
      });
    }
  };

  const handleEditProduct = (product: Product) => {
    setEditingProduct(product);
    form.reset({
      name: product.name,
      description: product.description || "",
      price: product.price,
      originalPrice: product.originalPrice || "",
      categoryId: product.categoryId || 0,
      stock: product.stock || 0,
      imageUrl: product.images?.[0] || "",
      images: product.images || [],
      isFastSell: product.isFastSell || false,
      isOnOffer: product.isOnOffer || false,
      offerPercentage: product.offerPercentage || 0,
      offerEndDate: product.offerEndDate || "",
    });
    setActiveTab("add-product");
  };

  const handleDeleteProduct = async (productId: number) => {
    if (!confirm("Are you sure you want to delete this product?")) return;

    try {
      await apiDelete(`/api/products/${productId}`);
      toast({ title: "Product deleted successfully" });
      // Invalidate queries to refresh data
      if (currentStore) {
        queryClient.invalidateQueries({
          queryKey: [`/api/products/store/${currentStore.id}`],
        });
        queryClient.invalidateQueries({ queryKey: ["/api/products"] });
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to delete product",
        variant: "destructive",
      });
    }
  };

  const handleCreateStore = async (data: StoreForm) => {
    try {
      const storeData = {
        ...data,
        ownerId: user!.id,
        phone: data.phone || null,
        description: data.description || null,
        website: data.website || null,
        logo: data.logo || null,
        coverImage: data.coverImage || null,
        latitude: data.latitude || null,
        longitude: data.longitude || null,
        storeType: data.storeType,
        cuisineType:
          data.storeType === "restaurant" ? data.cuisineType || null : null,
        deliveryTime:
          data.storeType === "restaurant" ? data.deliveryTime || null : null,
        minimumOrder:
          data.storeType === "restaurant" && data.minimumOrder
            ? data.minimumOrder
            : null,
        deliveryFee:
          data.storeType === "restaurant" && data.deliveryFee
            ? data.deliveryFee
            : null,
        isDeliveryAvailable:
          data.storeType === "restaurant" ? data.isDeliveryAvailable : false,
        openingHours:
          data.storeType === "restaurant" ? data.openingHours || null : null,
      };

      await apiPost("/api/stores", storeData);
      toast({ title: "Store created successfully" });
      storeForm.reset();
      queryClient.invalidateQueries({ queryKey: ["/api/stores"] });
      queryClient.invalidateQueries({
        queryKey: ["/api/stores", "owner", user!.id],
      });
    } catch (error) {
      toast({
        title: "Error",
        description:
          error instanceof Error ? error.message : "Failed to create store",
        variant: "destructive",
      });
    }
  };

  // Store update handler
  const handleUpdateStore = async (data: StoreForm) => {
    if (!currentStore?.id) return;
    
    try {
      const storeData = {
        ...data,
        minimumOrder: data.minimumOrder || null,
        deliveryFee: data.deliveryFee || null,
        latitude: storeLocation?.latitude?.toString() || data.latitude,
        longitude: storeLocation?.longitude?.toString() || data.longitude,
      };

      await apiPut(`/api/stores/${currentStore.id}`, storeData);
      
      queryClient.invalidateQueries({ queryKey: [`/api/stores/owner`, user?.id] });
      
      setIsEditStoreOpen(false);
      toast({
        title: "Success",
        description: "Store updated successfully",
      });
    } catch (error) {
      console.error("Store update error:", error);
      toast({
        title: "Error",
        description: "Failed to update store",
        variant: "destructive",
      });
    }
  };

  // Open edit store dialog
  const openEditStoreDialog = () => {
    if (currentStore) {
      editStoreForm.reset({
        name: currentStore.name || "",
        description: currentStore.description || "",
        address: currentStore.address || "",
        latitude: currentStore.latitude || "",
        longitude: currentStore.longitude || "",
        phone: currentStore.phone || "",
        website: currentStore.website || "",
        logo: currentStore.logo || "",
        coverImage: currentStore.coverImage || "",
        storeType: currentStore.storeType === "restaurant" ? "restaurant" : "retail",
        cuisineType: currentStore.cuisineType || "",
        deliveryTime: currentStore.deliveryTime || "",
        minimumOrder: currentStore.minimumOrder?.toString() || "",
        deliveryFee: currentStore.deliveryFee?.toString() || "",
        isDeliveryAvailable: Boolean(currentStore.isDeliveryAvailable),
        openingHours: currentStore.openingHours || "",
      });
      setIsEditStoreOpen(true);
    }
  };

  const handleOrderStatusUpdate = async (orderId: number, status: string) => {
    try {
      await apiPut(`/api/orders/${orderId}/status`, { status });
      toast({ title: "Order status updated successfully" });

      // Invalidate all related queries
      queryClient.invalidateQueries({
        queryKey: [`/api/orders/store/${currentStore?.id}`],
      });
      queryClient.invalidateQueries({ queryKey: [`/api/orders/store`] });
      queryClient.invalidateQueries({ queryKey: ["/api/orders"] });

      // Force refetch immediately
      if (currentStore?.id) {
        queryClient.refetchQueries({
          queryKey: [`/api/orders/store/${currentStore.id}`],
        });
      }
    } catch (error) {
      console.error("Order status update error:", error);
      toast({
        title: "Error",
        description: "Failed to update order status",
        variant: "destructive",
      });
    }
  };

  const handleNotifyDeliveryPartner = async (
    orderId: number,
    message: string,
    urgent: boolean = false,
  ) => {
    try {
      const response = await apiPost("/api/notifications/delivery-assignment", {
        orderId,
        message,
        storeId: currentStore?.id,
        shopkeeperId: user?.id,
        urgent,
        notificationType: "first_accept_first_serve",
      });

      // Add to notification history
      const newNotification = {
        id: Date.now(),
        orderId,
        message,
        urgent,
        sentAt: new Date().toISOString(),
        status: "sent",
        acceptedBy: null,
      };
      setNotificationHistory((prev) => [newNotification, ...prev]);

      toast({
        title: urgent
          ? "Urgent delivery notification sent"
          : "Delivery notification sent",
        description: "All available delivery partners have been notified",
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to notify delivery partners",
        variant: "destructive",
      });
    }
  };

  const handleBroadcastNotification = async (
    message: string,
    targetOrders: number[],
  ) => {
    try {
      await apiPost("/api/notifications/broadcast-delivery", {
        message,
        orderIds: targetOrders,
        storeId: currentStore?.id,
        shopkeeperId: user?.id,
      });

      toast({
        title: "Broadcast notification sent",
        description: `Notified delivery partners about ${targetOrders.length} orders`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to send broadcast notification",
        variant: "destructive",
      });
    }
  };



  if (!user || user.role !== "shopkeeper") {
    return (
      <div className="min-h-screen bg-muted flex items-center justify-center">
        <Card className="w-full max-w-md">
          <CardContent className="pt-6 text-center">
            <h2 className="text-xl font-semibold mb-2">Access Denied</h2>
            <p className="text-muted-foreground">
              This page is only accessible to shopkeepers.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-muted">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold text-foreground">
              Shopkeeper Dashboard
            </h1>
            <p className="text-muted-foreground">
              {currentStore
                ? `Managing ${currentStore.name}`
                : "Manage your store"}
            </p>
          </div>
          <Button 
            variant="ghost" 
            size="icon" 
            onClick={() => setIsCalculatorOpen(true)}
            title="Calculator"
          >
            <CalculatorIcon className="h-5 w-5" />
          </Button>
          {isCalculatorOpen && (
            <Calculator 
              isOpen={isCalculatorOpen} 
              onClose={() => setIsCalculatorOpen(false)}
              products={calculatorProducts}
            />
          )}
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList
            className={`grid w-full gap-2 h-auto p-2 bg-white dark:bg-gray-800 rounded-lg ${currentStore ? "grid-cols-2 md:grid-cols-4" : "grid-cols-2"}`}
          >
            <TabsTrigger 
              value="overview" 
              className="flex flex-col items-center gap-1 p-3 text-xs font-medium data-[state=active]:bg-orange-100 data-[state=active]:text-orange-600 dark:data-[state=active]:bg-orange-900 dark:data-[state=active]:text-orange-400"
            >
              <Home className="h-5 w-5" />
              <span className="hidden sm:inline">Overview</span>
            </TabsTrigger>
            {!currentStore && (
              <TabsTrigger 
                value="create-store"
                className="flex flex-col items-center gap-1 p-3 text-xs font-medium data-[state=active]:bg-orange-100 data-[state=active]:text-orange-600 dark:data-[state=active]:bg-orange-900 dark:data-[state=active]:text-orange-400"
              >
                <Store className="h-5 w-5" />
                <span className="hidden sm:inline">Create Store</span>
              </TabsTrigger>
            )}
            {currentStore && (
              <>
                <TabsTrigger 
                  value="analytics"
                  className="flex flex-col items-center gap-1 p-3 text-xs font-medium data-[state=active]:bg-orange-100 data-[state=active]:text-orange-600 dark:data-[state=active]:bg-orange-900 dark:data-[state=active]:text-orange-400"
                >
                  <TrendingUp className="h-5 w-5" />
                  <span className="hidden sm:inline">Analytics</span>
                </TabsTrigger>
                <TabsTrigger 
                  value="orders"
                  className="flex flex-col items-center gap-1 p-3 text-xs font-medium data-[state=active]:bg-orange-100 data-[state=active]:text-orange-600 dark:data-[state=active]:bg-orange-900 dark:data-[state=active]:text-orange-400"
                >
                  <ShoppingCart className="h-5 w-5" />
                  <span className="hidden sm:inline">Orders</span>
                </TabsTrigger>
                <TabsTrigger 
                  value="notifications"
                  className="flex flex-col items-center gap-1 p-3 text-xs font-medium data-[state=active]:bg-orange-100 data-[state=active]:text-orange-600 dark:data-[state=active]:bg-orange-900 dark:data-[state=active]:text-orange-400"
                >
                  <Bell className="h-5 w-5" />
                  <span className="hidden sm:inline">Notifications</span>
                </TabsTrigger>
              </>
            )}
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-6">
            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">
                        Total Products
                      </p>
                      <p className="text-2xl font-bold">{totalProducts}</p>
                    </div>
                    <Package className="h-8 w-8 text-primary" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">
                        Total Orders
                      </p>
                      <p className="text-2xl font-bold">{totalOrders}</p>
                    </div>
                    <ShoppingCart className="h-8 w-8 text-green-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">
                        Total Revenue
                      </p>
                      <p className="text-2xl font-bold">
                        ₹{totalRevenue.toLocaleString()}
                      </p>
                    </div>
                    <DollarSign className="h-8 w-8 text-yellow-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">
                        Pending Orders
                      </p>
                      <p className="text-2xl font-bold">{pendingOrders}</p>
                    </div>
                    <Clock className="h-8 w-8 text-orange-600" />
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Recent Orders */}
            <Card>
              <CardHeader>
                <CardTitle>Recent Orders</CardTitle>
              </CardHeader>
              <CardContent>
                {orders.length === 0 ? (
                  <div className="text-center py-8">
                    <p className="text-muted-foreground">No orders yet</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {orders.slice(0, 5).map((order) => (
                      <div
                        key={order.id}
                        className="flex items-center justify-between p-4 border rounded-lg"
                      >
                        <div>
                          <p className="font-medium">Order #{order.id}</p>
                          <p className="text-sm text-muted-foreground">
                            {order.customerName}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            {new Date(order.createdAt).toLocaleDateString()}
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="font-semibold">
                            ₹{Number(order.totalAmount).toLocaleString()}
                          </p>
                          <Badge
                            variant={
                              order.status === "delivered"
                                ? "default"
                                : order.status === "shipped"
                                  ? "secondary"
                                  : order.status === "processing"
                                    ? "outline"
                                    : "destructive"
                            }
                          >
                            {order.status}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Analytics Tab */}
          <TabsContent value="analytics" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Store Analytics</h2>
              <div className="flex space-x-2">
                <Select defaultValue="30">
                  <SelectTrigger className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="7">Last 7 days</SelectItem>
                    <SelectItem value="30">Last 30 days</SelectItem>
                    <SelectItem value="90">Last 90 days</SelectItem>
                    <SelectItem value="365">Last year</SelectItem>
                  </SelectContent>
                </Select>
                <Button variant="outline" size="sm">
                  <TrendingUp className="h-4 w-4" />
                </Button>
              </div>
            </div>

            {/* Performance Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">
                        Conversion Rate
                      </p>
                      <p className="text-2xl font-bold text-green-600">
                        {totalOrders > 0 ? ((totalOrders / (totalProducts * 10)) * 100).toFixed(1) : 0}%
                      </p>
                    </div>
                    <TrendingUp className="h-8 w-8 text-green-600" />
                  </div>
                  <p className="text-xs text-muted-foreground mt-2">
                    +2.5% from last month
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">
                        Average Order Value
                      </p>
                      <p className="text-2xl font-bold text-blue-600">
                        ₹{totalOrders > 0 ? (totalRevenue / totalOrders).toFixed(0) : 0}
                      </p>
                    </div>
                    <DollarSign className="h-8 w-8 text-blue-600" />
                  </div>
                  <p className="text-xs text-muted-foreground mt-2">
                    +5.2% from last month
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">
                        Customer Rating
                      </p>
                      <div className="flex items-center space-x-2">
                        <Star className="h-5 w-5 text-yellow-500 fill-current" />
                        <span className="text-2xl font-bold">
                          {currentStore?.rating || "0.0"}
                        </span>
                      </div>
                    </div>
                    <Star className="h-8 w-8 text-yellow-500" />
                  </div>
                  <p className="text-xs text-muted-foreground mt-2">
                    {currentStore?.totalReviews || 0} reviews
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">
                        Growth Rate
                      </p>
                      <p className="text-2xl font-bold text-purple-600">+12.5%</p>
                    </div>
                    <TrendingUp className="h-8 w-8 text-purple-600" />
                  </div>
                  <p className="text-xs text-muted-foreground mt-2">
                    Monthly growth
                  </p>
                </CardContent>
              </Card>
            </div>

            {/* Charts Section */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Revenue Trend</CardTitle>
                  <p className="text-muted-foreground">
                    Monthly revenue performance
                  </p>
                </CardHeader>
                <CardContent>
                  <div className="h-64 flex items-center justify-center bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <div className="text-center">
                      <TrendingUp className="h-12 w-12 text-muted-foreground mx-auto mb-2" />
                      <p className="text-muted-foreground">
                        Revenue chart visualization
                      </p>
                      <p className="text-sm text-muted-foreground mt-1">
                        Current total: ₹{totalRevenue.toLocaleString()}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Order Status Distribution</CardTitle>
                  <p className="text-muted-foreground">
                    Breakdown of order statuses
                  </p>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                        <span className="text-sm">Delivered</span>
                      </div>
                      <span className="text-sm font-medium">
                        {orders.filter(order => order.status === 'delivered').length}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                        <span className="text-sm">Processing</span>
                      </div>
                      <span className="text-sm font-medium">
                        {orders.filter(order => order.status === 'processing').length}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
                        <span className="text-sm">Pending</span>
                      </div>
                      <span className="text-sm font-medium">
                        {orders.filter(order => order.status === 'pending').length}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                        <span className="text-sm">Shipped</span>
                      </div>
                      <span className="text-sm font-medium">
                        {orders.filter(order => order.status === 'shipped').length}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Top Products Section */}
            <Card>
              <CardHeader>
                <CardTitle>Top Performing Products</CardTitle>
                <p className="text-muted-foreground">
                  Your best-selling products this month
                </p>
              </CardHeader>
              <CardContent>
                {products.length === 0 ? (
                  <div className="text-center py-8">
                    <Package className="h-12 w-12 text-muted-foreground mx-auto mb-2" />
                    <p className="text-muted-foreground">No products to analyze</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {products.slice(0, 5).map((product, index) => (
                      <div key={product.id} className="flex items-center justify-between p-3 border rounded-lg">
                        <div className="flex items-center space-x-3">
                          <span className="text-sm font-medium text-muted-foreground">
                            #{index + 1}
                          </span>
                          <img
                            src={product.images?.[0] || "https://images.unsplash.com/photo-1560472354-b33ff0c44a43"}
                            alt={product.name}
                            className="w-10 h-10 object-cover rounded"
                          />
                          <div>
                            <p className="font-medium">{product.name}</p>
                            <p className="text-sm text-muted-foreground">
                              ₹{Number(product.price).toLocaleString()}
                            </p>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className="text-sm font-medium">Stock: {product.stock}</p>
                          <Badge variant={product.isActive ? "default" : "secondary"}>
                            {product.isActive ? "Active" : "Inactive"}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Insights Section */}
            <Card>
              <CardHeader>
                <CardTitle>Business Insights</CardTitle>
                <p className="text-muted-foreground">
                  AI-powered recommendations for your store
                </p>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-start space-x-3 p-3 bg-blue-50 rounded-lg">
                    <TrendingUp className="h-5 w-5 text-blue-600 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium">Revenue Opportunity</p>
                      <p className="text-sm text-muted-foreground">
                        Consider adding more products in high-demand categories to increase revenue by an estimated 15-20%.
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-start space-x-3 p-3 bg-green-50 rounded-lg">
                    <Star className="h-5 w-5 text-green-600 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium">Customer Satisfaction</p>
                      <p className="text-sm text-muted-foreground">
                        Your store rating is performing well. Maintain quality service to keep customers happy.
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-start space-x-3 p-3 bg-orange-50 rounded-lg">
                    <Package className="h-5 w-5 text-orange-600 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium">Inventory Management</p>
                      <p className="text-sm text-muted-foreground">
                        {products.filter(p => (p.stock ?? 0) < 10).length > 0 
                          ? `${products.filter(p => (p.stock ?? 0) < 10).length} products are running low on stock. Consider restocking soon.`
                          : "Your inventory levels look healthy across all products."
                        }
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Inventory Tab */}
          <TabsContent value="inventory" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Package className="h-5 w-5" />
                  Add New Product
                </CardTitle>
                <p className="text-muted-foreground">
                  Add products to your store inventory
                </p>
              </CardHeader>
              <CardContent>
                <Form {...form}>
                  <form
                    onSubmit={form.handleSubmit(handleAddProduct)}
                    className="space-y-6"
                  >
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <FormField
                        control={form.control}
                        name="name"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Product Name *</FormLabel>
                            <FormControl>
                              <Input
                                placeholder="Enter product name"
                                {...field}
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="categoryId"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Category *</FormLabel>
                            <Select
                              onValueChange={(value) =>
                                field.onChange(parseInt(value))
                              }
                              defaultValue={field.value?.toString()}
                            >
                              <FormControl>
                                <SelectTrigger>
                                  <SelectValue placeholder="Select category" />
                                </SelectTrigger>
                              </FormControl>
                              <SelectContent>
                                {categories.map((category) => (
                                  <SelectItem
                                    key={category.id}
                                    value={category.id.toString()}
                                  >
                                    {category.name}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>

                    <FormField
                      control={form.control}
                      name="description"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Description</FormLabel>
                          <FormControl>
                            <Textarea
                              placeholder="Enter product description"
                              className="min-h-24"
                              {...field}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      <FormField
                        control={form.control}
                        name="price"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Price *</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                placeholder="0.00"
                                {...field}
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="originalPrice"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Original Price</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                placeholder="0.00"
                                {...field}
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="stock"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Stock Quantity *</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                placeholder="Enter quantity"
                                {...field}
                                onChange={(e) =>
                                  field.onChange(parseInt(e.target.value) || 0)
                                }
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>

                    <FormField
                      control={form.control}
                      name="images"
                      render={({ field }) => (
                        <FormItem>
                          <ImageUpload
                            label="Product Images"
                            maxImages={6}
                            minImages={1}
                            onImagesChange={field.onChange}
                            initialImages={field.value || []}
                            className="col-span-full"
                          />
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <Button type="submit" className="w-full">
                      <Plus className="h-4 w-4 mr-2" />
                      {editingProduct ? "Update Product" : "Add Product"}
                    </Button>
                  </form>
                </Form>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Create Store Tab */}
          <TabsContent value="create-store" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Create Your Store</CardTitle>
                <p className="text-muted-foreground">
                  Set up your store to start selling products on Siraha Bazaar
                </p>
              </CardHeader>
              <CardContent>
                <Form {...storeForm}>
                  <form
                    onSubmit={storeForm.handleSubmit(handleCreateStore)}
                    className="space-y-6"
                  >
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <FormField
                        control={storeForm.control}
                        name="name"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Store Name</FormLabel>
                            <FormControl>
                              <Input
                                placeholder="My Awesome Store"
                                {...field}
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={storeForm.control}
                        name="phone"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Phone Number</FormLabel>
                            <FormControl>
                              <Input placeholder="+1234567890" {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>

                    <FormField
                      control={storeForm.control}
                      name="description"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Description</FormLabel>
                          <FormControl>
                            <Textarea
                              placeholder="Tell customers about your store..."
                              {...field}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <LocationPicker
                      address={storeForm.watch("address")}
                      latitude={storeForm.watch("latitude")}
                      longitude={storeForm.watch("longitude")}
                      onLocationChange={(data) => {
                        storeForm.setValue("address", data.address);
                        storeForm.setValue("latitude", data.latitude);
                        storeForm.setValue("longitude", data.longitude);
                      }}
                    />

                    <FormField
                      control={storeForm.control}
                      name="website"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Website (Optional)</FormLabel>
                          <FormControl>
                            <Input
                              placeholder="https://mystore.com"
                              {...field}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={storeForm.control}
                      name="storeType"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Store Type</FormLabel>
                          <Select
                            onValueChange={field.onChange}
                            defaultValue={field.value}
                          >
                            <FormControl>
                              <SelectTrigger>
                                <SelectValue placeholder="Select store type" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="retail">
                                Retail Store
                              </SelectItem>
                              <SelectItem value="restaurant">
                                Restaurant
                              </SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    {storeForm.watch("storeType") === "restaurant" && (
                      <>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <FormField
                            control={storeForm.control}
                            name="cuisineType"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Cuisine Type</FormLabel>
                                <Select
                                  onValueChange={field.onChange}
                                  defaultValue={field.value}
                                >
                                  <FormControl>
                                    <SelectTrigger>
                                      <SelectValue placeholder="Select cuisine type" />
                                    </SelectTrigger>
                                  </FormControl>
                                  <SelectContent>
                                    <SelectItem value="indian">
                                      Indian
                                    </SelectItem>
                                    <SelectItem value="chinese">
                                      Chinese
                                    </SelectItem>
                                    <SelectItem value="fast-food">
                                      Fast Food
                                    </SelectItem>
                                    <SelectItem value="italian">
                                      Italian
                                    </SelectItem>
                                    <SelectItem value="mexican">
                                      Mexican
                                    </SelectItem>
                                    <SelectItem value="continental">
                                      Continental
                                    </SelectItem>
                                    <SelectItem value="desserts">
                                      Desserts & Sweets
                                    </SelectItem>
                                    <SelectItem value="beverages">
                                      Beverages
                                    </SelectItem>
                                  </SelectContent>
                                </Select>
                                <FormMessage />
                              </FormItem>
                            )}
                          />

                          <FormField
                            control={storeForm.control}
                            name="deliveryTime"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Delivery Time</FormLabel>
                                <FormControl>
                                  <Input
                                    placeholder="e.g., 25-35 mins"
                                    {...field}
                                  />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <FormField
                            control={storeForm.control}
                            name="minimumOrder"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Minimum Order Amount (₹)</FormLabel>
                                <FormControl>
                                  <Input placeholder="e.g., 200" {...field} />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />

                          <FormField
                            control={storeForm.control}
                            name="deliveryFee"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Delivery Fee (₹)</FormLabel>
                                <FormControl>
                                  <Input
                                    placeholder="e.g., 40 (0 for free)"
                                    {...field}
                                  />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <FormField
                            control={storeForm.control}
                            name="isDeliveryAvailable"
                            render={({ field }) => (
                              <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                                <div className="space-y-0.5">
                                  <FormLabel className="text-base">
                                    Delivery Available
                                  </FormLabel>
                                  <div className="text-sm text-muted-foreground">
                                    Enable home delivery for your restaurant
                                  </div>
                                </div>
                                <FormControl>
                                  <input
                                    type="checkbox"
                                    checked={field.value}
                                    onChange={field.onChange}
                                    className="rounded"
                                  />
                                </FormControl>
                              </FormItem>
                            )}
                          />

                          <FormField
                            control={storeForm.control}
                            name="openingHours"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Opening Hours</FormLabel>
                                <FormControl>
                                  <Input
                                    placeholder="e.g., 9:00 AM - 11:00 PM"
                                    {...field}
                                  />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                        </div>
                      </>
                    )}

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <FormField
                        control={storeForm.control}
                        name="logo"
                        render={({ field }) => (
                          <FormItem>
                            <ImageUpload
                              label="Store Logo"
                              single={true}
                              maxImages={1}
                              minImages={0}
                              onImagesChange={(images) =>
                                field.onChange(images[0] || "")
                              }
                              initialImages={field.value ? [field.value] : []}
                            />
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={storeForm.control}
                        name="coverImage"
                        render={({ field }) => (
                          <FormItem>
                            <ImageUpload
                              label="Store Cover Image"
                              single={true}
                              maxImages={1}
                              minImages={0}
                              onImagesChange={(images) =>
                                field.onChange(images[0] || "")
                              }
                              initialImages={field.value ? [field.value] : []}
                            />
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>

                    <Button type="submit" className="w-full">
                      Create Store
                    </Button>
                  </form>
                </Form>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Products Tab */}
          <TabsContent value="products" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>Manage Products</span>
                  <Button onClick={() => setActiveTab("add-product")}>
                    <Plus className="h-4 w-4 mr-2" />
                    Add Product
                  </Button>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {products.length === 0 ? (
                  <div className="text-center py-8">
                    <Package className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
                    <p className="text-muted-foreground">
                      No products added yet
                    </p>
                    <Button
                      className="mt-4"
                      onClick={() => setActiveTab("add-product")}
                    >
                      Add Your First Product
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {products.map((product) => (
                      <div
                        key={product.id}
                        className="flex items-center space-x-4 p-4 border rounded-lg"
                      >
                        <img
                          src={
                            product.images?.[0] ||
                            "https://images.unsplash.com/photo-1560472354-b33ff0c44a43?ixlib=rb-4.0.3&auto=format&fit=crop&w=100&h=100"
                          }
                          alt={product.name}
                          className="w-16 h-16 object-cover rounded-lg"
                        />
                        <div className="flex-1">
                          <h3 className="font-medium">{product.name}</h3>
                          <p className="text-sm text-muted-foreground">
                            Price: ₹{Number(product.price).toLocaleString()}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Stock: {product.stock} units
                          </p>
                          <div className="flex gap-2 mt-2">
                            {product.isFastSell && (
                              <Badge variant="destructive" className="text-xs">
                                🔥 Fast Sell
                              </Badge>
                            )}
                            {product.isOnOffer && (
                              <Badge variant="secondary" className="text-xs">
                                🏷️ {product.offerPercentage}% OFF
                              </Badge>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge
                            variant={product.isActive ? "default" : "secondary"}
                          >
                            {product.isActive ? "Active" : "Inactive"}
                          </Badge>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleEditProduct(product)}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleDeleteProduct(product.id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Add/Edit Product Tab */}
          <TabsContent value="add-product" className="space-y-4">
            <Card>
              <CardHeader className="pb-4">
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Plus className="h-5 w-5" />
                  {editingProduct ? "Edit Product" : "Add New Product"}
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4">
                <Form {...form}>
                  <form
                    onSubmit={form.handleSubmit(handleAddProduct)}
                    className="space-y-3 max-h-[70vh] overflow-y-auto"
                  >
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <FormField
                        control={form.control}
                        name="name"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Product Name</FormLabel>
                            <FormControl>
                              <Input
                                placeholder="Enter product name"
                                {...field}
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="categoryId"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Category</FormLabel>
                            <Select
                              onValueChange={(value) =>
                                field.onChange(parseInt(value))
                              }
                              value={field.value?.toString()}
                            >
                              <FormControl>
                                <SelectTrigger>
                                  <SelectValue placeholder="Select category" />
                                </SelectTrigger>
                              </FormControl>
                              <SelectContent>
                                {categories.map((category) => (
                                  <SelectItem
                                    key={category.id}
                                    value={category.id.toString()}
                                  >
                                    {category.name}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="price"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Price (₹)</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                placeholder="Enter price"
                                {...field}
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="originalPrice"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Original Price (₹) - Optional</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                placeholder="Enter original price"
                                {...field}
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="stock"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Stock Quantity</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                placeholder="Enter quantity"
                                {...field}
                                onChange={(e) =>
                                  field.onChange(parseInt(e.target.value) || 0)
                                }
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>

                    <FormField
                      control={form.control}
                      name="images"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Product Images</FormLabel>
                          <div className="space-y-4">
                            <ImageUpload
                              label=""
                              maxImages={6}
                              minImages={1}
                              onImagesChange={field.onChange}
                              initialImages={field.value || []}
                              className="col-span-full"
                            />
                            <div className="flex items-center gap-2">
                              <div className="flex-1 border-t border-gray-200"></div>
                              <span className="text-sm text-gray-500 px-2">or</span>
                              <div className="flex-1 border-t border-gray-200"></div>
                            </div>
                            <UnifiedImageUpload
                              onImageSelect={(imageUrl) => {
                                const currentImages = field.value || [];
                                if (currentImages.length < 6) {
                                  field.onChange([...currentImages, imageUrl]);
                                }
                              }}
                              selectedImages={field.value || []}
                              maxImages={6 - (field.value?.length || 0)}
                              buttonText="Add Images"
                            />
                          </div>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="description"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Description</FormLabel>
                          <FormControl>
                            <Textarea
                              placeholder="Enter product description"
                              className="min-h-20"
                              {...field}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    {/* Special Features Section */}
                    <div className="space-y-4 p-4 border rounded-lg bg-gray-50">
                      <h3 className="font-medium text-lg flex items-center gap-2">
                        <TrendingUp className="h-5 w-5" />
                        Special Features
                      </h3>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <FormField
                          control={form.control}
                          name="isFastSell"
                          render={({ field }) => (
                            <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                              <div className="space-y-0.5">
                                <FormLabel className="text-base font-medium">
                                  Fast Sell Product
                                </FormLabel>
                                <div className="text-sm text-muted-foreground">
                                  Mark as fast-selling/trending item
                                </div>
                              </div>
                              <FormControl>
                                <input
                                  type="checkbox"
                                  checked={field.value}
                                  onChange={field.onChange}
                                  className="w-4 h-4"
                                />
                              </FormControl>
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="isOnOffer"
                          render={({ field }) => (
                            <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                              <div className="space-y-0.5">
                                <FormLabel className="text-base font-medium">
                                  Special Offer
                                </FormLabel>
                                <div className="text-sm text-muted-foreground">
                                  Apply discount offer
                                </div>
                              </div>
                              <FormControl>
                                <input
                                  type="checkbox"
                                  checked={field.value}
                                  onChange={field.onChange}
                                  className="w-4 h-4"
                                />
                              </FormControl>
                            </FormItem>
                          )}
                        />
                      </div>

                      {form.watch("isOnOffer") && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                          <FormField
                            control={form.control}
                            name="offerPercentage"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Discount Percentage (%)</FormLabel>
                                <FormControl>
                                  <Input
                                    type="number"
                                    placeholder="Enter discount percentage"
                                    min="0"
                                    max="100"
                                    {...field}
                                    onChange={(e) =>
                                      field.onChange(
                                        parseInt(e.target.value) || 0,
                                      )
                                    }
                                  />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />

                          <FormField
                            control={form.control}
                            name="offerEndDate"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Offer End Date</FormLabel>
                                <FormControl>
                                  <Input type="date" {...field} />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                        </div>
                      )}
                    </div>

                    {/* Food-specific fields for restaurants */}
                    {currentStore?.storeType === "restaurant" && (
                      <div className="space-y-4 p-4 border rounded-lg bg-orange-50">
                        <h3 className="font-medium text-lg flex items-center gap-2">
                          <UtensilsCrossed className="h-5 w-5" />
                          Food Item Details
                        </h3>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <FormField
                            control={form.control}
                            name="preparationTime"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Preparation Time</FormLabel>
                                <FormControl>
                                  <Input
                                    placeholder="e.g., 15-20 mins"
                                    {...field}
                                  />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />

                          <FormField
                            control={form.control}
                            name="spiceLevel"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Spice Level</FormLabel>
                                <Select
                                  onValueChange={field.onChange}
                                  defaultValue={field.value}
                                >
                                  <FormControl>
                                    <SelectTrigger>
                                      <SelectValue placeholder="Select spice level" />
                                    </SelectTrigger>
                                  </FormControl>
                                  <SelectContent>
                                    <SelectItem value="">
                                      Not Applicable
                                    </SelectItem>
                                    <SelectItem value="mild">Mild</SelectItem>
                                    <SelectItem value="medium">
                                      Medium
                                    </SelectItem>
                                    <SelectItem value="hot">Hot</SelectItem>
                                    <SelectItem value="extra-hot">
                                      Extra Hot
                                    </SelectItem>
                                  </SelectContent>
                                </Select>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <FormField
                            control={form.control}
                            name="isVegetarian"
                            render={({ field }) => (
                              <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                                <div className="space-y-0.5">
                                  <FormLabel className="text-base font-medium">
                                    Vegetarian
                                  </FormLabel>
                                  <div className="text-sm text-muted-foreground">
                                    Contains no meat or fish
                                  </div>
                                </div>
                                <FormControl>
                                  <input
                                    type="checkbox"
                                    checked={field.value}
                                    onChange={field.onChange}
                                    className="w-4 h-4"
                                  />
                                </FormControl>
                              </FormItem>
                            )}
                          />

                          <FormField
                            control={form.control}
                            name="isVegan"
                            render={({ field }) => (
                              <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                                <div className="space-y-0.5">
                                  <FormLabel className="text-base font-medium">
                                    Vegan
                                  </FormLabel>
                                  <div className="text-sm text-muted-foreground">
                                    Contains no animal products
                                  </div>
                                </div>
                                <FormControl>
                                  <input
                                    type="checkbox"
                                    checked={field.value}
                                    onChange={field.onChange}
                                    className="w-4 h-4"
                                  />
                                </FormControl>
                              </FormItem>
                            )}
                          />
                        </div>

                        <FormField
                          control={form.control}
                          name="nutritionInfo"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>
                                Nutrition Information (Optional)
                              </FormLabel>
                              <FormControl>
                                <Textarea
                                  placeholder="e.g., Calories: 350, Protein: 15g, Carbs: 45g, Fat: 12g"
                                  className="min-h-20"
                                  {...field}
                                />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                    )}

                    <div className="flex gap-3 pt-2">
                      <Button type="submit" className="flex-1 h-10" size="sm">
                        <Plus className="h-4 w-4 mr-2" />
                        {editingProduct ? "Update Product" : "Add Product"}
                      </Button>
                      {editingProduct && (
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          className="h-10"
                          onClick={() => {
                            setEditingProduct(null);
                            form.reset();
                          }}
                        >
                          Cancel
                        </Button>
                      )}
                    </div>
                  </form>
                </Form>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Store Tab */}
          <TabsContent value="store" className="space-y-6">
            {currentStore ? (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Store className="h-5 w-5" />
                    Store Information
                  </CardTitle>
                  <p className="text-muted-foreground">
                    Manage your store details and settings
                  </p>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Store Name</label>
                      <p className="text-sm text-muted-foreground">{currentStore.name}</p>
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Store Type</label>
                      <p className="text-sm text-muted-foreground capitalize">{currentStore.storeType}</p>
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Address</label>
                      <p className="text-sm text-muted-foreground">{currentStore.address}</p>
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Phone</label>
                      <p className="text-sm text-muted-foreground">{currentStore.phone || "Not set"}</p>
                    </div>
                    {currentStore.storeType === "restaurant" && (
                      <>
                        <div className="space-y-2">
                          <label className="text-sm font-medium">Cuisine Type</label>
                          <p className="text-sm text-muted-foreground capitalize">{currentStore.cuisineType || "Not set"}</p>
                        </div>
                        <div className="space-y-2">
                          <label className="text-sm font-medium">Delivery Time</label>
                          <p className="text-sm text-muted-foreground">{currentStore.deliveryTime || "Not set"}</p>
                        </div>
                        <div className="space-y-2">
                          <label className="text-sm font-medium">Minimum Order</label>
                          <p className="text-sm text-muted-foreground">₹{currentStore.minimumOrder || "Not set"}</p>
                        </div>
                        <div className="space-y-2">
                          <label className="text-sm font-medium">Delivery Fee</label>
                          <p className="text-sm text-muted-foreground">₹{currentStore.deliveryFee || "Not set"}</p>
                        </div>
                      </>
                    )}
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Rating</label>
                      <div className="flex items-center gap-2">
                        <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                        <span className="text-sm text-muted-foreground">{currentStore.rating || "0.0"} ({currentStore.totalReviews || 0} reviews)</span>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => window.open(`/store/${currentStore.id}#store-reviews`, '_blank')}
                        >
                          View Reviews
                        </Button>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Status</label>
                      <Badge variant={currentStore.isActive ? "default" : "secondary"}>
                        {currentStore.isActive ? "Approved" : "Pending Approval"}
                      </Badge>
                    </div>
                  </div>
                  
                  <Separator />
                  
                  <div className="flex gap-4">
                    <Button variant="outline" className="flex-1" onClick={openEditStoreDialog}>
                      <Edit className="h-4 w-4 mr-2" />
                      Edit Store Details
                    </Button>
                    <Button variant="outline" className="flex-1">
                      <MapPin className="h-4 w-4 mr-2" />
                      Update Location
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ) : (
              <Card>
                <CardContent className="text-center py-8">
                  <Store className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">Please create a store first</p>
                  <Button 
                    className="mt-4" 
                    onClick={() => setActiveTab("create-store")}
                  >
                    Create Store
                  </Button>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Orders Tab */}
          <TabsContent value="orders" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Order Management</CardTitle>
              </CardHeader>
              <CardContent>
                {orders.length === 0 ? (
                  <div className="text-center py-8">
                    <ShoppingCart className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
                    <p className="text-muted-foreground">No orders yet</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {orders.map((order) => (
                      <div key={order.id} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-4">
                          <div>
                            <h3 className="font-semibold">Order #{order.id}</h3>
                            <p className="text-sm text-muted-foreground">
                              {order.customerName} • {order.phone}
                            </p>
                            <p className="text-sm text-muted-foreground">
                              {new Date(order.createdAt).toLocaleDateString()}
                            </p>
                          </div>
                          <div className="text-right space-y-2">
                            <p className="font-semibold text-lg">
                              ₹{Number(order.totalAmount).toLocaleString()}
                            </p>
                            <div className="flex gap-2">
                              <Select
                                value={order.status}
                                onValueChange={(value) =>
                                  handleOrderStatusUpdate(order.id, value)
                                }
                              >
                                <SelectTrigger className="w-32">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectItem value="pending">
                                    Pending
                                  </SelectItem>
                                  <SelectItem value="processing">
                                    Processing
                                  </SelectItem>
                                  <SelectItem value="ready_for_pickup">
                                    Ready for Pickup
                                  </SelectItem>
                                  <SelectItem value="assigned_for_delivery">
                                    Assigned for Delivery
                                  </SelectItem>
                                  <SelectItem value="shipped">
                                    Shipped
                                  </SelectItem>
                                  <SelectItem value="delivered">
                                    Delivered
                                  </SelectItem>
                                  <SelectItem value="cancelled">
                                    Cancelled
                                  </SelectItem>
                                </SelectContent>
                              </Select>
                            </div>

                            {/* First-Accept-First-Serve Delivery System */}
                            <div className="flex flex-wrap gap-2 mt-2">
                              {order.status !== "assigned_for_delivery" &&
                                order.status !== "delivered" &&
                                order.status !== "cancelled" && (
                                  <div className="flex gap-2">
                                    <Button
                                      onClick={() => {
                                        handleNotifyDeliveryPartner(
                                          order.id,
                                          `🚚 New Order Available: Order #${order.id} from ${currentStore?.name}. Customer: ${order.customerName}. Total: ₹${order.totalAmount}. First to accept gets delivery!`,
                                          false,
                                        );
                                      }}
                                      className="bg-orange-600 hover:bg-orange-700 text-white"
                                    >
                                      <Bell className="h-4 w-4 mr-2" />
                                      Send to All Partners (First Accept)
                                    </Button>
                                  </div>
                                )}

                              {order.status === "assigned_for_delivery" && (
                                <div className="bg-green-50 border border-green-200 rounded-lg p-3 w-full">
                                  <p className="text-sm text-green-700 font-medium">
                                    ✅ Delivery partner assigned and notified
                                  </p>
                                  <p className="text-xs text-green-600 mt-1">
                                    Order is being processed for delivery
                                  </p>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>

                        <Separator className="my-3" />

                        {/* Order Items Section with Product Images */}
                        {order.items && order.items.length > 0 && (
                          <div className="mb-3">
                            <p className="text-sm font-medium mb-2">Order Items:</p>
                            <div className="space-y-2">
                              {order.items.map((item) => {
                                // Enhanced image handling - prefer images array over single imageUrl
                                const getProductImage = () => {
                                  if (item.product?.images && item.product.images.length > 0) {
                                    return item.product.images[0];
                                  }
                                  if (item.product?.imageUrl) {
                                    return item.product.imageUrl;
                                  }
                                  return null;
                                };
                                
                                const productImage = getProductImage();
                                
                                return (
                                  <div key={item.id} className="flex items-center space-x-3 p-2 bg-gray-50 dark:bg-gray-800 rounded-lg">
                                    <div className="w-12 h-12 bg-gray-200 rounded-lg overflow-hidden flex-shrink-0 relative">
                                      {productImage ? (
                                        <img 
                                          src={productImage} 
                                          alt={item.product?.name || 'Product'}
                                          className="w-full h-full object-cover"
                                          onError={(e) => {
                                            e.currentTarget.classList.add('hidden');
                                            const fallback = e.currentTarget.parentElement?.querySelector('.fallback-icon') as HTMLElement;
                                            if (fallback) fallback.classList.remove('hidden');
                                          }}
                                        />
                                      ) : null}
                                      <Package className={`fallback-icon w-6 h-6 text-gray-400 absolute inset-0 m-auto ${productImage ? 'hidden' : 'flex'}`} />
                                    </div>
                                    <div className="flex-1 min-w-0">
                                      <p className="text-sm font-medium truncate">{item.product?.name || `Product #${item.productId}`}</p>
                                      <p className="text-xs text-muted-foreground">
                                        Qty: {item.quantity} × ₹{Number(item.price).toLocaleString()} = ₹{(item.quantity * Number(item.price)).toLocaleString()}
                                      </p>
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}

                        <div>
                          <p className="text-sm font-medium mb-2">
                            Delivery Address:
                          </p>
                          <p className="text-sm text-muted-foreground">
                            {order.shippingAddress}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Notifications Tab */}
          <TabsContent value="notifications" className="space-y-6">
            {/* Quick Actions Section */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">
                        Ready for Pickup
                      </p>
                      <p className="text-2xl font-bold text-green-600">
                        {
                          orders.filter(
                            (order) => order.status === "ready_for_pickup",
                          ).length
                        }
                      </p>
                    </div>
                    <CheckCircle className="h-8 w-8 text-green-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">
                        Processing
                      </p>
                      <p className="text-2xl font-bold text-blue-600">
                        {
                          orders.filter(
                            (order) => order.status === "processing",
                          ).length
                        }
                      </p>
                    </div>
                    <Timer className="h-8 w-8 text-blue-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">
                        Notifications Sent
                      </p>
                      <p className="text-2xl font-bold text-purple-600">
                        {notificationHistory.length}
                      </p>
                    </div>
                    <Bell className="h-8 w-8 text-purple-600" />
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* First Accept First Serve Notification System */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Truck className="h-5 w-5" />
                  First Accept First Serve - Delivery Notifications
                </CardTitle>
                <p className="text-muted-foreground">
                  Send notifications to all available delivery partners. The
                  first one to accept gets the delivery.
                </p>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Bulk Actions */}
                <div className="flex flex-wrap gap-3 p-4 bg-gray-50 rounded-lg">
                  <Button
                    onClick={() => {
                      const readyOrders = orders.filter(
                        (order) => order.status === "ready_for_pickup",
                      );
                      if (readyOrders.length > 0) {
                        handleBroadcastNotification(
                          `🚨 URGENT: ${readyOrders.length} orders ready for immediate pickup from ${currentStore?.name}`,
                          readyOrders.map((o) => o.id),
                        );
                      }
                    }}
                    disabled={
                      orders.filter(
                        (order) => order.status === "ready_for_pickup",
                      ).length === 0
                    }
                    className="bg-red-600 hover:bg-red-700"
                  >
                    <AlertCircle className="h-4 w-4 mr-2" />
                    Broadcast All Ready Orders (Urgent)
                  </Button>

                  <Button
                    variant="outline"
                    onClick={() => {
                      const processingOrders = orders.filter(
                        (order) => order.status === "processing",
                      );
                      if (processingOrders.length > 0) {
                        handleBroadcastNotification(
                          `📦 ${processingOrders.length} orders being prepared at ${currentStore?.name}`,
                          processingOrders.map((o) => o.id),
                        );
                      }
                    }}
                    disabled={
                      orders.filter((order) => order.status === "processing")
                        .length === 0
                    }
                  >
                    <Send className="h-4 w-4 mr-2" />
                    Notify About Processing Orders
                  </Button>
                </div>

                {/* Individual Order Notifications */}
                <div className="space-y-4">
                  <h3 className="font-semibold text-lg">
                    Individual Order Notifications
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {orders
                      .filter(
                        (order) =>
                          order.status === "processing" ||
                          order.status === "ready_for_pickup",
                      )
                      .map((order) => (
                        <div
                          key={order.id}
                          className="border rounded-lg p-4 space-y-3 hover:shadow-md transition-shadow"
                        >
                          <div className="flex justify-between items-start">
                            <div>
                              <h4 className="font-medium">Order #{order.id}</h4>
                              <p className="text-sm text-muted-foreground">
                                {order.customerName}
                              </p>
                              <p className="text-xs text-muted-foreground">
                                {order.phone}
                              </p>
                              <Badge
                                variant={
                                  order.status === "ready_for_pickup"
                                    ? "default"
                                    : "secondary"
                                }
                                className={
                                  order.status === "ready_for_pickup"
                                    ? "bg-green-100 text-green-800"
                                    : ""
                                }
                              >
                                {order.status.replace("_", " ").toUpperCase()}
                              </Badge>
                            </div>
                            <div className="text-right">
                              <p className="font-semibold">
                                ₹{Number(order.totalAmount).toLocaleString()}
                              </p>
                              <p className="text-xs text-muted-foreground">
                                {new Date(order.createdAt).toLocaleDateString()}
                              </p>
                            </div>
                          </div>

                          <div className="text-sm text-muted-foreground">
                            <p className="truncate">
                              📍 {order.shippingAddress}
                            </p>
                          </div>

                          <div className="space-y-2">
                            <Button
                              size="sm"
                              className="w-full bg-red-600 hover:bg-red-700"
                              onClick={() =>
                                handleNotifyDeliveryPartner(
                                  order.id,
                                  `🚨 URGENT PICKUP: Order #${order.id} ready NOW from ${currentStore?.name}! Customer: ${order.customerName}, Amount: ₹${order.totalAmount}. First to accept gets this delivery!`,
                                  true,
                                )
                              }
                            >
                              <AlertCircle className="h-4 w-4 mr-2" />
                              Send Urgent Alert (First Accept First Serve)
                            </Button>

                            <Button
                              size="sm"
                              variant="outline"
                              className="w-full"
                              onClick={() =>
                                handleNotifyDeliveryPartner(
                                  order.id,
                                  `📦 Pickup Available: Order #${order.id} at ${currentStore?.name}. Customer: ${order.customerName}, Amount: ₹${order.totalAmount}. Accept to claim this delivery!`,
                                  false,
                                )
                              }
                            >
                              <Send className="h-4 w-4 mr-2" />
                              Send Standard Notification
                            </Button>
                          </div>
                          {/* Display Delivery Tracking Map if a delivery partner is assigned */}
                          {order.deliveryPartner && (
                            <div className="mt-4 border-t pt-4">
                              <div className="flex items-center justify-between mb-3">
                                <h5 className="font-semibold flex items-center gap-2">
                                  <MapPin className="h-4 w-4" />
                                  Live Delivery Tracking
                                </h5>
                                <Badge
                                  variant="secondary"
                                  className="bg-green-100 text-green-800"
                                >
                                  Live
                                </Badge>
                              </div>
                              <div className="bg-gray-50 rounded-lg p-3 mb-3">
                                <p className="text-sm">
                                  <strong>Contact Delivery Partner:</strong>
                                  <a
                                    href={`tel:${order.deliveryPartner.phone}`}
                                    className="text-blue-600 hover:underline ml-2"
                                  >
                                    <Phone className="inline h-4 w-4 mr-1" />
                                    {order.deliveryPartner.phone}
                                  </a>
                                </p>
                                <p className="text-sm text-gray-600 mt-1">
                                  Partner:{" "}
                                  {order.deliveryPartner.name ||
                                    "Assigned Partner"}
                                </p>
                              </div>
                              <div className="h-64 rounded-lg overflow-hidden border">
                                <DeliveryTrackingMap
                                  deliveryId={order.id}
                                  userType="shopkeeper"
                                />
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                  </div>

                  {orders.filter(
                    (order) =>
                      order.status === "processing" ||
                      order.status === "ready_for_pickup",
                  ).length === 0 && (
                    <div className="text-center py-8">
                      <Truck className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
                      <p className="text-muted-foreground">
                        No orders ready for delivery notifications
                      </p>
                      <p className="text-sm text-muted-foreground mt-2">
                        Orders with "Processing" or "Ready for Pickup" status
                        will appear here
                      </p>
                    </div>
                  )}
                </div>

                {/* Notification History */}
                {notificationHistory.length > 0 && (
                  <div className="space-y-4">
                    <h3 className="font-semibold text-lg">
                      Recent Notifications
                    </h3>
                    <div className="space-y-2 max-h-60 overflow-y-auto">
                      {notificationHistory.slice(0, 10).map((notification) => (
                        <div
                          key={notification.id}
                          className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                        >
                          <div className="flex items-center gap-3">
                            {notification.urgent ? (
                              <AlertCircle className="h-4 w-4 text-red-500" />
                            ) : (
                              <Bell className="h-4 w-4 text-blue-500" />
                            )}
                            <div>
                              <p className="text-sm font-medium">
                                Order #{notification.orderId}
                              </p>
                              <p className="text-xs text-muted-foreground">
                                {new Date(notification.sentAt).toLocaleString()}
                              </p>
                            </div>
                          </div>
                          <Badge
                            variant={
                              notification.urgent ? "destructive" : "secondary"
                            }
                          >
                            {notification.urgent ? "Urgent" : "Standard"}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Mobile-Optimized Floating Add Product Button */}
        {currentStore && (
          <Dialog open={showAddProductModal} onOpenChange={setShowAddProductModal}>
            <DialogTrigger asChild>
              <Button
                size="lg"
                className="floating-button-mobile-optimized fixed bottom-20 right-4 sm:right-6 h-14 w-14 sm:h-16 sm:w-16 rounded-full shadow-2xl bg-gradient-to-r from-orange-500 to-orange-600 hover:from-orange-600 hover:to-orange-700 text-white z-[999] transition-all duration-300 ease-in-out hover:scale-110 active:scale-95 border-2 border-white/20"
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  console.log('Floating button clicked - opening modal');
                  setEditingProduct(null);
                  form.reset();
                  setShowAddProductModal(true);
                }}
                onTouchStart={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  console.log('Floating button touched');
                }}
                style={{
                  touchAction: 'manipulation',
                  WebkitTouchCallout: 'none',
                  WebkitUserSelect: 'none',
                  userSelect: 'none',
                  pointerEvents: 'auto',
                  cursor: 'pointer'
                }}
              >
                <Plus className="h-6 w-6 sm:h-7 sm:w-7" />
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-4xl max-h-[95vh] overflow-y-auto mx-4 sm:mx-auto rounded-lg">
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Plus className="h-5 w-5" />
                  {editingProduct ? "Edit Product" : "Add New Product"}
                </DialogTitle>
                <DialogDescription>
                  {editingProduct ? "Update your product details and images" : "Add a new product to your store with images and details"}
                </DialogDescription>
              </DialogHeader>
              <div className="mt-4">
                <Form {...form}>
                  <form
                    onSubmit={form.handleSubmit(handleAddProduct)}
                    className="space-y-6"
                  >
                    {/* Product Name */}
                    <FormField
                      control={form.control}
                      name="name"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-base font-medium">
                            {isRestaurant ? 'Menu Item Name *' : 'Product Name *'}
                          </FormLabel>
                          <FormControl>
                            <Input 
                              placeholder={isRestaurant ? "Enter menu item name" : "Enter product name"} 
                              className="h-11"
                              {...field} 
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />



                    {/* Category */}
                    <FormField
                      control={form.control}
                      name="categoryId"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-base font-medium">Category *</FormLabel>
                          <Select 
                            onValueChange={(value) => field.onChange(parseInt(value))}
                            defaultValue={field.value?.toString()}
                          >
                            <FormControl>
                              <SelectTrigger className="h-11">
                                <SelectValue placeholder="Select a category" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              {categories.length > 0 ? (
                                categories.map((category) => (
                                  <SelectItem key={category.id} value={category.id.toString()}>
                                    {category.name}
                                  </SelectItem>
                                ))
                              ) : (
                                <SelectItem value="1" disabled>
                                  Loading categories...
                                </SelectItem>
                              )}
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    {/* Description */}
                    <FormField
                      control={form.control}
                      name="description"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-base font-medium">Description</FormLabel>
                          <FormControl>
                            <Textarea 
                              placeholder="Enter product description" 
                              rows={4}
                              {...field} 
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    {/* Price and Original Price */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <FormField
                        control={form.control}
                        name="price"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel className="text-base font-medium">Price *</FormLabel>
                            <FormControl>
                              <Input 
                                type="number" 
                                step="0.01" 
                                placeholder="0.00" 
                                className="h-11"
                                {...field} 
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="originalPrice"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel className="text-base font-medium">Original Price</FormLabel>
                            <FormControl>
                              <Input 
                                type="number" 
                                step="0.01" 
                                placeholder="0.00" 
                                className="h-11"
                                {...field} 
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>

                    {/* Stock */}
                    <FormField
                      control={form.control}
                      name="stock"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-base font-medium">Stock Quantity *</FormLabel>
                          <FormControl>
                            <Input 
                              type="number" 
                              placeholder="Enter stock quantity" 
                              className="h-11"
                              {...field}
                              onChange={(e) => field.onChange(parseInt(e.target.value) || 0)}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="images"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Product Images</FormLabel>
                          <div className="space-y-4">
                            <ImageUpload
                              label=""
                              maxImages={6}
                              minImages={1}
                              onImagesChange={field.onChange}
                              initialImages={field.value || []}
                              className="col-span-full"
                            />
                            <div className="flex items-center gap-2">
                              <div className="flex-1 border-t border-gray-200"></div>
                              <span className="text-sm text-gray-500 px-2">or</span>
                              <div className="flex-1 border-t border-gray-200"></div>
                            </div>
                            <UnifiedImageUpload
                              onImageSelect={(imageUrl) => {
                                const currentImages = field.value || [];
                                if (currentImages.length < 6) {
                                  field.onChange([...currentImages, imageUrl]);
                                }
                              }}
                              selectedImages={field.value || []}
                              maxImages={6 - (field.value?.length || 0)}
                              buttonText="Add Images"
                            />
                          </div>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    {/* Food-specific fields (shown only for restaurants) */}
                    {isRestaurant && (
                      <div className="space-y-6 border-t pt-6">
                        <h3 className="text-lg font-semibold text-orange-600">Food Item Details</h3>
                        
                        {/* Preparation Time */}
                        <FormField
                          control={form.control}
                          name="preparationTime"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel className="text-base font-medium">Preparation Time</FormLabel>
                              <FormControl>
                                <Input 
                                  placeholder="e.g., 15-20 minutes" 
                                  className="h-11"
                                  {...field} 
                                />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        {/* Ingredients */}
                        <div>
                          <FormLabel className="text-base font-medium">Ingredients</FormLabel>
                          <div className="mt-2 space-y-3">
                            <div className="flex gap-2">
                              <Input
                                placeholder="Enter ingredient"
                                value={newIngredient}
                                onChange={(e) => setNewIngredient(e.target.value)}
                                className="h-11"
                                onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), handleAddIngredient())}
                              />
                              <Button type="button" onClick={handleAddIngredient} className="h-11">
                                <Plus className="h-4 w-4" />
                              </Button>
                            </div>
                            {ingredients.length > 0 && (
                              <div className="flex flex-wrap gap-2">
                                {ingredients.map((ingredient, index) => (
                                  <span 
                                    key={index}
                                    className="inline-flex items-center gap-1 px-3 py-1 bg-orange-100 text-orange-800 rounded-full text-sm"
                                  >
                                    {ingredient}
                                    <Button
                                      type="button"
                                      variant="ghost"
                                      size="sm"
                                      className="h-4 w-4 p-0 hover:bg-orange-200"
                                      onClick={() => handleRemoveIngredient(ingredient)}
                                    >
                                      <X className="h-3 w-3" />
                                    </Button>
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Allergens */}
                        <div>
                          <FormLabel className="text-base font-medium">Allergens</FormLabel>
                          <div className="mt-2 space-y-3">
                            <div className="flex gap-2">
                              <Input
                                placeholder="Enter allergen"
                                value={newAllergen}
                                onChange={(e) => setNewAllergen(e.target.value)}
                                className="h-11"
                                onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), handleAddAllergen())}
                              />
                              <Button type="button" onClick={handleAddAllergen} className="h-11">
                                <Plus className="h-4 w-4" />
                              </Button>
                            </div>
                            {allergens.length > 0 && (
                              <div className="flex flex-wrap gap-2">
                                {allergens.map((allergen, index) => (
                                  <span 
                                    key={index}
                                    className="inline-flex items-center gap-1 px-3 py-1 bg-red-100 text-red-800 rounded-full text-sm"
                                  >
                                    {allergen}
                                    <Button
                                      type="button"
                                      variant="ghost"
                                      size="sm"
                                      className="h-4 w-4 p-0 hover:bg-red-200"
                                      onClick={() => handleRemoveAllergen(allergen)}
                                    >
                                      <X className="h-3 w-3" />
                                    </Button>
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Spice Level */}
                        <FormField
                          control={form.control}
                          name="spiceLevel"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel className="text-base font-medium">Spice Level</FormLabel>
                              <Select onValueChange={field.onChange} defaultValue={field.value}>
                                <FormControl>
                                  <SelectTrigger className="h-11">
                                    <SelectValue placeholder="Select spice level" />
                                  </SelectTrigger>
                                </FormControl>
                                <SelectContent>
                                  <SelectItem value="mild">Mild</SelectItem>
                                  <SelectItem value="medium">Medium</SelectItem>
                                  <SelectItem value="hot">Hot</SelectItem>
                                  <SelectItem value="extra-hot">Extra Hot</SelectItem>
                                </SelectContent>
                              </Select>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        {/* Dietary Options */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                          <FormField
                            control={form.control}
                            name="isVegetarian"
                            render={({ field }) => (
                              <FormItem className="flex flex-row items-center space-x-3 space-y-0">
                                <FormControl>
                                  <input
                                    type="checkbox"
                                    checked={field.value}
                                    onChange={field.onChange}
                                    className="h-4 w-4"
                                  />
                                </FormControl>
                                <FormLabel className="text-base font-medium">Vegetarian</FormLabel>
                              </FormItem>
                            )}
                          />

                          <FormField
                            control={form.control}
                            name="isVegan"
                            render={({ field }) => (
                              <FormItem className="flex flex-row items-center space-x-3 space-y-0">
                                <FormControl>
                                  <input
                                    type="checkbox"
                                    checked={field.value}
                                    onChange={field.onChange}
                                    className="h-4 w-4"
                                  />
                                </FormControl>
                                <FormLabel className="text-base font-medium">Vegan</FormLabel>
                              </FormItem>
                            )}
                          />
                        </div>

                        {/* Nutrition Info */}
                        <FormField
                          control={form.control}
                          name="nutritionInfo"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel className="text-base font-medium">Nutrition Information</FormLabel>
                              <FormControl>
                                <Textarea 
                                  placeholder="Enter nutrition information (optional)" 
                                  rows={3}
                                  {...field} 
                                />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                    )}

                    <div className="flex gap-3 pt-4">
                      <Button type="submit" className="flex-1">
                        <Plus className="h-4 w-4 mr-2" />
                        {editingProduct ? "Update Product" : "Add Product"}
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => setShowAddProductModal(false)}
                      >
                        Cancel
                      </Button>
                    </div>
                  </form>
                </Form>
              </div>
            </DialogContent>
          </Dialog>
        )}

        {/* Edit Store Dialog */}
        <Dialog open={isEditStoreOpen} onOpenChange={setIsEditStoreOpen}>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Edit Store Details</DialogTitle>
              <DialogDescription>
                Update your store information and settings
              </DialogDescription>
            </DialogHeader>
            <Form {...editStoreForm}>
              <form
                onSubmit={editStoreForm.handleSubmit(handleUpdateStore)}
                className="space-y-6"
              >
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField
                    control={editStoreForm.control}
                    name="name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Store Name</FormLabel>
                        <FormControl>
                          <Input placeholder="My Awesome Store" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={editStoreForm.control}
                    name="phone"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Phone Number</FormLabel>
                        <FormControl>
                          <Input placeholder="+1234567890" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                <FormField
                  control={editStoreForm.control}
                  name="description"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Description</FormLabel>
                      <FormControl>
                        <Textarea
                          placeholder="Tell customers about your store"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={editStoreForm.control}
                  name="address"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Address</FormLabel>
                      <FormControl>
                        <Input placeholder="Store Address" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <div className="flex justify-end space-x-2">
                  <Button type="button" variant="outline" onClick={() => setIsEditStoreOpen(false)}>
                    Cancel
                  </Button>
                  <Button type="submit">
                    Update Store
                  </Button>
                </div>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}
