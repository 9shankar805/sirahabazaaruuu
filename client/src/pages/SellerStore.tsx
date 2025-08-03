import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "wouter";
import { 
  Store, Edit, MapPin, Phone, Globe, Star, Plus, Camera, Save, UtensilsCrossed, Clock, X, Link as LinkIcon
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import ImageUpload from "@/components/ImageUpload";
import { LocationPicker } from "@/components/LocationPicker";
import { useAuth } from "@/hooks/useAuth";
import { BackToDashboard } from "@/components/BackToDashboard";

// Enhanced validation schema with graceful error handling
const storeSchema = z.object({
  name: z.string().min(1, "Store name is required").transform(val => val.trim()),
  description: z.string().optional().default(""),
  address: z.string().min(1, "Address is required").transform(val => val.trim()),
  latitude: z.string().optional().default(""),
  longitude: z.string().optional().default(""),
  phone: z.string().optional().default("").transform(val => val?.trim() || ""),
  website: z.string()
    .optional()
    .default("")
    .transform(val => {
      if (!val || val.trim() === "") return "";
      const trimmed = val.trim();
      // Add https:// if no protocol is provided
      if (trimmed && !trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
        return `https://${trimmed}`;
      }
      return trimmed;
    })
    .pipe(z.string().url().optional().or(z.literal(""))),
  logo: z.string().optional().default(""),
  coverImage: z.string().optional().default(""),
  storeType: z.enum(["retail", "restaurant"]).default("retail"),
  cuisineType: z.string().optional().default(""),
  deliveryTime: z.string().optional().default(""),
  minimumOrder: z.string().optional().default("").transform(val => val?.trim() || ""),
  deliveryFee: z.string().optional().default("").transform(val => val?.trim() || ""),
  isDeliveryAvailable: z.boolean().default(false),
  openingHours: z.string().optional().default("")
});

interface StoreData {
  id: number;
  name: string;
  description: string;
  ownerId: number;
  address: string;
  latitude: string;
  longitude: string;
  phone: string;
  website: string;
  logo: string;
  coverImage: string;
  rating: string;
  totalReviews: number;
  featured: boolean;
  isActive: boolean;
  storeType: string;
  cuisineType?: string;
  deliveryTime?: string;
  minimumOrder?: number;
  deliveryFee?: number;
  isDeliveryAvailable: boolean;
  openingHours?: string;
  createdAt: string;
}

export default function SellerStore() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const { user: currentUser } = useAuth();

  const form = useForm<z.infer<typeof storeSchema>>({
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
      openingHours: ""
    }
  });

  // Store query
  const { data: stores, isLoading: storesLoading } = useQuery<StoreData[]>({
    queryKey: ['/api/stores/owner', currentUser?.id],
    enabled: !!currentUser?.id,
  });

  const userStore = stores?.[0]; // Assuming one store per user for now

  // Create store mutation with enhanced error handling
  const createStoreMutation = useMutation({
    mutationFn: async (data: z.infer<typeof storeSchema>) => {
      try {
        const response = await fetch('/api/stores', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            ...data,
            ownerId: currentUser?.id
          })
        });
        
        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          const errorMessage = errorData.message || `Store creation failed (${response.status})`;
          throw new Error(errorMessage);
        }
        
        return response.json();
      } catch (error) {
        // Handle network errors gracefully
        if (error instanceof TypeError && error.message.includes('fetch')) {
          throw new Error('Network connection error. Please check your internet connection.');
        }
        throw error;
      }
    },
    onSuccess: (data) => {
      const storeType = data.storeType || 'store';
      const storeTypeText = storeType === 'restaurant' ? 'restaurant' : 'retail store';
      
      toast({
        title: "Store Created Successfully!",
        description: `Your ${storeTypeText} "${data.name || 'store'}" is now live on Siraha Bazaar`,
      });
      
      queryClient.invalidateQueries({ queryKey: ['/api/stores/owner', currentUser?.id] });
      setIsCreateDialogOpen(false);
      form.reset();
    },
    onError: (error: Error) => {
      console.warn('Store creation error:', error.message);
      
      // User-friendly error messages
      let userMessage = "Unable to create your store right now. Please try again.";
      
      if (error.message.includes('network') || error.message.includes('connection')) {
        userMessage = "Network connection issue. Please check your internet and try again.";
      } else if (error.message.includes('duplicate') || error.message.includes('exists')) {
        userMessage = "A store with this name already exists. Please choose a different name.";
      } else if (error.message.includes('validation')) {
        userMessage = "Please check your store information and try again.";
      }
      
      toast({
        title: "Store Creation Issue",
        description: userMessage,
        variant: "destructive"
      });
    }
  });

  // Update store mutation with enhanced error handling
  const updateStoreMutation = useMutation({
    mutationFn: async (data: z.infer<typeof storeSchema>) => {
      try {
        const response = await fetch(`/api/stores/${userStore?.id}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(data)
        });
        
        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          const errorMessage = errorData.message || `Store update failed (${response.status})`;
          throw new Error(errorMessage);
        }
        
        return response.json();
      } catch (error) {
        // Handle network errors gracefully
        if (error instanceof TypeError && error.message.includes('fetch')) {
          throw new Error('Network connection error. Please check your internet connection.');
        }
        throw error;
      }
    },
    onSuccess: (data) => {
      const storeType = data.storeType || userStore?.storeType || 'store';
      const storeTypeText = storeType === 'restaurant' ? 'restaurant' : 'retail store';
      
      toast({
        title: "Store Updated Successfully!",
        description: `Your ${storeTypeText} information has been updated`,
      });
      
      queryClient.invalidateQueries({ queryKey: ['/api/stores/owner', currentUser?.id] });
      setIsEditDialogOpen(false);
    },
    onError: (error: Error) => {
      console.warn('Store update error:', error.message);
      
      // User-friendly error messages
      let userMessage = "Unable to update your store right now. Please try again.";
      
      if (error.message.includes('network') || error.message.includes('connection')) {
        userMessage = "Network connection issue. Please check your internet and try again.";
      } else if (error.message.includes('not found')) {
        userMessage = "Store not found. Please refresh the page and try again.";
      } else if (error.message.includes('validation')) {
        userMessage = "Please check your store information and try again.";
      }
      
      toast({
        title: "Store Update Issue",
        description: userMessage,
        variant: "destructive"
      });
    }
  });

  const handleCreateStore = (data: z.infer<typeof storeSchema>) => {
    // Clean the data before sending to prevent null value issues
    const cleanedData = {
      ...data,
      // Ensure all string fields are properly set
      name: data.name?.trim() || "",
      description: data.description || "",
      address: data.address?.trim() || "",
      phone: data.phone || "",
      website: data.website || "",
      logo: data.logo || "",
      coverImage: data.coverImage || "",
      latitude: data.latitude || "",
      longitude: data.longitude || "",
      cuisineType: data.cuisineType || "",
      deliveryTime: data.deliveryTime || "",
      minimumOrder: data.minimumOrder || "",
      deliveryFee: data.deliveryFee || "",
      openingHours: data.openingHours || "",
      // Set boolean properly
      isDeliveryAvailable: Boolean(data.isDeliveryAvailable),
      // Set store type properly
      storeType: data.storeType || "retail"
    };
    
    console.log('Creating store with cleaned data:', cleanedData);
    createStoreMutation.mutate(cleanedData);
  };

  const handleUpdateStore = (data: z.infer<typeof storeSchema>) => {
    // Clean the data before sending to prevent null value issues
    const cleanedData = {
      ...data,
      // Ensure all string fields are properly set
      name: data.name?.trim() || "",
      description: data.description || "",
      address: data.address?.trim() || "",
      phone: data.phone || "",
      website: data.website || "",
      logo: data.logo || "",
      coverImage: data.coverImage || "",
      latitude: data.latitude || "",
      longitude: data.longitude || "",
      cuisineType: data.cuisineType || "",
      deliveryTime: data.deliveryTime || "",
      minimumOrder: data.minimumOrder || "",
      deliveryFee: data.deliveryFee || "",
      openingHours: data.openingHours || "",
      // Set boolean properly
      isDeliveryAvailable: Boolean(data.isDeliveryAvailable),
      // Set store type properly
      storeType: data.storeType || "retail"
    };
    
    console.log('Updating store with cleaned data:', cleanedData);
    updateStoreMutation.mutate(cleanedData);
  };

  const openEditDialog = () => {
    if (userStore) {
      // Safely handle all store data with fallbacks
      form.reset({
        name: userStore.name || "",
        description: userStore.description || "",
        address: userStore.address || "",
        latitude: userStore.latitude || "",
        longitude: userStore.longitude || "",
        phone: userStore.phone || "",
        website: userStore.website || "",
        logo: userStore.logo || "",
        coverImage: userStore.coverImage || "",
        storeType: userStore.storeType === "restaurant" ? "restaurant" : "retail",
        cuisineType: userStore.cuisineType || "",
        deliveryTime: userStore.deliveryTime || "",
        minimumOrder: userStore.minimumOrder?.toString() || "",
        deliveryFee: userStore.deliveryFee?.toString() || "",
        isDeliveryAvailable: Boolean(userStore.isDeliveryAvailable),
        openingHours: userStore.openingHours || ""
      });
      setIsEditDialogOpen(true);
    }
  };

  const openCreateDialog = () => {
    // Reset form with proper defaults
    form.reset({
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
      openingHours: ""
    });
    setIsCreateDialogOpen(true);
  };

  if (!currentUser || currentUser.role !== 'shopkeeper') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle className="text-center text-red-600">Access Denied</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-center text-muted-foreground">
              You need to be a shopkeeper to access store management.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Check if shopkeeper is approved by admin
  if (currentUser.role === 'shopkeeper' && (currentUser as any).status !== 'active') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <Card className="w-full max-w-lg">
          <CardHeader>
            <CardTitle className="text-center text-yellow-600">
              Pending Admin Approval
            </CardTitle>
          </CardHeader>
          <CardContent className="text-center space-y-4">
            <div className="mx-auto w-16 h-16 rounded-full bg-yellow-100 dark:bg-yellow-900/20 flex items-center justify-center">
              <Clock className="h-8 w-8 text-yellow-600" />
            </div>
            <p className="text-muted-foreground">
              Your seller account is pending approval from our admin team. You cannot access store management until approved.
            </p>
            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <Link href="/">
                <Button variant="outline">Go to Homepage</Button>
              </Link>
              <Link href="/account">
                <Button variant="default">View Account Status</Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Store className="h-8 w-8 text-primary" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Store Management</h1>
                <p className="text-sm text-muted-foreground">Manage your store information and settings</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <BackToDashboard />
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {storesLoading ? (
          /* Loading State */
          <div className="space-y-6">
            <Card>
              <CardContent className="pt-6">
                <div className="flex flex-col md:flex-row items-start md:items-center space-y-4 md:space-y-0 md:space-x-6">
                  <div className="w-24 h-24 bg-gray-200 dark:bg-gray-700 rounded-lg animate-pulse"></div>
                  <div className="flex-1 space-y-3">
                    <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded animate-pulse"></div>
                    <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded animate-pulse w-3/4"></div>
                    <div className="flex gap-2">
                      <div className="h-6 w-20 bg-gray-200 dark:bg-gray-700 rounded animate-pulse"></div>
                      <div className="h-6 w-16 bg-gray-200 dark:bg-gray-700 rounded animate-pulse"></div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        ) : userStore ? (
          /* Existing Store Management */
          <div className="space-y-6">
            {/* Store Header */}
            <Card>
              <CardContent className="pt-6">
                <div className="flex flex-col md:flex-row items-start md:items-center space-y-4 md:space-y-0 md:space-x-6">
                  <div className="flex-shrink-0">
                    <div className="w-24 h-24 bg-gray-100 dark:bg-gray-800 rounded-lg flex items-center justify-center overflow-hidden">
                      {userStore.logo ? (
                        <img 
                          src={userStore.logo} 
                          alt={userStore.name || 'Store Logo'} 
                          className="w-full h-full object-cover"
                          onError={(e) => {
                            // Handle broken images gracefully
                            const target = e.target as HTMLImageElement;
                            target.style.display = 'none';
                            const fallback = target.parentElement?.querySelector('.fallback-icon') as HTMLElement;
                            if (fallback) fallback.style.display = 'block';
                          }}
                        />
                      ) : null}
                      <Store className={`h-12 w-12 text-muted-foreground fallback-icon ${userStore.logo ? 'hidden' : 'block'}`} />
                    </div>
                  </div>
                  <div className="flex-1">
                    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
                      <div>
                        <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
                          {userStore.name || 'My Store'}
                        </h2>
                        <p className="text-muted-foreground">
                          {userStore.description || 'No description added yet.'}
                        </p>
                        <div className="flex items-center space-x-4 mt-2">
                          <div className="flex items-center space-x-1">
                            <Star className="h-4 w-4 text-yellow-400 fill-current" />
                            <span className="text-sm">
                              {userStore.rating ? parseFloat(userStore.rating).toFixed(1) : '0.0'}
                            </span>
                            <span className="text-sm text-muted-foreground">
                              ({userStore.totalReviews || 0} reviews)
                            </span>
                          </div>
                          <Badge variant={userStore.storeType === 'restaurant' ? 'default' : 'secondary'}>
                            {userStore.storeType === 'restaurant' ? (
                              <><UtensilsCrossed className="h-3 w-3 mr-1" /> Restaurant</>
                            ) : (
                              <><Store className="h-3 w-3 mr-1" /> Retail</>
                            )}
                          </Badge>
                          <Badge variant={userStore.isActive ? 'default' : 'secondary'}>
                            {userStore.isActive ? 'Active' : 'Inactive'}
                          </Badge>
                        </div>
                      </div>
                      <Button onClick={openEditDialog} className="mt-4 sm:mt-0">
                        <Edit className="h-4 w-4 mr-2" />
                        Edit Store
                      </Button>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Store Details */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Contact Information</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-start space-x-3">
                    <MapPin className="h-5 w-5 text-muted-foreground mt-0.5" />
                    <div>
                      <p className="font-medium">Address</p>
                      <p className="text-muted-foreground">
                        {userStore.address || 'No address provided'}
                      </p>
                    </div>
                  </div>
                  {userStore.phone && userStore.phone.trim() && (
                    <div className="flex items-start space-x-3">
                      <Phone className="h-5 w-5 text-muted-foreground mt-0.5" />
                      <div>
                        <p className="font-medium">Phone</p>
                        <p className="text-muted-foreground">{userStore.phone}</p>
                      </div>
                    </div>
                  )}
                  {userStore.website && userStore.website.trim() && (
                    <div className="flex items-start space-x-3">
                      <Globe className="h-5 w-5 text-muted-foreground mt-0.5" />
                      <div>
                        <p className="font-medium">Website</p>
                        <a 
                          href={userStore.website} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-primary hover:underline break-all"
                        >
                          {userStore.website}
                        </a>
                      </div>
                    </div>
                  )}
                  {(!userStore.phone || !userStore.phone.trim()) && (!userStore.website || !userStore.website.trim()) && (
                    <div className="text-center py-4">
                      <p className="text-muted-foreground text-sm">
                        Add your phone number and website to help customers connect with you
                      </p>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Store Statistics</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-2xl font-bold">{userStore.totalReviews || 0}</p>
                      <p className="text-sm text-muted-foreground">Total Reviews</p>
                    </div>
                    <div>
                      <p className="text-2xl font-bold">
                        {userStore.rating ? parseFloat(userStore.rating).toFixed(1) : '0.0'}
                      </p>
                      <p className="text-sm text-muted-foreground">Average Rating</p>
                    </div>
                  </div>
                  <div className="pt-4">
                    <p className="text-sm text-muted-foreground">
                      Store created on {
                        userStore.createdAt 
                          ? new Date(userStore.createdAt).toLocaleDateString() 
                          : 'Unknown date'
                      }
                    </p>
                    {userStore.storeType === 'restaurant' && (
                      <div className="mt-2 space-y-1">
                        {userStore.cuisineType && (
                          <p className="text-sm text-muted-foreground">
                            <strong>Cuisine:</strong> {userStore.cuisineType}
                          </p>
                        )}
                        {userStore.deliveryTime && (
                          <p className="text-sm text-muted-foreground">
                            <strong>Delivery Time:</strong> {userStore.deliveryTime}
                          </p>
                        )}
                        {userStore.minimumOrder && (
                          <p className="text-sm text-muted-foreground">
                            <strong>Minimum Order:</strong> ₹{userStore.minimumOrder}
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Quick Actions */}
            <Card>
              <CardHeader>
                <CardTitle>Quick Actions</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <Link href="/seller/products/add">
                    <Button className="w-full">
                      <Plus className="h-4 w-4 mr-2" />
                      Add Product
                    </Button>
                  </Link>
                  <Link href="/seller/inventory">
                    <Button variant="outline" className="w-full">
                      View Inventory
                    </Button>
                  </Link>
                  <Link href="/seller/orders">
                    <Button variant="outline" className="w-full">
                      Manage Orders
                    </Button>
                  </Link>
                </div>
              </CardContent>
            </Card>
          </div>
        ) : (
          /* No Store - Create Store */
          <div className="max-w-4xl mx-auto">
            <Card>
              <CardHeader className="text-center">
                <div className="w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Store className="h-8 w-8 text-primary" />
                </div>
                <CardTitle className="text-2xl">Create Your Store</CardTitle>
                <p className="text-muted-foreground">
                  Set up your store to start selling products on Siraha Bazaar
                </p>
              </CardHeader>
              <CardContent>
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(handleCreateStore)} className="space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <FormField
                        control={form.control}
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
                        control={form.control}
                        name="storeType"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Store Type</FormLabel>
                            <Select onValueChange={field.onChange} defaultValue={field.value}>
                              <FormControl>
                                <SelectTrigger>
                                  <SelectValue placeholder="Select store type" />
                                </SelectTrigger>
                              </FormControl>
                              <SelectContent>
                                <SelectItem value="retail">Retail Store</SelectItem>
                                <SelectItem value="restaurant">Restaurant</SelectItem>
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
                            <Textarea placeholder="Tell customers about your store..." {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <LocationPicker
                      address={form.watch("address")}
                      latitude={form.watch("latitude")}
                      longitude={form.watch("longitude")}
                      onLocationChange={(data) => {
                        form.setValue("address", data.address);
                        form.setValue("latitude", data.latitude);
                        form.setValue("longitude", data.longitude);
                      }}
                    />

                    <FormField
                      control={form.control}
                      name="website"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Website (Optional)</FormLabel>
                          <FormControl>
                            <Input placeholder="https://mystore.com" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    {/* Restaurant-specific fields */}
                    {form.watch("storeType") === "restaurant" && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 border rounded-lg bg-orange-50 dark:bg-orange-950/20">
                        <div className="md:col-span-2">
                          <h3 className="text-lg font-medium text-orange-800 dark:text-orange-200 mb-2">
                            🍽️ Restaurant Information
                          </h3>
                          <p className="text-sm text-orange-700 dark:text-orange-300 mb-4">
                            Additional fields for restaurants
                          </p>
                        </div>
                        
                        <FormField
                          control={form.control}
                          name="phone"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Phone Number</FormLabel>
                              <FormControl>
                                <Input placeholder="+977-XXXXXXXXX" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="deliveryFee"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Delivery Fee (₹)</FormLabel>
                              <FormControl>
                                <Input placeholder="50" type="number" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="minimumOrder"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Minimum Order (₹)</FormLabel>
                              <FormControl>
                                <Input placeholder="300" type="number" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="deliveryTime"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Delivery Time</FormLabel>
                              <FormControl>
                                <Input placeholder="30-45 minutes" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="cuisineType"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Cuisine Type</FormLabel>
                              <FormControl>
                                <Input placeholder="Nepali, Indian, Chinese" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="openingHours"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Opening Hours</FormLabel>
                              <FormControl>
                                <Input placeholder="9:00 AM - 10:00 PM" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                    )}



                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <FormField
                        control={form.control}
                        name="logo"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Store Logo</FormLabel>
                            <FormControl>
                              <ImageUpload
                                label="Store Logo"
                                maxImages={1}
                                minImages={0}
                                onImagesChange={(images) => field.onChange(images[0] || "")}
                                initialImages={field.value ? [field.value] : []}
                                className="w-full"
                              />
                            </FormControl>
                            <div className="text-sm text-muted-foreground">
                              Auto-compressed to 200KB for fast loading
                            </div>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="coverImage"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Store Cover Image</FormLabel>
                            <FormControl>
                              <ImageUpload
                                label="Store Cover Image"
                                maxImages={1}
                                minImages={0}
                                onImagesChange={(images) => field.onChange(images[0] || "")}
                                initialImages={field.value ? [field.value] : []}
                                className="w-full"
                              />
                            </FormControl>
                            <div className="text-sm text-muted-foreground">
                              Auto-compressed to 200KB for fast loading
                            </div>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>

                    <div className="flex justify-center">
                      <Button type="submit" disabled={createStoreMutation.isPending} size="lg" className="w-full sm:w-auto px-8">
                        {createStoreMutation.isPending ? 'Creating...' : 'Create Store'}
                      </Button>
                    </div>
                  </form>
                </Form>
              </CardContent>
            </Card>
          </div>
        )}
      </div>



      {/* Edit Store Dialog */}
      <Dialog open={isEditDialogOpen} onOpenChange={setIsEditDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit Store Information</DialogTitle>
          </DialogHeader>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(handleUpdateStore)} className="space-y-4 pb-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <FormField
                  control={form.control}
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
                  control={form.control}
                  name="storeType"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Store Type</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select store type" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="retail">Retail Store</SelectItem>
                          <SelectItem value="restaurant">Restaurant</SelectItem>
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
                      <Textarea placeholder="Tell customers about your store..." {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <LocationPicker
                address={form.watch("address")}
                latitude={form.watch("latitude")}
                longitude={form.watch("longitude")}
                onLocationChange={(data) => {
                  form.setValue("address", data.address);
                  form.setValue("latitude", data.latitude);
                  form.setValue("longitude", data.longitude);
                }}
              />

              <FormField
                control={form.control}
                name="website"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Website (Optional)</FormLabel>
                    <FormControl>
                      <Input placeholder="https://mystore.com" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Image Upload Section */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="logo"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-base font-medium">Store Logo</FormLabel>
                      <div className="space-y-4">
                        {/* File Upload and Camera Options */}
                        <div className="space-y-3">
                          <div className="grid grid-cols-1 gap-4">
                            {/* File Upload */}
                            <div className="flex items-center justify-center w-full">
                              <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-gray-300 border-dashed rounded-lg cursor-pointer bg-gray-50 hover:bg-gray-100">
                                <div className="flex flex-col items-center justify-center pt-5 pb-6">
                                  <Plus className="w-6 h-6 mb-2 text-gray-500" />
                                  <p className="text-sm text-gray-500 font-semibold">Upload Logo</p>
                                  <p className="text-xs text-gray-500">PNG, JPG recommended</p>
                                </div>
                                <input
                                  type="file"
                                  className="hidden"
                                  accept="image/*"
                                  onChange={(e) => {
                                    const file = e.target.files?.[0];
                                    if (file) {
                                      const reader = new FileReader();
                                      reader.onload = (event) => {
                                        const imageUrl = event.target?.result as string;
                                        if (imageUrl) {
                                          field.onChange(imageUrl);
                                        }
                                      };
                                      reader.readAsDataURL(file);
                                    }
                                  }}
                                />
                              </label>
                            </div>

                            {/* Camera Capture */}
                            <div className="flex items-center justify-center w-full">
                              <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-orange-300 border-dashed rounded-lg cursor-pointer bg-orange-50 hover:bg-orange-100">
                                <div className="flex flex-col items-center justify-center pt-5 pb-6">
                                  <Camera className="w-6 h-6 mb-2 text-orange-500" />
                                  <p className="text-sm text-orange-600 font-semibold">Take Photo</p>
                                  <p className="text-xs text-orange-500">Camera capture</p>
                                </div>
                                <input
                                  type="file"
                                  className="hidden"
                                  accept="image/*"
                                  capture="environment"
                                  onChange={(e) => {
                                    const file = e.target.files?.[0];
                                    if (file) {
                                      const reader = new FileReader();
                                      reader.onload = (event) => {
                                        const imageUrl = event.target?.result as string;
                                        if (imageUrl) {
                                          field.onChange(imageUrl);
                                        }
                                      };
                                      reader.readAsDataURL(file);
                                    }
                                  }}
                                />
                              </label>
                            </div>
                          </div>

                          {/* URL Input Alternative */}
                          <div className="relative">
                            <Input
                              placeholder="Or paste image URL..."
                              value={field.value || ""}
                              onChange={(e) => field.onChange(e.target.value)}
                              className="pr-10"
                            />
                            <div className="absolute inset-y-0 right-0 pr-3 flex items-center">
                              <LinkIcon className="h-4 w-4 text-gray-400" />
                            </div>
                          </div>

                          {/* Image Preview */}
                          {field.value && (
                            <div className="relative">
                              <img
                                src={field.value}
                                alt="Store logo preview"
                                className="w-full h-24 object-cover rounded-lg border"
                              />
                              <Button
                                type="button"
                                variant="outline"
                                size="sm"
                                className="absolute top-2 right-2"
                                onClick={() => field.onChange("")}
                              >
                                <X className="h-4 w-4" />
                              </Button>
                            </div>
                          )}
                        </div>
                      </div>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="coverImage"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="text-base font-medium">Cover Image</FormLabel>
                      <div className="space-y-4">
                        {/* File Upload and Camera Options */}
                        <div className="space-y-3">
                          <div className="grid grid-cols-1 gap-4">
                            {/* File Upload */}
                            <div className="flex items-center justify-center w-full">
                              <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-gray-300 border-dashed rounded-lg cursor-pointer bg-gray-50 hover:bg-gray-100">
                                <div className="flex flex-col items-center justify-center pt-5 pb-6">
                                  <Plus className="w-6 h-6 mb-2 text-gray-500" />
                                  <p className="text-sm text-gray-500 font-semibold">Upload Cover</p>
                                  <p className="text-xs text-gray-500">Wide format preferred</p>
                                </div>
                                <input
                                  type="file"
                                  className="hidden"
                                  accept="image/*"
                                  onChange={(e) => {
                                    const file = e.target.files?.[0];
                                    if (file) {
                                      const reader = new FileReader();
                                      reader.onload = (event) => {
                                        const imageUrl = event.target?.result as string;
                                        if (imageUrl) {
                                          field.onChange(imageUrl);
                                        }
                                      };
                                      reader.readAsDataURL(file);
                                    }
                                  }}
                                />
                              </label>
                            </div>

                            {/* Camera Capture */}
                            <div className="flex items-center justify-center w-full">
                              <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-orange-300 border-dashed rounded-lg cursor-pointer bg-orange-50 hover:bg-orange-100">
                                <div className="flex flex-col items-center justify-center pt-5 pb-6">
                                  <Camera className="w-6 h-6 mb-2 text-orange-500" />
                                  <p className="text-sm text-orange-600 font-semibold">Take Photo</p>
                                  <p className="text-xs text-orange-500">Camera capture</p>
                                </div>
                                <input
                                  type="file"
                                  className="hidden"
                                  accept="image/*"
                                  capture="environment"
                                  onChange={(e) => {
                                    const file = e.target.files?.[0];
                                    if (file) {
                                      const reader = new FileReader();
                                      reader.onload = (event) => {
                                        const imageUrl = event.target?.result as string;
                                        if (imageUrl) {
                                          field.onChange(imageUrl);
                                        }
                                      };
                                      reader.readAsDataURL(file);
                                    }
                                  }}
                                />
                              </label>
                            </div>
                          </div>

                          {/* URL Input Alternative */}
                          <div className="relative">
                            <Input
                              placeholder="Or paste image URL..."
                              value={field.value || ""}
                              onChange={(e) => field.onChange(e.target.value)}
                              className="pr-10"
                            />
                            <div className="absolute inset-y-0 right-0 pr-3 flex items-center">
                              <LinkIcon className="h-4 w-4 text-gray-400" />
                            </div>
                          </div>

                          {/* Image Preview */}
                          {field.value && (
                            <div className="relative">
                              <img
                                src={field.value}
                                alt="Store cover preview"
                                className="w-full h-24 object-cover rounded-lg border"
                              />
                              <Button
                                type="button"
                                variant="outline"
                                size="sm"
                                className="absolute top-2 right-2"
                                onClick={() => field.onChange("")}
                              >
                                <X className="h-4 w-4" />
                              </Button>
                            </div>
                          )}
                        </div>
                      </div>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              {/* Restaurant-specific fields for edit form */}
              {form.watch("storeType") === "restaurant" && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 border rounded-lg bg-orange-50 dark:bg-orange-950/20">
                  <div className="md:col-span-2">
                    <h3 className="text-lg font-medium text-orange-800 dark:text-orange-200 mb-2">
                      🍽️ Restaurant Information
                    </h3>
                  </div>
                  
                  <FormField
                    control={form.control}
                    name="phone"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Phone Number</FormLabel>
                        <FormControl>
                          <Input placeholder="+977-XXXXXXXXX" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="deliveryFee"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Delivery Fee (₹)</FormLabel>
                        <FormControl>
                          <Input placeholder="50" type="number" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="minimumOrder"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Minimum Order (₹)</FormLabel>
                        <FormControl>
                          <Input placeholder="300" type="number" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="deliveryTime"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Delivery Time</FormLabel>
                        <FormControl>
                          <Input placeholder="30-45 minutes" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="cuisineType"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Cuisine Type</FormLabel>
                        <FormControl>
                          <Input placeholder="Nepali, Indian, Chinese" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="openingHours"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Opening Hours</FormLabel>
                        <FormControl>
                          <Input placeholder="9:00 AM - 10:00 PM" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
              )}

              <div className="flex justify-end space-x-2">
                <Button type="button" variant="outline" onClick={() => setIsEditDialogOpen(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={updateStoreMutation.isPending}>
                  {updateStoreMutation.isPending ? 'Updating...' : 'Update Store'}
                </Button>
              </div>
            </form>
          </Form>
        </DialogContent>
      </Dialog>
    </div>
  );
}