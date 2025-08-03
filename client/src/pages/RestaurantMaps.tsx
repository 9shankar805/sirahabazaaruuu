import { useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import RestaurantMap from "@/components/RestaurantMap";
import NotificationCenter from "@/components/NotificationCenter";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Utensils, MapPin, Clock, Car, DollarSign } from "lucide-react";

export default function RestaurantMaps() {
  const { user } = useAuth();
  const [cuisineFilter, setCuisineFilter] = useState("all");

  const cuisineTypes = [
    { value: "all", label: "All Cuisines" },
    { value: "indian", label: "Indian" },
    { value: "chinese", label: "Chinese" },
    { value: "fast-food", label: "Fast Food" },
    { value: "italian", label: "Italian" },
    { value: "nepali", label: "Nepali" },
    { value: "continental", label: "Continental" },
    { value: "thai", label: "Thai" },
    { value: "pizza", label: "Pizza" },
    { value: "burger", label: "Burger" },
    { value: "dessert", label: "Dessert" }
  ];

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2 flex items-center gap-2">
          <Utensils className="h-8 w-8 text-red-600" />
          Restaurant Locations & Food Delivery
        </h1>
        <p className="text-gray-600">
          Find nearby restaurants, check delivery options, and get directions
        </p>
      </div>

      {/* Cuisine Filter */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="text-lg">Filter by Cuisine</CardTitle>
          <CardDescription>Choose your preferred cuisine type</CardDescription>
        </CardHeader>
        <CardContent>
          <Select value={cuisineFilter} onValueChange={setCuisineFilter}>
            <SelectTrigger className="w-full md:w-64">
              <SelectValue placeholder="Select cuisine type" />
            </SelectTrigger>
            <SelectContent>
              {cuisineTypes.map((cuisine) => (
                <SelectItem key={cuisine.value} value={cuisine.value}>
                  {cuisine.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <RestaurantMap cuisineFilter={cuisineFilter} />
        </div>
        
        <div className="space-y-6">
          {user && (
            <NotificationCenter userId={user.id} />
          )}
          
          <Card>
            <CardHeader>
              <CardTitle>How Food Delivery Works</CardTitle>
              <CardDescription>Order food from local restaurants</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <h4 className="font-medium flex items-center gap-2">
                  <MapPin className="h-4 w-4 text-red-600" />
                  1. Find Restaurants
                </h4>
                <p className="text-sm text-gray-600">
                  Share your location to discover nearby restaurants and their menus
                </p>
              </div>
              
              <div className="space-y-2">
                <h4 className="font-medium flex items-center gap-2">
                  <Clock className="h-4 w-4 text-red-600" />
                  2. Check Delivery Time
                </h4>
                <p className="text-sm text-gray-600">
                  View estimated delivery times and minimum order requirements
                </p>
              </div>
              
              <div className="space-y-2">
                <h4 className="font-medium flex items-center gap-2">
                  <DollarSign className="h-4 w-4 text-red-600" />
                  3. Place Your Order
                </h4>
                <p className="text-sm text-gray-600">
                  Browse menus, add items to cart, and complete your order
                </p>
              </div>

              <div className="space-y-2">
                <h4 className="font-medium flex items-center gap-2">
                  <Car className="h-4 w-4 text-red-600" />
                  4. Track Delivery
                </h4>
                <p className="text-sm text-gray-600">
                  Get real-time updates on your order status and delivery progress
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Delivery Features</CardTitle>
              <CardDescription>What we offer</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span>Real-time order tracking</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span>Multiple payment options</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span>Live location sharing with restaurants</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span>Cuisine-based filtering</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span>Distance-based restaurant discovery</span>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}