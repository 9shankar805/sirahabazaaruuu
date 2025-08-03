import { useState } from "react";
import { Utensils, MapPin, Clock, Star, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import ModernFoodFilter from "@/components/ModernFoodFilter";

export default function FoodDelivery() {
  const [searchQuery, setSearchQuery] = useState("");

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Hero Section */}
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-2 flex items-center gap-3">
          <Utensils className="h-10 w-10 text-orange-600" />
          Food Delivery
        </h1>
        <p className="text-gray-600 text-lg">
          Modern food delivery with 10km radius filtering - just like the apps you love
        </p>
      </div>

      {/* Key Features */}
      <Card className="mb-8 bg-gradient-to-r from-orange-50 to-red-50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-orange-700">
            <Zap className="h-5 w-5" />
            Modern Food Delivery Features
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center gap-3">
              <MapPin className="h-8 w-8 text-orange-600 flex-shrink-0" />
              <div>
                <h3 className="font-semibold">10km Radius</h3>
                <p className="text-sm text-gray-600">Only show restaurants and food within delivery range</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Clock className="h-8 w-8 text-orange-600 flex-shrink-0" />
              <div>
                <h3 className="font-semibold">Real-time Distance</h3>
                <p className="text-sm text-gray-600">Sort by delivery time and distance automatically</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Star className="h-8 w-8 text-orange-600 flex-shrink-0" />
              <div>
                <h3 className="font-semibold">Smart Filtering</h3>
                <p className="text-sm text-gray-600">Filter by cuisine, spice level, and dietary preferences</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Search Bar */}
      <Card className="mb-6">
        <CardContent className="pt-6">
          <div className="relative">
            <Input
              type="text"
              placeholder="Search for food, restaurants, or cuisine..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 pr-4 py-3 text-lg"
            />
            <Utensils className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
          </div>
          <div className="flex flex-wrap gap-2 mt-4">
            <Badge variant="secondary" className="cursor-pointer hover:bg-orange-100">
              <Button 
                variant="ghost" 
                size="sm" 
                className="p-0 h-auto font-normal" 
                onClick={() => setSearchQuery("Pizza")}
              >
                🍕 Pizza
              </Button>
            </Badge>
            <Badge variant="secondary" className="cursor-pointer hover:bg-orange-100">
              <Button 
                variant="ghost" 
                size="sm" 
                className="p-0 h-auto font-normal" 
                onClick={() => setSearchQuery("Burger")}
              >
                🍔 Burgers
              </Button>
            </Badge>
            <Badge variant="secondary" className="cursor-pointer hover:bg-orange-100">
              <Button 
                variant="ghost" 
                size="sm" 
                className="p-0 h-auto font-normal" 
                onClick={() => setSearchQuery("Indian")}
              >
                🍛 Indian
              </Button>
            </Badge>
            <Badge variant="secondary" className="cursor-pointer hover:bg-orange-100">
              <Button 
                variant="ghost" 
                size="sm" 
                className="p-0 h-auto font-normal" 
                onClick={() => setSearchQuery("Chinese")}
              >
                🥡 Chinese
              </Button>
            </Badge>
            <Badge variant="secondary" className="cursor-pointer hover:bg-orange-100">
              <Button 
                variant="ghost" 
                size="sm" 
                className="p-0 h-auto font-normal" 
                onClick={() => setSearchQuery("Vegetarian")}
              >
                🥗 Vegetarian
              </Button>
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* Modern Food Filter Component */}
      <ModernFoodFilter 
        searchQuery={searchQuery} 
        className="w-full"
      />
    </div>
  );
}