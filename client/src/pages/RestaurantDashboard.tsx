import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "wouter";
import { useAuth } from "@/hooks/useAuth";
import { 
  ChefHat, Clock, Coffee, Utensils, MapPin, Phone, Mail, Globe,
  CheckCircle, XCircle, AlertCircle, Timer, Receipt, Truck,
  DollarSign, TrendingUp, Users, Star, Eye, BarChart3, Settings,
  Plus, Edit, Trash2, Search, Calendar, Package, Bell
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";

interface RestaurantStats {
  totalMenuItems: number;
  todayOrders: number;
  todayRevenue: number;
  pendingOrders: number;
  preparingOrders: number;
  readyOrders: number;
  averageRating: number;
  totalReviews: number;
  averagePreparationTime: number;
  tablesOccupied: number;
  totalTables: number;
  staffOnDuty: number;
}

interface Order {
  id: number;
  orderNumber: string;
  customerName: string;
  items: string[];
  total: number;
  status: 'pending' | 'preparing' | 'ready' | 'delivered' | 'cancelled';
  orderTime: string;
  estimatedTime: number;
  tableNumber?: number;
  deliveryAddress?: string;
  orderType: 'dine-in' | 'takeout' | 'delivery';
}

interface MenuItem {
  id: number;
  name: string;
  description: string;
  price: number;
  category: string;
  preparationTime: number;
  availability: boolean;
  ingredients: string[];
  allergens: string[];
  isVegetarian: boolean;
  isVegan: boolean;
  spiceLevel: string;
  image: string;
}

export default function RestaurantDashboard() {
  const { toast } = useToast();
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState("overview");
  const [selectedPeriod, setSelectedPeriod] = useState('today');

  // Mock data for demonstration - replace with real API calls
  const restaurantStats: RestaurantStats = {
    totalMenuItems: 45,
    todayOrders: 127,
    todayRevenue: 3250,
    pendingOrders: 8,
    preparingOrders: 12,
    readyOrders: 3,
    averageRating: 4.7,
    totalReviews: 342,
    averagePreparationTime: 18,
    tablesOccupied: 15,
    totalTables: 20,
    staffOnDuty: 8
  };

  const recentOrders: Order[] = [
    {
      id: 1,
      orderNumber: "ORD-001",
      customerName: "John Doe",
      items: ["Chicken Biryani", "Mango Lassi"],
      total: 25.99,
      status: "preparing",
      orderTime: "2:30 PM",
      estimatedTime: 15,
      tableNumber: 7,
      orderType: "dine-in"
    },
    {
      id: 2,
      orderNumber: "ORD-002",
      customerName: "Sarah Wilson",
      items: ["Vegetable Curry", "Naan", "Rice"],
      total: 18.50,
      status: "ready",
      orderTime: "2:25 PM",
      estimatedTime: 0,
      orderType: "takeout"
    },
    {
      id: 3,
      orderNumber: "ORD-003",
      customerName: "Mike Johnson",
      items: ["Tandoori Chicken", "Garlic Naan"],
      total: 22.75,
      status: "pending",
      orderTime: "2:35 PM",
      estimatedTime: 20,
      deliveryAddress: "123 Main St",
      orderType: "delivery"
    }
  ];

  const salesData = [
    { time: '9 AM', orders: 5, revenue: 125 },
    { time: '10 AM', orders: 8, revenue: 200 },
    { time: '11 AM', orders: 12, revenue: 300 },
    { time: '12 PM', orders: 25, revenue: 625 },
    { time: '1 PM', orders: 30, revenue: 750 },
    { time: '2 PM', orders: 22, revenue: 550 },
    { time: '3 PM', orders: 15, revenue: 375 },
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pending': return 'bg-yellow-500';
      case 'preparing': return 'bg-blue-500';
      case 'ready': return 'bg-green-500';
      case 'delivered': return 'bg-gray-500';
      case 'cancelled': return 'bg-red-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending': return <Clock className="h-4 w-4" />;
      case 'preparing': return <ChefHat className="h-4 w-4" />;
      case 'ready': return <CheckCircle className="h-4 w-4" />;
      case 'delivered': return <Truck className="h-4 w-4" />;
      case 'cancelled': return <XCircle className="h-4 w-4" />;
      default: return <AlertCircle className="h-4 w-4" />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <ChefHat className="h-8 w-8 text-orange-600" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Restaurant Dashboard</h1>
                <p className="text-sm text-muted-foreground">Manage your restaurant operations</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <Button variant="outline" size="sm">
                <Bell className="h-4 w-4 mr-2" />
                Notifications
              </Button>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                New Order
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-6">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="orders">Orders</TabsTrigger>
            <TabsTrigger value="menu">Menu</TabsTrigger>
            <TabsTrigger value="tables">Tables</TabsTrigger>
            <TabsTrigger value="staff">Staff</TabsTrigger>
            <TabsTrigger value="analytics">Analytics</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-6">
            {/* Quick Stats */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Today's Orders</CardTitle>
                  <Receipt className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{restaurantStats.todayOrders}</div>
                  <p className="text-xs text-muted-foreground">
                    +12% from yesterday
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Today's Revenue</CardTitle>
                  <DollarSign className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">${restaurantStats.todayRevenue}</div>
                  <p className="text-xs text-muted-foreground">
                    +8% from yesterday
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Active Orders</CardTitle>
                  <ChefHat className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {restaurantStats.pendingOrders + restaurantStats.preparingOrders}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {restaurantStats.readyOrders} ready for pickup
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Tables Occupied</CardTitle>
                  <Utensils className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {restaurantStats.tablesOccupied}/{restaurantStats.totalTables}
                  </div>
                  <Progress 
                    value={(restaurantStats.tablesOccupied / restaurantStats.totalTables) * 100} 
                    className="mt-2"
                  />
                </CardContent>
              </Card>
            </div>

            {/* Order Status Overview */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <Card className="lg:col-span-2">
                <CardHeader>
                  <CardTitle>Recent Orders</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {recentOrders.map((order) => (
                      <div key={order.id} className="flex items-center justify-between p-4 border rounded-lg">
                        <div className="flex items-center space-x-4">
                          <div className={`p-2 rounded-full text-white ${getStatusColor(order.status)}`}>
                            {getStatusIcon(order.status)}
                          </div>
                          <div>
                            <div className="font-medium">{order.orderNumber}</div>
                            <div className="text-sm text-muted-foreground">
                              {order.customerName} • {order.orderTime}
                            </div>
                            <div className="text-xs text-muted-foreground">
                              {order.items.join(', ')}
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="font-medium">${order.total}</div>
                          <Badge variant={order.status === 'ready' ? 'default' : 'secondary'}>
                            {order.status}
                          </Badge>
                          {order.estimatedTime > 0 && (
                            <div className="text-xs text-muted-foreground mt-1">
                              {order.estimatedTime} min
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Kitchen Status</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Pending Orders</span>
                    <Badge variant="outline">{restaurantStats.pendingOrders}</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Preparing</span>
                    <Badge variant="outline">{restaurantStats.preparingOrders}</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Ready</span>
                    <Badge variant="default">{restaurantStats.readyOrders}</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Avg. Prep Time</span>
                    <span className="text-sm font-medium">{restaurantStats.averagePreparationTime} min</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Staff on Duty</span>
                    <span className="text-sm font-medium">{restaurantStats.staffOnDuty}</span>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Sales Chart */}
            <Card>
              <CardHeader>
                <CardTitle>Today's Sales</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={salesData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis yAxisId="left" />
                    <YAxis yAxisId="right" orientation="right" />
                    <Tooltip />
                    <Legend />
                    <Area
                      yAxisId="left"
                      type="monotone"
                      dataKey="orders"
                      stackId="1"
                      stroke="#8884d8"
                      fill="#8884d8"
                      name="Orders"
                    />
                    <Area
                      yAxisId="right"
                      type="monotone"
                      dataKey="revenue"
                      stackId="2"
                      stroke="#82ca9d"
                      fill="#82ca9d"
                      name="Revenue ($)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Orders Tab */}
          <TabsContent value="orders" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Order Management</h2>
              <div className="flex space-x-2">
                <Input placeholder="Search orders..." className="w-64" />
                <Button variant="outline">Filter</Button>
                <Button>New Order</Button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Pending Orders */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <Clock className="h-5 w-5 mr-2 text-yellow-500" />
                    Pending ({restaurantStats.pendingOrders})
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {recentOrders.filter(o => o.status === 'pending').map((order) => (
                      <div key={order.id} className="p-3 border rounded-lg">
                        <div className="flex justify-between items-start">
                          <div>
                            <div className="font-medium">{order.orderNumber}</div>
                            <div className="text-sm text-muted-foreground">{order.customerName}</div>
                            <div className="text-xs text-muted-foreground">{order.orderTime}</div>
                          </div>
                          <div className="text-right">
                            <div className="font-medium">${order.total}</div>
                            <Button size="sm" className="mt-1">Start</Button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Preparing Orders */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <ChefHat className="h-5 w-5 mr-2 text-blue-500" />
                    Preparing ({restaurantStats.preparingOrders})
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {recentOrders.filter(o => o.status === 'preparing').map((order) => (
                      <div key={order.id} className="p-3 border rounded-lg">
                        <div className="flex justify-between items-start">
                          <div>
                            <div className="font-medium">{order.orderNumber}</div>
                            <div className="text-sm text-muted-foreground">{order.customerName}</div>
                            <div className="text-xs text-muted-foreground">{order.estimatedTime} min left</div>
                          </div>
                          <div className="text-right">
                            <div className="font-medium">${order.total}</div>
                            <Button size="sm" variant="outline" className="mt-1">Ready</Button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Ready Orders */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <CheckCircle className="h-5 w-5 mr-2 text-green-500" />
                    Ready ({restaurantStats.readyOrders})
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {recentOrders.filter(o => o.status === 'ready').map((order) => (
                      <div key={order.id} className="p-3 border rounded-lg bg-green-50 dark:bg-green-900/20">
                        <div className="flex justify-between items-start">
                          <div>
                            <div className="font-medium">{order.orderNumber}</div>
                            <div className="text-sm text-muted-foreground">{order.customerName}</div>
                            <div className="text-xs text-green-600">Ready for pickup</div>
                          </div>
                          <div className="text-right">
                            <div className="font-medium">${order.total}</div>
                            <Button size="sm" variant="default" className="mt-1">Complete</Button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Menu Tab */}
          <TabsContent value="menu" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Menu Management</h2>
              <div className="flex space-x-2">
                <Link href="/seller/products/add">
                  <Button>
                    <Plus className="h-4 w-4 mr-2" />
                    Add Menu Item
                  </Button>
                </Link>
              </div>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Menu Categories</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  <Card className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium">Appetizers</h3>
                        <p className="text-sm text-muted-foreground">8 items</p>
                      </div>
                      <Button variant="outline" size="sm">Manage</Button>
                    </div>
                  </Card>
                  <Card className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium">Main Courses</h3>
                        <p className="text-sm text-muted-foreground">15 items</p>
                      </div>
                      <Button variant="outline" size="sm">Manage</Button>
                    </div>
                  </Card>
                  <Card className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium">Beverages</h3>
                        <p className="text-sm text-muted-foreground">12 items</p>
                      </div>
                      <Button variant="outline" size="sm">Manage</Button>
                    </div>
                  </Card>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Tables Tab */}
          <TabsContent value="tables" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Table Management</h2>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                Add Table
              </Button>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Table Status</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-4">
                  {Array.from({ length: 20 }, (_, i) => i + 1).map((tableNum) => (
                    <Card key={tableNum} className={`p-4 text-center cursor-pointer transition-colors ${
                      tableNum <= restaurantStats.tablesOccupied 
                        ? 'bg-red-50 dark:bg-red-900/20 border-red-200' 
                        : 'bg-green-50 dark:bg-green-900/20 border-green-200'
                    }`}>
                      <div className="font-medium">Table {tableNum}</div>
                      <div className={`text-sm ${
                        tableNum <= restaurantStats.tablesOccupied 
                          ? 'text-red-600' 
                          : 'text-green-600'
                      }`}>
                        {tableNum <= restaurantStats.tablesOccupied ? 'Occupied' : 'Available'}
                      </div>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Staff Tab */}
          <TabsContent value="staff" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Staff Management</h2>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                Add Staff
              </Button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Staff on Duty</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{restaurantStats.staffOnDuty}</div>
                  <p className="text-sm text-muted-foreground">out of 12 total staff</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Kitchen Staff</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">5</div>
                  <p className="text-sm text-muted-foreground">chefs and cooks</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Service Staff</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">3</div>
                  <p className="text-sm text-muted-foreground">waiters and servers</p>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Analytics Tab */}
          <TabsContent value="analytics" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Restaurant Analytics</h2>
              <div className="flex space-x-2">
                <Button variant="outline" size="sm">Export Report</Button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Average Rating</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center space-x-2">
                    <Star className="h-5 w-5 text-yellow-500 fill-current" />
                    <span className="text-2xl font-bold">{restaurantStats.averageRating}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{restaurantStats.totalReviews} reviews</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Avg. Prep Time</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{restaurantStats.averagePreparationTime} min</div>
                  <p className="text-xs text-muted-foreground">-2 min from last week</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Menu Items</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{restaurantStats.totalMenuItems}</div>
                  <p className="text-xs text-muted-foreground">across all categories</p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Table Turnover</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">3.2x</div>
                  <p className="text-xs text-muted-foreground">tables per day</p>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Weekly Sales Trend</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={400}>
                  <LineChart data={[
                    { day: 'Mon', orders: 45, revenue: 1125 },
                    { day: 'Tue', orders: 52, revenue: 1300 },
                    { day: 'Wed', orders: 48, revenue: 1200 },
                    { day: 'Thu', orders: 61, revenue: 1525 },
                    { day: 'Fri', orders: 75, revenue: 1875 },
                    { day: 'Sat', orders: 88, revenue: 2200 },
                    { day: 'Sun', orders: 67, revenue: 1675 }
                  ]}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="day" />
                    <YAxis yAxisId="left" />
                    <YAxis yAxisId="right" orientation="right" />
                    <Tooltip />
                    <Legend />
                    <Line yAxisId="left" type="monotone" dataKey="orders" stroke="#8884d8" name="Orders" />
                    <Line yAxisId="right" type="monotone" dataKey="revenue" stroke="#82ca9d" name="Revenue ($)" />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}