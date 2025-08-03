import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useUser } from "@/hooks/use-user";
import { Truck, Package, DollarSign, Clock, MapPin, CheckCircle, Star, Bell, TrendingUp, Calendar, Navigation, Phone, AlertCircle, Timer, Home, AlertTriangle, Activity, History, Wallet, User } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useState, useEffect } from "react";
import DeliveryNotifications from "@/components/DeliveryNotifications";
import DeliveryPartnerProfileSetup from "@/components/DeliveryPartnerProfileSetup";
import DeliveryMap from "@/components/DeliveryMap";

import SoundTestButton from "@/components/SoundTestButton";

// Timer component for delivery time tracking
const DeliveryTimer = ({ createdAt, estimatedTime }: { createdAt: string; estimatedTime: number }) => {
  const [elapsedTime, setElapsedTime] = useState(0);
  const [isOverdue, setIsOverdue] = useState(false);

  useEffect(() => {
    const interval = setInterval(() => {
      const now = new Date();
      const start = new Date(createdAt);
      const elapsed = Math.floor((now.getTime() - start.getTime()) / 1000 / 60); // minutes
      setElapsedTime(elapsed);
      setIsOverdue(elapsed > estimatedTime);
    }, 1000);

    return () => clearInterval(interval);
  }, [createdAt, estimatedTime]);

  const formatTime = (minutes: number) => {
    if (minutes < 60) {
      return `${minutes}m`;
    }
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return `${hours}h ${mins}m`;
  };

  const remainingTime = Math.max(0, estimatedTime - elapsedTime);
  const progress = Math.min(100, (elapsedTime / estimatedTime) * 100);

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs">
        <div className="flex items-center gap-1">
          <Timer className="h-3 w-3" />
          <span className={isOverdue ? 'text-red-600 font-medium' : 'text-gray-600'}>
            {formatTime(elapsedTime)} elapsed
          </span>
        </div>
        <div className={`text-xs ${isOverdue ? 'text-red-600 font-medium' : 'text-green-600'}`}>
          {isOverdue ? 'Overdue' : `${formatTime(remainingTime)} left`}
        </div>
      </div>
      <div className="w-full bg-gray-200 rounded-full h-1.5">
        <div 
          className={`h-1.5 rounded-full transition-all duration-1000 ${
            isOverdue ? 'bg-red-500' : 'bg-green-500'
          }`}
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className="text-xs text-gray-500 text-center">
        Target: {formatTime(estimatedTime)} | Status: {isOverdue ? 'Behind Schedule' : 'On Track'}
      </div>
    </div>
  );
};

interface DeliveryPartner {
  id: number;
  userId: number;
  vehicleType: string;
  vehicleNumber: string;
  drivingLicense: string;
  idProofType: string;
  idProofNumber: string;
  deliveryAreas: string[];
  emergencyContact: string;
  bankAccountNumber: string;
  ifscCode: string;
  status: string;
  isAvailable: boolean;
  currentLocation: string | null;
  totalDeliveries: number;
  totalEarnings: string;
  rating: number | null;
  createdAt: string;
}

interface Delivery {
  id: number;
  orderId: number;
  deliveryFee: string;
  pickupAddress: string;
  deliveryAddress: string;
  estimatedDistance: number;
  status: string;
  assignedAt: string | null;
  pickedUpAt: string | null;
  deliveredAt: string | null;
  customerFeedback: string | null;
  customerRating: number | null;
  createdAt: string;
  customerName?: string;
  customerPhone?: string;
  totalAmount?: string;
}

interface DeliveryPartnerStats {
  totalDeliveries: number;
  totalEarnings: number;
  rating: number;
  todayDeliveries: number;
  todayEarnings: number;
  activeDeliveries: number;
}

export default function DeliveryPartnerDashboard() {
  const { user } = useUser();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedTab, setSelectedTab] = useState("dashboard");

  const { data: partner, isLoading: partnerLoading, error: partnerError } = useQuery({
    queryKey: ['/api/delivery-partners/user', user?.id],
    queryFn: async () => {
      const response = await fetch(`/api/delivery-partners/user?userId=${user?.id}`);
      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw new Error('Failed to fetch partner data');
      }
      return response.json();
    },
    enabled: !!user?.id,
    retry: 2,
  });

  const { data: deliveries = [], isLoading: deliveriesLoading } = useQuery({
    queryKey: ['/api/deliveries/partner', partner?.id],
    queryFn: async () => {
      const response = await fetch(`/api/deliveries/partner/${partner?.id}`);
      if (!response.ok) {
        return [];
      }
      return response.json();
    },
    enabled: !!partner?.id,
  });

  const { data: activeDeliveriesData = [], isLoading: activeDeliveriesLoading } = useQuery({
    queryKey: ['/api/deliveries/active', user?.id],
    queryFn: async () => {
      const response = await fetch(`/api/deliveries/active/${user?.id}`);
      if (!response.ok) {
        return [];
      }
      return response.json();
    },
    enabled: !!user?.id,
    refetchInterval: 5000, // Refresh active deliveries every 5 seconds
  });

  const { data: stats } = useQuery({
    queryKey: ['/api/delivery-partners/stats', partner?.id],
    queryFn: async () => {
      const response = await fetch(`/api/delivery-partners/${partner?.id}/stats`);
      if (!response.ok) {
        return {
          totalDeliveries: partner?.totalDeliveries || 0,
          totalEarnings: parseFloat(partner?.totalEarnings || '0'),
          rating: partner?.rating ? parseFloat(partner.rating.toString()) : 0,
          todayDeliveries: 0,
          todayEarnings: 0,
          activeDeliveries: Array.isArray(deliveries) ? deliveries.filter((d: Delivery) => ['assigned', 'picked_up'].includes(d.status)).length : 0
        };
      }
      return response.json();
    },
    enabled: !!partner?.id,
  });

  const updateDeliveryStatus = useMutation({
    mutationFn: async ({ deliveryId, status }: { deliveryId: number; status: string }) => {
      const response = await fetch(`/api/deliveries/${deliveryId}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, partnerId: partner?.id }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/deliveries/partner'] });
      toast({
        title: "Status Updated",
        description: "Delivery status has been updated successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to update delivery status.",
        variant: "destructive",
      });
    },
  });

  const toggleAvailability = useMutation({
    mutationFn: async (isAvailable: boolean) => {
      const response = await fetch(`/api/delivery-partners/${partner?.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ isAvailable }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/delivery-partners/user'] });
      toast({
        title: "Availability Updated",
        description: "Your availability status has been updated.",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to update delivery status.",
        variant: "destructive",
      });
    },
  });

  if (partnerLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-4">
        <div className="text-center max-w-sm w-full">
          <div className="animate-spin rounded-full h-12 w-12 sm:h-16 sm:w-16 border-b-4 border-blue-600 mx-auto mb-4 sm:mb-6"></div>
          <h2 className="text-lg sm:text-2xl font-semibold text-gray-700 mb-2">Loading Dashboard</h2>
          <p className="text-sm sm:text-base text-gray-500">Please wait while we fetch your information...</p>
        </div>
      </div>
    );
  }

  if (!partner) {
    return <DeliveryPartnerProfileSetup userId={user?.id || 0} />;
  }

  const deliveriesArray = Array.isArray(deliveries) ? deliveries : [];
  const activeDeliveriesArray = Array.isArray(activeDeliveriesData) ? activeDeliveriesData : [];
  const pendingDeliveries = deliveriesArray.filter((d: Delivery) => d.status === 'assigned');
  const completedDeliveries = deliveriesArray.filter((d: Delivery) => d.status === 'delivered');

  const currentStats = stats || {
    totalDeliveries: partner?.totalDeliveries || 0,
    totalEarnings: parseFloat(partner?.totalEarnings || '0'),
    rating: partner?.rating ? parseFloat(partner.rating.toString()) : 0,
    todayDeliveries: 0,
    todayEarnings: 0,
    activeDeliveries: activeDeliveriesArray.length
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 w-full overflow-x-hidden">
      {/* Mobile-First Header - Full Width Coverage */}
      <div className="bg-white shadow-sm border-b w-full">
        <div className="w-full max-w-none px-2 xs:px-3 sm:px-4 lg:px-6 py-2 xs:py-3 sm:py-4">
          <div className="flex flex-col xs:flex-row xs:items-center xs:justify-between gap-2 xs:gap-3 sm:gap-4">
            <div className="flex items-center gap-2 xs:gap-3 sm:gap-4 min-w-0 flex-1">
              <div className="p-1.5 xs:p-2 sm:p-3 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-full flex-shrink-0">
                <Truck className="h-3 w-3 xs:h-4 xs:w-4 sm:h-6 sm:w-6 text-white" />
              </div>
              <div className="min-w-0 flex-1">
                <h1 className="text-sm xs:text-base sm:text-lg lg:text-2xl font-bold text-gray-800 truncate">Delivery Dashboard</h1>
                <p className="text-xs xs:text-sm sm:text-base text-gray-600 truncate">Welcome, {user?.fullName}</p>
              </div>
            </div>
            <div className="flex flex-row items-center gap-2 xs:gap-3 flex-shrink-0">
              <div className="flex items-center gap-1.5 xs:gap-2">
                <span className="text-[10px] xs:text-xs text-gray-600 font-medium">
                  {partner.isAvailable ? "Online" : "Offline"}
                </span>
                <button
                  onClick={() => toggleAvailability.mutate(!partner.isAvailable)}
                  disabled={toggleAvailability.isPending}
                  className={`relative inline-flex h-5 xs:h-6 w-9 xs:w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 ${
                    partner.isAvailable 
                      ? "bg-green-500 focus:ring-green-500" 
                      : "bg-gray-300 focus:ring-gray-300"
                  } ${toggleAvailability.isPending ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  <span
                    className={`inline-block h-3 xs:h-4 w-3 xs:w-4 transform rounded-full bg-white transition-transform ${
                      partner.isAvailable ? "translate-x-5 xs:translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="w-full max-w-none px-1 xs:px-2 sm:px-3 lg:px-6 py-2 xs:py-3 sm:py-4 lg:py-6">
        <Tabs value={selectedTab} onValueChange={setSelectedTab} className="w-full">
          {/* Mobile-First Icon-Only Tabs - Ultra Compact */}
          <TabsList className="grid grid-cols-6 mb-2 xs:mb-3 sm:mb-6 bg-white shadow-sm h-auto p-0.5 w-full rounded-xl">
            <TabsTrigger value="dashboard" className="flex items-center justify-center py-2 xs:py-2.5 px-1 h-auto min-h-[45px] xs:min-h-[50px] data-[state=active]:bg-blue-50 data-[state=active]:text-blue-600 rounded-lg" title="Dashboard">
              <Home className="h-5 w-5 xs:h-6 xs:w-6" />
            </TabsTrigger>
            <TabsTrigger value="orders" className="flex items-center justify-center py-2 xs:py-2.5 px-1 relative h-auto min-h-[45px] xs:min-h-[50px] data-[state=active]:bg-orange-50 data-[state=active]:text-orange-600 rounded-lg" title="Alerts">
              <div className="relative">
                <AlertTriangle className="h-5 w-5 xs:h-6 xs:w-6" />
                <div className="absolute -top-1 -right-1 w-2 h-2 xs:w-2.5 xs:h-2.5 bg-red-500 rounded-full"></div>
              </div>
            </TabsTrigger>
            <TabsTrigger value="deliveries" className="flex items-center justify-center py-2 xs:py-2.5 px-1 relative h-auto min-h-[45px] xs:min-h-[50px] data-[state=active]:bg-green-50 data-[state=active]:text-green-600 rounded-lg" title="Active Deliveries">
              <div className="relative">
                <Activity className="h-5 w-5 xs:h-6 xs:w-6" />
                {(pendingDeliveries.length + activeDeliveriesArray.length) > 0 && (
                  <div className="absolute -top-1 -right-1 w-4 h-4 bg-green-500 rounded-full flex items-center justify-center">
                    <span className="text-[8px] xs:text-[9px] font-bold text-white">{pendingDeliveries.length + activeDeliveriesArray.length}</span>
                  </div>
                )}
              </div>
            </TabsTrigger>
            <TabsTrigger value="history" className="flex items-center justify-center py-2 xs:py-2.5 px-1 h-auto min-h-[45px] xs:min-h-[50px] data-[state=active]:bg-purple-50 data-[state=active]:text-purple-600 rounded-lg" title="History">
              <History className="h-5 w-5 xs:h-6 xs:w-6" />
            </TabsTrigger>
            <TabsTrigger value="earnings" className="flex items-center justify-center py-2 xs:py-2.5 px-1 h-auto min-h-[45px] xs:min-h-[50px] data-[state=active]:bg-green-50 data-[state=active]:text-green-600 rounded-lg" title="Earnings">
              <Wallet className="h-5 w-5 xs:h-6 xs:w-6" />
            </TabsTrigger>
            <TabsTrigger value="profile" className="flex items-center justify-center py-2 xs:py-2.5 px-1 h-auto min-h-[45px] xs:min-h-[50px] data-[state=active]:bg-indigo-50 data-[state=active]:text-indigo-600 rounded-lg" title="Profile">
              <User className="h-5 w-5 xs:h-6 xs:w-6" />
            </TabsTrigger>
          </TabsList>

          <TabsContent value="dashboard" className="space-y-2 xs:space-y-3 sm:space-y-4 lg:space-y-6">
            {/* Mobile-First Stats Cards - Full Width Coverage */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-1.5 xs:gap-2 sm:gap-3 lg:gap-6 w-full">
              <Card className="bg-gradient-to-br from-blue-500 to-blue-600 text-white border-0 shadow-lg">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1 xs:pb-2 px-2 xs:px-3 sm:px-6 pt-2 xs:pt-3 sm:pt-6">
                  <CardTitle className="text-[10px] xs:text-xs sm:text-sm font-medium opacity-90 leading-tight">Total Deliveries</CardTitle>
                  <Package className="h-3 w-3 xs:h-4 xs:w-4 sm:h-5 sm:w-5 opacity-80 flex-shrink-0" />
                </CardHeader>
                <CardContent className="px-2 xs:px-3 sm:px-6 pb-2 xs:pb-3 sm:pb-6">
                  <div className="text-base xs:text-lg sm:text-xl lg:text-3xl font-bold">{currentStats.totalDeliveries}</div>
                  <p className="text-[8px] xs:text-[9px] sm:text-[10px] lg:text-xs opacity-80 mt-0.5 xs:mt-1 leading-tight">
                    +{currentStats.todayDeliveries} today
                  </p>
                </CardContent>
              </Card>

              <Card className="bg-gradient-to-br from-green-500 to-green-600 text-white border-0 shadow-lg">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1 xs:pb-2 px-2 xs:px-3 sm:px-6 pt-2 xs:pt-3 sm:pt-6">
                  <CardTitle className="text-[10px] xs:text-xs sm:text-sm font-medium opacity-90 leading-tight">Total Earnings</CardTitle>
                  <DollarSign className="h-3 w-3 xs:h-4 xs:w-4 sm:h-5 sm:w-5 opacity-80 flex-shrink-0" />
                </CardHeader>
                <CardContent className="px-2 xs:px-3 sm:px-6 pb-2 xs:pb-3 sm:pb-6">
                  <div className="text-base xs:text-lg sm:text-xl lg:text-3xl font-bold">₹{currentStats.totalEarnings.toFixed(2)}</div>
                  <p className="text-[8px] xs:text-[9px] sm:text-[10px] lg:text-xs opacity-80 mt-0.5 xs:mt-1 leading-tight">
                    +₹{currentStats.todayEarnings.toFixed(2)} today
                  </p>
                </CardContent>
              </Card>

              <Card className="bg-gradient-to-br from-orange-500 to-orange-600 text-white border-0 shadow-lg">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1 xs:pb-2 px-2 xs:px-3 sm:px-6 pt-2 xs:pt-3 sm:pt-6">
                  <CardTitle className="text-[10px] xs:text-xs sm:text-sm font-medium opacity-90 leading-tight">Active Deliveries</CardTitle>
                  <Clock className="h-3 w-3 xs:h-4 xs:w-4 sm:h-5 sm:w-5 opacity-80 flex-shrink-0" />
                </CardHeader>
                <CardContent className="px-2 xs:px-3 sm:px-6 pb-2 xs:pb-3 sm:pb-6">
                  <div className="text-base xs:text-lg sm:text-xl lg:text-3xl font-bold">{currentStats.activeDeliveries}</div>
                  <p className="text-[8px] xs:text-[9px] sm:text-[10px] lg:text-xs opacity-80 mt-0.5 xs:mt-1 leading-tight">
                    {pendingDeliveries.length} pending, {activeDeliveriesArray.length} active
                  </p>
                </CardContent>
              </Card>

              <Card className="bg-gradient-to-br from-purple-500 to-purple-600 text-white border-0 shadow-lg">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1 xs:pb-2 px-2 xs:px-3 sm:px-6 pt-2 xs:pt-3 sm:pt-6">
                  <CardTitle className="text-[10px] xs:text-xs sm:text-sm font-medium opacity-90 leading-tight">Rating</CardTitle>
                  <Star className="h-3 w-3 xs:h-4 xs:w-4 sm:h-5 sm:w-5 opacity-80 flex-shrink-0 fill-current" />
                </CardHeader>
                <CardContent className="px-2 xs:px-3 sm:px-6 pb-2 xs:pb-3 sm:pb-6">
                  <div className="text-base xs:text-lg sm:text-xl lg:text-3xl font-bold flex items-center gap-1">
                    {currentStats.rating > 0 ? (
                      <>
                        <span>{currentStats.rating.toFixed(1)}</span>
                        <Star className="h-3 w-3 xs:h-4 xs:w-4 fill-current text-yellow-300" />
                      </>
                    ) : "N/A"}
                  </div>
                  <p className="text-[8px] xs:text-[9px] sm:text-[10px] lg:text-xs opacity-80 mt-0.5 xs:mt-1 leading-tight">
                    Customer feedback
                  </p>
                </CardContent>
              </Card>
            </div>

            {/* Mobile-First Quick Actions - Compact Design */}
            <Card className="shadow-lg border-0">
              <CardHeader className="px-2 xs:px-3 sm:px-6 py-2 xs:py-3 sm:py-4">
                <CardTitle className="text-sm xs:text-base sm:text-lg lg:text-xl flex items-center gap-2">
                  <Activity className="h-4 w-4 xs:h-5 xs:w-5 text-blue-600" />
                  Quick Actions
                </CardTitle>
                <CardDescription className="text-xs xs:text-sm">Common tasks</CardDescription>
              </CardHeader>
              <CardContent className="px-2 xs:px-3 sm:px-6 pb-2 xs:pb-3 sm:pb-6">
                <div className="grid grid-cols-2 xs:grid-cols-4 gap-2 xs:gap-3 sm:gap-4">
                  <Button className="h-10 xs:h-12 sm:h-16 flex flex-col gap-0.5 xs:gap-1 sm:gap-2 bg-blue-600 hover:bg-blue-700 text-[10px] xs:text-xs sm:text-sm px-1 xs:px-2">
                    <Bell className="h-3 w-3 xs:h-4 xs:w-4 sm:h-5 sm:w-5" />
                    <span className="leading-tight">Alerts</span>
                  </Button>
                  <Button variant="outline" className="h-10 xs:h-12 sm:h-16 flex flex-col gap-0.5 xs:gap-1 sm:gap-2 text-[10px] xs:text-xs sm:text-sm px-1 xs:px-2">
                    <Navigation className="h-3 w-3 xs:h-4 xs:w-4 sm:h-5 sm:w-5" />
                    <span className="leading-tight">Navigate</span>
                  </Button>
                  <Button variant="outline" className="h-10 xs:h-12 sm:h-16 flex flex-col gap-0.5 xs:gap-1 sm:gap-2 text-[10px] xs:text-xs sm:text-sm px-1 xs:px-2">
                    <Phone className="h-3 w-3 xs:h-4 xs:w-4 sm:h-5 sm:w-5" />
                    <span className="leading-tight">Help</span>
                  </Button>
                  <Button variant="outline" className="h-10 xs:h-12 sm:h-16 flex flex-col gap-0.5 xs:gap-1 sm:gap-2 text-[10px] xs:text-xs sm:text-sm px-1 xs:px-2">
                    <TrendingUp className="h-3 w-3 xs:h-4 xs:w-4 sm:h-5 sm:w-5" />
                    <span className="leading-tight">Stats</span>
                  </Button>
                </div>
              </CardContent>
            </Card>

      <SoundTestButton />
          </TabsContent>

          <TabsContent value="orders" className="space-y-4 sm:space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6">
              {/* Mobile Responsive Map Section */}
              <div className="lg:col-span-2">
                <Card className="shadow-lg border-0">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="flex flex-col sm:flex-row sm:items-center gap-2">
                      <div className="flex items-center gap-2">
                        <MapPin className="h-4 w-4 sm:h-5 sm:w-5" />
                        <span className="text-base sm:text-lg">Delivery Area Map</span>
                      </div>
                      <Badge variant="secondary" className="bg-green-100 text-green-800 w-fit">
                        Live
                      </Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <div className="w-full h-64 sm:h-80 lg:h-96 bg-gradient-to-br from-blue-50 to-indigo-100 rounded-lg border-2 border-dashed border-blue-200 flex items-center justify-center">
                      <div className="text-center p-4 sm:p-8 max-w-sm">
                        <MapPin className="h-12 w-12 sm:h-16 sm:w-16 text-blue-400 mx-auto mb-3 sm:mb-4" />
                        <h3 className="text-lg sm:text-xl font-semibold text-gray-700 mb-2">Interactive Map</h3>
                        <p className="text-sm sm:text-base text-gray-500 mb-3 sm:mb-4">
                          Real-time delivery tracking and navigation
                        </p>
                        <div className="space-y-2 text-xs sm:text-sm text-gray-600 mb-4 sm:mb-6">
                          <div className="flex items-center justify-center gap-2">
                            <div className="w-2 h-2 sm:w-3 sm:h-3 bg-green-500 rounded-full"></div>
                            <span>Pickup Locations</span>
                          </div>
                          <div className="flex items-center justify-center gap-2">
                            <div className="w-2 h-2 sm:w-3 sm:h-3 bg-red-500 rounded-full"></div>
                            <span>Delivery Destinations</span>
                          </div>
                          <div className="flex items-center justify-center gap-2">
                            <div className="w-2 h-2 sm:w-3 sm:h-3 bg-blue-500 rounded-full"></div>
                            <span>Your Location</span>
                          </div>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 sm:gap-3">
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => window.open('https://www.google.com/maps', '_blank')}
                            className="text-xs sm:text-sm"
                          >
                            <Navigation className="h-3 w-3 sm:h-4 sm:w-4 mr-1 sm:mr-2" />
                            Open Maps
                          </Button>
                          <Button 
                            size="sm"
                            onClick={() => {
                              if (navigator.geolocation) {
                                navigator.geolocation.getCurrentPosition((position) => {
                                  toast({
                                    title: "Location Updated",
                                    description: "Your current location has been recorded.",
                                  });
                                });
                              }
                            }}
                            className="text-xs sm:text-sm"
                          >
                            <MapPin className="h-3 w-3 sm:h-4 sm:w-4 mr-1 sm:mr-2" />
                            Update Location
                          </Button>
                        </div>
                      </div>
                    </div>

                    {/* Mobile Responsive Quick Stats */}
                    <div className="grid grid-cols-3 gap-2 sm:gap-4 mt-4 sm:mt-6">
                      <div className="text-center p-3 sm:p-4 bg-green-50 rounded-lg">
                        <div className="text-lg sm:text-2xl font-bold text-green-600">{partner.deliveryAreas.length}</div>
                        <div className="text-xs sm:text-sm text-green-700">Coverage Areas</div>
                      </div>
                      <div className="text-center p-3 sm:p-4 bg-blue-50 rounded-lg">
                        <div className="text-lg sm:text-2xl font-bold text-blue-600">{currentStats.activeDeliveries}</div>
                        <div className="text-xs sm:text-sm text-blue-700">Active Routes</div>
                      </div>
                      <div className="text-center p-3 sm:p-4 bg-orange-50 rounded-lg">
                        <div className="text-lg sm:text-2xl font-bold text-orange-600">
                          {partner.isAvailable ? "Online" : "Offline"}
                        </div>
                        <div className="text-xs sm:text-sm text-orange-700">Status</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Mobile Responsive Notifications Panel */}
              <div className="lg:col-span-1">
                <div className="h-full">
                  <DeliveryNotifications deliveryPartnerId={partner?.id || 0} />
                </div>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="orders" className="space-y-4 sm:space-y-6">
            {/* Delivery Notifications - Alerts Tab */}
            <Card className="shadow-lg border-0">
              <CardHeader className="px-3 sm:px-6">
                <CardTitle className="flex items-center gap-2 text-base sm:text-lg">
                  <Bell className="h-4 w-4 sm:h-5 sm:w-5 text-orange-500" />
                  Delivery Alerts
                </CardTitle>
                <CardDescription className="text-sm">New delivery opportunities available</CardDescription>
              </CardHeader>
              <CardContent className="px-3 sm:px-6">
                <DeliveryNotifications deliveryPartnerId={partner?.id || 0} />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="deliveries" className="space-y-2 xs:space-y-3 sm:space-y-4 lg:space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-2 xs:gap-3 sm:gap-4 lg:gap-6 w-full">
              {/* Mobile-First Pending Deliveries */}
              <Card className="shadow-lg border-0 w-full">
                <CardHeader className="px-2 xs:px-3 sm:px-6 py-2 xs:py-3 sm:py-4">
                  <CardTitle className="flex items-center gap-1 xs:gap-2 text-sm xs:text-base sm:text-lg">
                    <Clock className="h-3 w-3 xs:h-4 xs:w-4 sm:h-5 sm:w-5 text-orange-500 flex-shrink-0" />
                    <span className="truncate">Pending ({pendingDeliveries.length})</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 xs:space-y-3 sm:space-y-4 px-2 xs:px-3 sm:px-6 pb-2 xs:pb-3 sm:pb-6">
                  {pendingDeliveries.length === 0 ? (
                    <div className="text-center py-4 xs:py-6 sm:py-8">
                      <Package className="h-6 w-6 xs:h-8 xs:w-8 sm:h-10 sm:w-10 lg:h-12 lg:w-12 text-gray-300 mx-auto mb-2 xs:mb-3 sm:mb-4" />
                      <p className="text-xs xs:text-sm sm:text-base text-gray-500">No pending deliveries</p>
                    </div>
                  ) : (
                    pendingDeliveries.map((delivery: Delivery) => (
                      <Card key={delivery.id} className="border border-orange-200 bg-orange-50 w-full overflow-hidden">
                        <CardContent className="p-1.5 xs:p-2 sm:p-4">
                          <div className="flex items-center justify-between mb-1.5 xs:mb-2 gap-1 xs:gap-2">
                            <div className="font-semibold text-[10px] xs:text-xs sm:text-sm lg:text-lg truncate min-w-0">Order #{delivery.orderId}</div>
                            <Badge className="bg-orange-100 text-orange-800 border-orange-200 text-[8px] xs:text-[9px] sm:text-xs flex-shrink-0 px-1 xs:px-2 py-0.5">
                              ₹{delivery.deliveryFee}
                            </Badge>
                          </div>
                          <div className="space-y-1 xs:space-y-1.5 sm:space-y-2 text-[9px] xs:text-[10px] sm:text-xs lg:text-sm">
                            <div className="flex items-start gap-1 xs:gap-1.5 sm:gap-2">
                              <MapPin className="h-2.5 w-2.5 xs:h-3 xs:w-3 sm:h-4 sm:w-4 text-green-500 mt-0.5 flex-shrink-0" />
                              <div className="min-w-0 flex-1">
                                <p className="font-medium text-[9px] xs:text-[10px] sm:text-xs">Pickup</p>
                                <p className="text-gray-600 text-[8px] xs:text-[9px] sm:text-xs line-clamp-2 break-words">{delivery.pickupAddress}</p>
                              </div>
                            </div>
                            <div className="flex items-start gap-1 xs:gap-1.5 sm:gap-2">
                              <MapPin className="h-2.5 w-2.5 xs:h-3 xs:w-3 sm:h-4 sm:w-4 text-red-500 mt-0.5 flex-shrink-0" />
                              <div className="min-w-0 flex-1">
                                <p className="font-medium text-[9px] xs:text-[10px] sm:text-xs">Delivery</p>
                                <p className="text-gray-600 text-[8px] xs:text-[9px] sm:text-xs line-clamp-2 break-words">{delivery.deliveryAddress}</p>
                              </div>
                            </div>
                          </div>
                          <div className="mt-2 xs:mt-2.5 sm:mt-3 lg:mt-4 flex flex-col xs:flex-row gap-1 xs:gap-1.5 sm:gap-2">
                            <Button
                              onClick={() => updateDeliveryStatus.mutate({ deliveryId: delivery.id, status: 'picked_up' })}
                              disabled={updateDeliveryStatus.isPending}
                              className="flex-1 bg-green-600 hover:bg-green-700 text-[8px] xs:text-[9px] sm:text-xs py-1 xs:py-1.5 sm:py-2 h-6 xs:h-7 sm:h-auto"
                              size="sm"
                            >
                              <span className="hidden xs:inline">Accept & Pickup</span>
                              <span className="xs:hidden">Accept</span>
                            </Button>
                            <Button variant="outline" size="sm" className="xs:w-auto h-6 xs:h-7 sm:h-auto px-2">
                              <MapPin className="h-2.5 w-2.5 xs:h-3 xs:w-3 sm:h-4 sm:w-4" />
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    ))
                  )}
                </CardContent>
              </Card>

              {/* Mobile Responsive Active Deliveries */}
              <Card className="shadow-lg border-0">
                <CardHeader className="px-3 sm:px-6">
                  <CardTitle className="flex items-center gap-2 text-base sm:text-lg">
                    <Truck className="h-4 w-4 sm:h-5 sm:w-5 text-blue-500" />
                    Active Deliveries ({activeDeliveriesArray.length})
                    {activeDeliveriesLoading && (
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600"></div>
                    )}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 sm:space-y-4 px-3 sm:px-6">
                  {activeDeliveriesLoading ? (
                    <div className="text-center py-6 sm:py-8">
                      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
                      <p className="text-sm sm:text-base text-gray-500">Loading active deliveries...</p>
                    </div>
                  ) : activeDeliveriesArray.length === 0 ? (
                    <div className="text-center py-6 sm:py-8">
                      <Truck className="h-10 w-10 sm:h-12 sm:w-12 text-gray-300 mx-auto mb-3 sm:mb-4" />
                      <p className="text-sm sm:text-base text-gray-500">No active deliveries</p>
                      <p className="text-xs text-gray-400 mt-2">Accept delivery orders to see them here</p>
                    </div>
                  ) : (
                    activeDeliveriesArray.map((delivery: Delivery) => (
                      <Card key={delivery.id} className="border border-blue-200 bg-blue-50 max-w-full overflow-hidden">
                        <CardContent className="p-2 sm:p-4">
                          <div className="flex items-center justify-between mb-2 gap-2">
                            <div className="font-semibold text-xs sm:text-lg truncate min-w-0">Order #{delivery.orderId}</div>
                            <Badge className="bg-blue-100 text-blue-800 border-blue-200 text-xs flex-shrink-0">
                              In Progress
                            </Badge>
                          </div>
                          <div className="space-y-2 text-xs sm:text-sm">
                            <div className="flex items-start gap-2">
                              <MapPin className="h-3 w-3 sm:h-4 sm:w-4 text-red-500 mt-0.5 flex-shrink-0" />
                              <div className="min-w-0 flex-1">
                                <p className="font-medium text-xs sm:text-sm">Delivery Address</p>
                                <p className="text-gray-600 text-xs sm:text-sm line-clamp-2 word-wrap break-words overflow-wrap-anywhere">{delivery.deliveryAddress}</p>
                              </div>
                            </div>
                            {/* Delivery Timer */}
                            <div className="mt-3 p-2 bg-white rounded-md border">
                              <DeliveryTimer 
                                createdAt={delivery.createdAt} 
                                estimatedTime={45} 
                              />
                            </div>
                          </div>
                          <div className="mt-3 sm:mt-4 flex flex-col sm:flex-row gap-2">
                            <Button
                              variant="outline"
                              onClick={() => window.open(`/delivery-map/${delivery.id}`, '_blank')}
                              className="flex-1 text-xs py-2"
                              size="sm"
                            >
                              <Navigation className="h-3 w-3 sm:h-4 sm:w-4 mr-1" />
                              <span className="hidden sm:inline">Navigate</span>
                              <span className="sm:hidden">Nav</span>
                            </Button>
                            <Button
                              onClick={() => updateDeliveryStatus.mutate({ deliveryId: delivery.id, status: 'delivered' })}
                              disabled={updateDeliveryStatus.isPending}
                              className="flex-1 bg-green-600 hover:bg-green-700 text-xs py-2"
                              size="sm"
                            >
                              <span className="hidden sm:inline">Mark Delivered</span>
                              <span className="sm:hidden">Delivered</span>
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    ))
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="history" className="space-y-4 sm:space-y-6">
            <Card className="shadow-lg border-0">
              <CardHeader className="px-3 sm:px-6">
                <CardTitle className="text-base sm:text-lg">Delivery History</CardTitle>
                <CardDescription className="text-sm">Your completed deliveries</CardDescription>
              </CardHeader>
              <CardContent className="px-3 sm:px-6">
                {completedDeliveries.length === 0 ? (
                  <div className="text-center py-8 sm:py-12">
                    <Calendar className="h-12 w-12 sm:h-16 sm:w-16 text-gray-300 mx-auto mb-3 sm:mb-4" />
                    <p className="text-base sm:text-lg text-gray-500">No completed deliveries yet</p>
                  </div>
                ) : (
                  <div className="space-y-3 sm:space-y-4">
                    {completedDeliveries.map((delivery: Delivery) => (
                      <Card key={delivery.id} className="border border-green-200 bg-green-50 max-w-full overflow-hidden">
                        <CardContent className="p-2 sm:p-4">
                          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                            <div className="flex-1 min-w-0">
                              <div className="font-semibold text-xs sm:text-lg truncate">Order #{delivery.orderId}</div>
                              <p className="text-xs sm:text-sm text-gray-600 truncate">
                                Delivered on {new Date(delivery.deliveredAt!).toLocaleDateString()}
                              </p>
                              {delivery.customerRating && (
                                <div className="flex items-center gap-1 mt-1">
                                  <Star className="h-3 w-3 sm:h-4 sm:w-4 text-yellow-500 fill-current" />
                                  <span className="text-xs sm:text-sm font-medium">{delivery.customerRating}</span>
                                </div>
                              )}
                            </div>
                            <div className="text-left sm:text-right flex-shrink-0">
                              <div className="font-bold text-green-600 text-sm sm:text-lg">₹{delivery.deliveryFee}</div>
                              <Badge variant="outline" className="border-green-300 text-green-700 text-xs">
                                Completed
                              </Badge>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="earnings" className="space-y-4 sm:space-y-6">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
              <Card className="shadow-lg border-0">
                <CardHeader className="px-3 sm:px-6">
                  <CardTitle className="text-base sm:text-lg">Today's Earnings</CardTitle>
                </CardHeader>
                <CardContent className="px-3 sm:px-6">
                  <div className="text-2xl sm:text-3xl font-bold text-green-600">₹{currentStats.todayEarnings.toFixed(2)}</div>
                  <p className="text-xs sm:text-sm text-gray-500">{currentStats.todayDeliveries} {currentStats.todayDeliveries === 1 ? 'delivery' : 'deliveries'}</p>
                </CardContent>
              </Card>

              <Card className="shadow-lg border-0">
                <CardHeader className="px-3 sm:px-6">
                  <CardTitle className="text-base sm:text-lg">This Week</CardTitle>
                </CardHeader>
                <CardContent className="px-3 sm:px-6">
                  <div className="text-2xl sm:text-3xl font-bold text-blue-600">₹{(currentStats.todayEarnings * 7).toFixed(2)}</div>
                  <p className="text-xs sm:text-sm text-gray-500">Weekly projection</p>
                </CardContent>
              </Card>

              <Card className="shadow-lg border-0 sm:col-span-2 lg:col-span-1">
                <CardHeader className="px-3 sm:px-6">
                  <CardTitle className="text-base sm:text-lg">Total Lifetime</CardTitle>
                </CardHeader>
                <CardContent className="px-3 sm:px-6">
                  <div className="text-2xl sm:text-3xl font-bold text-purple-600">₹{currentStats.totalEarnings.toFixed(2)}</div>
                  <p className="text-xs sm:text-sm text-gray-500">{currentStats.totalDeliveries} total deliveries</p>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="profile">
            <Card className="shadow-lg border-0">
              <CardHeader className="px-3 sm:px-6">
                <CardTitle className="text-base sm:text-lg">Profile Information</CardTitle>
                <CardDescription className="text-sm">Your delivery partner details</CardDescription>
              </CardHeader>
              <CardContent className="px-3 sm:px-6">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
                  <div className="space-y-4">
                    <h3 className="font-semibold text-base sm:text-lg">Vehicle Details</h3>
                    <div className="space-y-3">
                      <div className="flex flex-col sm:flex-row sm:justify-between py-2 border-b gap-1">
                        <span className="text-gray-600 text-sm">Vehicle Type:</span>
                        <span className="font-medium capitalize text-sm">{partner.vehicleType}</span>
                      </div>
                      <div className="flex flex-col sm:flex-row sm:justify-between py-2 border-b gap-1">
                        <span className="text-gray-600 text-sm">Vehicle Number:</span>
                        <span className="font-medium text-sm">{partner.vehicleNumber}</span>
                      </div>
                      <div className="flex flex-col sm:flex-row sm:justify-between py-2 border-b gap-1">
                        <span className="text-gray-600 text-sm">Driving License:</span>
                        <span className="font-medium text-sm">{partner.drivingLicense}</span>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h3 className="font-semibold text-base sm:text-lg">Contact & Areas</h3>
                    <div className="space-y-3">
                      <div className="flex flex-col sm:flex-row sm:justify-between py-2 border-b gap-1">
                        <span className="text-gray-600 text-sm">Emergency Contact:</span>
                        <span className="font-medium text-sm">{partner.emergencyContact}</span>
                      </div>
                      <div className="py-2 border-b">
                        <span className="text-gray-600 text-sm">Delivery Areas:</span>
                        <div className="flex flex-wrap gap-1 sm:gap-2 mt-2">
                          {partner.deliveryAreas.map((area: string, index: number) => (
                            <Badge key={index} variant="outline" className="bg-blue-50 text-blue-700 text-xs">
                              {area}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      <div className="flex flex-col sm:flex-row sm:justify-between py-2 border-b gap-1">
                        <span className="text-gray-600 text-sm">Status:</span>
                        <Badge 
                          variant={partner.status === 'approved' ? 'default' : 'secondary'}
                          className={`${partner.status === 'approved' ? 'bg-green-100 text-green-800' : ''} text-xs w-fit`}
                        >
                          {partner.status}
                        </Badge>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}