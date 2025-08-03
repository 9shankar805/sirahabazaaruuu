import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import {
  Users, Store, Package, ShoppingCart, DollarSign, TrendingUp, AlertTriangle, 
  Eye, Edit, Trash2, Plus, Download, Upload, Search, Filter, MoreHorizontal,
  CheckCircle, XCircle, Clock, Ban, Settings, Bell, Shield, CreditCard,
  BarChart3, FileText, MessageSquare, Tag, Image, Globe, Zap, UserCheck,
  LogOut, RefreshCw, Calendar, Mail, Phone, MapPin, Truck, Star, Activity,
  PieChart, LineChart, Target, Award, Briefcase, Building, Home, Loader2, X, Car, User
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

export default function ImprovedAdminDashboard() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [adminUser, setAdminUser] = useState<any>(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [searchTerm, setSearchTerm] = useState("");
  const [filterStatus, setFilterStatus] = useState("all");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [showUserDialog, setShowUserDialog] = useState(false);
  const [selectedUser, setSelectedUser] = useState<any>(null);
  const [showStoreDialog, setShowStoreDialog] = useState(false);
  const [selectedStore, setSelectedStore] = useState<any>(null);
  const [editingZone, setEditingZone] = useState<any>(null);
  const [showEditZoneDialog, setShowEditZoneDialog] = useState(false);
  const [showCreateZone, setShowCreateZone] = useState(false);
  const [newZone, setNewZone] = useState({
    name: "",
    minDistance: "",
    maxDistance: "",
    baseFee: "",
    perKmRate: "",
    isActive: true
  });
  const [showEditProfileDialog, setShowEditProfileDialog] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem("adminUser");
    if (stored && stored !== "undefined" && stored !== "null") {
      try {
        const adminData = JSON.parse(stored);
        setAdminUser(adminData);
      } catch (error) {
        console.error('Error parsing admin user data:', error);
        localStorage.removeItem("adminUser");
        setLocation("/admin/login");
      }
    } else {
      setLocation("/admin/login");
    }
  }, [setLocation]);

  // Data fetching queries
  const { data: dashboardStats = {} } = useQuery({
    queryKey: ["/api/admin/dashboard/stats"],
    enabled: !!adminUser,
  });

  const { data: allUsers = [] } = useQuery({
    queryKey: ["/api/admin/users"],
    enabled: !!adminUser,
  }) as { data: any[] };

  const { data: deliveryPartners = [] } = useQuery({
    queryKey: ["/api/delivery-partners"],
    enabled: !!adminUser,
  }) as { data: any[] };

  const { data: allStores = [] } = useQuery({
    queryKey: ["/api/admin/stores"],
    enabled: !!adminUser,
  }) as { data: any[] };

  const { data: allProducts = [] } = useQuery({
    queryKey: ["/api/admin/products"],
    enabled: !!adminUser,
  }) as { data: any[] };

  const { data: allOrders = [] } = useQuery({
    queryKey: ["/api/admin/orders"],
    enabled: !!adminUser,
  }) as { data: any[] };

  const { data: pendingUsers = [] } = useQuery({
    queryKey: ["/api/admin/users/pending"],
    enabled: !!adminUser,
  }) as { data: any[] };

  const { data: coupons = [] } = useQuery({
    queryKey: ["/api/admin/coupons"],
    enabled: !!adminUser,
  }) as { data: any[] };

  const { data: deliveryZones = [] } = useQuery({
    queryKey: ["/api/delivery-zones"],
    enabled: !!adminUser,
  }) as { data: any[] };

  // Mutations
  const approveUserMutation = useMutation({
    mutationFn: async (userId: number) => {
      const response = await apiRequest(`/api/admin/users/${userId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser.id }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users/pending"] });
      toast({ title: "Success", description: "User approved successfully" });
    },
    onError: (error: any) => {
      toast({ 
        title: "Error", 
        description: error.message || "Failed to approve user",
        variant: "destructive"
      });
    },
  });

  const rejectUserMutation = useMutation({
    mutationFn: async ({ userId, reason }: { userId: number; reason: string }) => {
      const response = await apiRequest(`/api/admin/users/${userId}/reject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser.id, reason }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users/pending"] });
      toast({ title: "Success", description: "User rejected successfully" });
    },
    onError: (error: any) => {
      toast({ 
        title: "Error", 
        description: error.message || "Failed to reject user",
        variant: "destructive"
      });
    },
  });

  // Delivery partner approval mutations
  const approvePartnerMutation = useMutation({
    mutationFn: async (partnerId: number) => {
      const response = await apiRequest(`/api/delivery-partners/${partnerId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser.id }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-partners"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users/pending"] });
      toast({ title: "Success", description: "Delivery partner approved successfully" });
    },
    onError: (error: any) => {
      toast({ 
        title: "Error", 
        description: error.message || "Failed to approve delivery partner",
        variant: "destructive"
      });
    },
  });

  const rejectPartnerMutation = useMutation({
    mutationFn: async ({ partnerId, reason }: { partnerId: number; reason: string }) => {
      const response = await apiRequest(`/api/delivery-partners/${partnerId}/reject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser.id, reason }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-partners"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users/pending"] });
      toast({ title: "Success", description: "Delivery partner rejected successfully" });
    },
    onError: (error: any) => {
      toast({ 
        title: "Error", 
        description: error.message || "Failed to reject delivery partner",
        variant: "destructive"
      });
    },
  });

  const banUserMutation = useMutation({
    mutationFn: async (userId: number) => {
      const response = await apiRequest(`/api/admin/users/${userId}/ban`, {
        method: "PUT",
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      toast({ title: "Success", description: "User banned successfully" });
    },
  });

  const unbanUserMutation = useMutation({
    mutationFn: async (userId: number) => {
      const response = await apiRequest(`/api/admin/users/${userId}/unban`, {
        method: "PUT",
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      toast({ title: "Success", description: "User unbanned successfully" });
    },
  });

  const updateZoneMutation = useMutation({
    mutationFn: async ({ id, data }: { id: number; data: any }) => {
      const response = await apiRequest(`/api/admin/delivery-zones/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...data, adminId: adminUser.id }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-zones"] });
      setShowEditZoneDialog(false);
      setEditingZone(null);
      toast({ title: "Success", description: "Delivery zone updated successfully" });
    },
    onError: (error: any) => {
      toast({ 
        title: "Error", 
        description: error.message || "Failed to update delivery zone",
        variant: "destructive"
      });
    },
  });

  const createZoneMutation = useMutation({
    mutationFn: async (zoneData: any) => {
      const response = await apiRequest("/api/admin/delivery-zones", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...zoneData, adminId: adminUser.id }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-zones"] });
      setShowCreateZone(false);
      setNewZone({
        name: "",
        minDistance: "",
        maxDistance: "",
        baseFee: "",
        perKmRate: "",
        isActive: true
      });
      toast({ title: "Success", description: "Delivery zone created successfully" });
    },
    onError: (error: any) => {
      toast({ 
        title: "Error", 
        description: error.message || "Failed to create delivery zone",
        variant: "destructive"
      });
    },
  });

  const updateProfileMutation = useMutation({
    mutationFn: async (profileData: any) => {
      const response = await apiRequest("/api/admin/profile", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...profileData, adminId: adminUser.id }),
      });
      return response.json();
    },
    onSuccess: (data) => {
      // Update local admin user data
      const updatedAdmin = { ...adminUser, ...data.admin };
      setAdminUser(updatedAdmin);
      localStorage.setItem("adminUser", JSON.stringify(updatedAdmin));
      toast({ title: "Success", description: "Profile updated successfully" });
      setShowEditProfileDialog(false); // Close the dialog after successful update
    },
    onError: (error: any) => {
      toast({ 
        title: "Error", 
        description: error.message || "Failed to update profile",
        variant: "destructive"
      });
    },
  });

  const handleLogout = () => {
    localStorage.removeItem("adminUser");
    setLocation("/admin/login");
  };

  // Calculate stats
  const totalUsers = Array.isArray(allUsers) ? allUsers.length : 0;
  const totalStores = Array.isArray(allStores) ? allStores.length : 0;
  const totalProducts = Array.isArray(allProducts) ? allProducts.length : 0;
  const totalOrders = Array.isArray(allOrders) ? allOrders.length : 0;
  const pendingApprovals = Array.isArray(pendingUsers) ? pendingUsers.length : 0;
  const activeUsers = Array.isArray(allUsers) ? allUsers.filter((user: any) => user.status === 'active').length : 0;
  const totalRevenue = Array.isArray(allOrders) ? allOrders.reduce((sum: number, order: any) => sum + (order.total || 0), 0) : 0;
  const averageOrderValue = totalOrders > 0 ? totalRevenue / totalOrders : 0;

  // Status badge components
  const StatusBadge = ({ status }: { status: string }) => {
    const variants: Record<string, string> = {
      active: "bg-green-100 text-green-800",
      pending: "bg-yellow-100 text-yellow-800",
      banned: "bg-red-100 text-red-800",
      rejected: "bg-gray-100 text-gray-800",
    };
    return (
      <Badge className={variants[status] || "bg-gray-100 text-gray-800"}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </Badge>
    );
  };

  const sidebarItems = [
    { id: "overview", label: "Overview", icon: Home },
    { id: "users", label: "Users", icon: Users },
    { id: "stores", label: "Stores", icon: Store },
    { id: "products", label: "Products", icon: Package },
    { id: "orders", label: "Orders", icon: ShoppingCart },
    { id: "pending", label: "Pending Approvals", icon: Clock },
    { id: "coupons", label: "Coupons", icon: Tag },
    { id: "delivery", label: "Delivery Zones", icon: Truck },
    { id: "analytics", label: "Analytics", icon: BarChart3 },
    { id: "settings", label: "Settings", icon: Settings },
  ];

  if (!adminUser) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <motion.div
        initial={false}
        animate={{ width: sidebarCollapsed ? 80 : 280 }}
        className="bg-white shadow-lg border-r border-gray-200 flex flex-col"
      >
        {/* Logo and Admin Info */}
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center">
            <Shield className="h-8 w-8 text-blue-600" />
            {!sidebarCollapsed && (
              <div className="ml-3">
                <h1 className="text-xl font-bold text-gray-900">Admin Panel</h1>
                <p className="text-sm text-gray-500">Siraha Bazaar</p>
              </div>
            )}
          </div>
          {!sidebarCollapsed && (
            <div className="mt-4 p-3 bg-blue-50 rounded-lg">
              <div className="flex items-center">
                <Avatar className="h-8 w-8">
                  <AvatarFallback className="bg-blue-100 text-blue-600">
                    {adminUser.fullName?.charAt(0) || "A"}
                  </AvatarFallback>
                </Avatar>
                <div className="ml-3">
                  <p className="text-sm font-medium text-gray-900">{adminUser.fullName}</p>
                  <p className="text-xs text-gray-500">Administrator</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-2">
          {sidebarItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center px-3 py-2 rounded-lg text-left transition-colors ${
                  isActive
                    ? "bg-blue-100 text-blue-700 border border-blue-200"
                    : "text-gray-600 hover:bg-gray-100"
                }`}
              >
                <Icon className="h-5 w-5" />
                {!sidebarCollapsed && <span className="ml-3">{item.label}</span>}
                {item.id === "pending" && pendingApprovals > 0 && (
                  <Badge className="ml-auto bg-red-500 text-white">
                    {pendingApprovals}
                  </Badge>
                )}
              </button>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="p-4 border-t border-gray-200 space-y-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="w-full justify-start"
          >
            <Filter className="h-4 w-4" />
            {!sidebarCollapsed && <span className="ml-2">Collapse</span>}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleLogout}
            className="w-full justify-start text-red-600 hover:text-red-700 hover:bg-red-50"
          >
            <LogOut className="h-4 w-4" />
            {!sidebarCollapsed && <span className="ml-2">Logout</span>}
          </Button>
        </div>
      </motion.div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="bg-white shadow-sm border-b border-gray-200 px-6 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-bold text-gray-900 capitalize">
                {activeTab.replace("-", " ")}
              </h2>
              <p className="text-sm text-gray-500">
                Manage your platform efficiently
              </p>
            </div>
            <div className="flex items-center space-x-4">
              <Button variant="outline" size="sm">
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
              <Button variant="outline" size="sm">
                <Download className="h-4 w-4 mr-2" />
                Export
              </Button>
            </div>
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 overflow-auto p-6">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.2 }}
            >
              {activeTab === "overview" && (
                <div className="space-y-6">
                  {/* Stats Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    <Card>
                      <CardContent className="p-6">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-gray-600">Total Users</p>
                            <p className="text-3xl font-bold text-gray-900">{totalUsers}</p>
                            <p className="text-sm text-green-600 mt-1">
                              {activeUsers} active
                            </p>
                          </div>
                          <div className="bg-blue-100 p-3 rounded-full">
                            <Users className="h-6 w-6 text-blue-600" />
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardContent className="p-6">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-gray-600">Total Stores</p>
                            <p className="text-3xl font-bold text-gray-900">{totalStores}</p>
                            <p className="text-sm text-blue-600 mt-1">
                              {allStores.filter((s: any) => s.status === 'active').length} active
                            </p>
                          </div>
                          <div className="bg-green-100 p-3 rounded-full">
                            <Store className="h-6 w-6 text-green-600" />
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardContent className="p-6">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-gray-600">Total Orders</p>
                            <p className="text-3xl font-bold text-gray-900">{totalOrders}</p>
                            <p className="text-sm text-purple-600 mt-1">
                              ${averageOrderValue.toFixed(2)} avg
                            </p>
                          </div>
                          <div className="bg-purple-100 p-3 rounded-full">
                            <ShoppingCart className="h-6 w-6 text-purple-600" />
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardContent className="p-6">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-gray-600">Total Revenue</p>
                            <p className="text-3xl font-bold text-gray-900">
                              ${totalRevenue.toFixed(2)}
                            </p>
                            <p className="text-sm text-green-600 mt-1">
                              +12% from last month
                            </p>
                          </div>
                          <div className="bg-yellow-100 p-3 rounded-full">
                            <DollarSign className="h-6 w-6 text-yellow-600" />
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>

                  {/* Quick Actions */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center">
                          <Clock className="h-5 w-5 mr-2" />
                          Pending Approvals
                        </CardTitle>
                        <CardDescription>
                          Users waiting for approval
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        {!Array.isArray(pendingUsers) || pendingUsers.length === 0 ? (
                          <p className="text-gray-500 text-center py-4">
                            No pending approvals
                          </p>
                        ) : (
                          <div className="space-y-3">
                            {Array.isArray(pendingUsers) && pendingUsers.slice(0, 3).map((user: any) => (
                              <div key={user.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                <div className="flex items-center">
                                  <Avatar className="h-8 w-8">
                                    <AvatarFallback>
                                      {user.fullName?.charAt(0) || "U"}
                                    </AvatarFallback>
                                  </Avatar>
                                  <div className="ml-3">
                                    <p className="text-sm font-medium">{user.fullName}</p>
                                    <p className="text-xs text-gray-500">{user.email}</p>
                                  </div>
                                </div>
                                <div className="flex space-x-2">
                                  <Button
                                    size="sm"
                                    onClick={() => approveUserMutation.mutate(user.id)}
                                    disabled={approveUserMutation.isPending || rejectUserMutation.isPending}
                                    className="bg-green-600 hover:bg-green-700 text-white disabled:opacity-50 transition-all duration-200"
                                  >
                                    {approveUserMutation.isPending ? (
                                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                                    ) : (
                                      <CheckCircle className="h-4 w-4" />
                                    )}
                                  </Button>
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    onClick={() => rejectUserMutation.mutate({ userId: user.id, reason: "Admin rejection" })}
                                    disabled={approveUserMutation.isPending || rejectUserMutation.isPending}
                                    className="border-red-300 text-red-600 hover:bg-red-50 disabled:opacity-50 transition-all duration-200"
                                  >
                                    {rejectUserMutation.isPending ? (
                                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-red-600"></div>
                                    ) : (
                                      <XCircle className="h-4 w-4" />
                                    )}
                                  </Button>
                                </div>
                              </div>
                            ))}
                            {Array.isArray(pendingUsers) && pendingUsers.length > 3 && (
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => setActiveTab("pending")}
                                className="w-full"
                              >
                                View All ({pendingUsers.length})
                              </Button>
                            )}
                          </div>
                        )}
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center">
                          <TrendingUp className="h-5 w-5 mr-2" />
                          Recent Activity
                        </CardTitle>
                        <CardDescription>
                          Latest platform activities
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          <div className="flex items-center space-x-3">
                            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                            <div className="flex-1">
                              <p className="text-sm">New store registered</p>
                              <p className="text-xs text-gray-500">2 hours ago</p>
                            </div>
                          </div>
                          <div className="flex items-center space-x-3">
                            <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                            <div className="flex-1">
                              <p className="text-sm">Order #1234 completed</p>
                              <p className="text-xs text-gray-500">4 hours ago</p>
                            </div>
                          </div>
                          <div className="flex items-center space-x-3">
                            <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
                            <div className="flex-1">
                              <p className="text-sm">New product added</p>
                              <p className="text-xs text-gray-500">6 hours ago</p>
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              )}

              {activeTab === "users" && (
                <div className="space-y-6">
                  {/* Search and Filters */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                        <Input
                          placeholder="Search users..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          className="pl-10 w-80"
                        />
                      </div>
                      <Select value={filterStatus} onValueChange={setFilterStatus}>
                        <SelectTrigger className="w-40">
                          <SelectValue placeholder="Filter by status" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">All Status</SelectItem>
                          <SelectItem value="active">Active</SelectItem>
                          <SelectItem value="pending">Pending</SelectItem>
                          <SelectItem value="banned">Banned</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <Button>
                      <Plus className="h-4 w-4 mr-2" />
                      Add User
                    </Button>
                  </div>

                  {/* Users Table */}
                  <Card>
                    <CardContent className="p-0">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>User</TableHead>
                            <TableHead>Email</TableHead>
                            <TableHead>Role</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Joined</TableHead>
                            <TableHead>Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {Array.isArray(allUsers) && allUsers
                            .filter((user: any) => {
                              const matchesSearch = user.fullName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                                                  user.email?.toLowerCase().includes(searchTerm.toLowerCase());
                              const matchesStatus = filterStatus === "all" || user.status === filterStatus;
                              return matchesSearch && matchesStatus;
                            })
                            .map((user: any) => (
                              <TableRow key={user.id}>
                                <TableCell>
                                  <div className="flex items-center">
                                    <Avatar className="h-8 w-8">
                                      <AvatarFallback>
                                        {user.fullName?.charAt(0) || "U"}
                                      </AvatarFallback>
                                    </Avatar>
                                    <div className="ml-3">
                                      <p className="font-medium">{user.fullName}</p>
                                      <p className="text-sm text-gray-500">ID: {user.id}</p>
                                    </div>
                                  </div>
                                </TableCell>
                                <TableCell>{user.email}</TableCell>
                                <TableCell>
                                  <Badge variant="outline">{user.role}</Badge>
                                </TableCell>
                                <TableCell>
                                  <StatusBadge status={user.status} />
                                </TableCell>
                                <TableCell>
                                  {user.createdAt ? new Date(user.createdAt).toLocaleDateString() : "N/A"}
                                </TableCell>
                                <TableCell>
                                  <div className="flex items-center space-x-2">
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      onClick={() => {
                                        setSelectedUser(user);
                                        setShowUserDialog(true);
                                      }}
                                    >
                                      <Eye className="h-4 w-4" />
                                    </Button>
                                    {user.status === "banned" ? (
                                      <Button
                                        size="sm"
                                        variant="outline"
                                        onClick={() => unbanUserMutation.mutate(user.id)}
                                        disabled={unbanUserMutation.isPending}
                                      >
                                        <UserCheck className="h-4 w-4" />
                                      </Button>
                                    ) : (
                                      <AlertDialog>
                                        <AlertDialogTrigger asChild>
                                          <Button size="sm" variant="destructive">
                                            <Ban className="h-4 w-4" />
                                          </Button>
                                        </AlertDialogTrigger>
                                        <AlertDialogContent>
                                          <AlertDialogHeader>
                                            <AlertDialogTitle>Ban User</AlertDialogTitle>
                                            <AlertDialogDescription>
                                              Are you sure you want to ban {user.fullName}? This action can be reversed later.
                                            </AlertDialogDescription>
                                          </AlertDialogHeader>
                                          <AlertDialogFooter>
                                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                                            <AlertDialogAction
                                              onClick={() => banUserMutation.mutate(user.id)}
                                              className="bg-red-600 hover:bg-red-700"
                                            >
                                              Ban User
                                            </AlertDialogAction>
                                          </AlertDialogFooter>
                                        </AlertDialogContent>
                                      </AlertDialog>
                                    )}
                                  </div>
                                </TableCell>
                              </TableRow>
                            ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                </div>
              )}

              {activeTab === "stores" && (
                <div className="space-y-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                        <Input
                          placeholder="Search stores..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          className="pl-10 w-80"
                        />
                      </div>
                    </div>
                    <Button>
                      <Plus className="h-4 w-4 mr-2" />
                      Add Store
                    </Button>
                  </div>

                  <Card>
                    <CardContent className="p-0">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Store</TableHead>
                            <TableHead>```python
                            Type</TableHead>
                            <TableHead>Owner</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Products</TableHead>
                            <TableHead>Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {Array.isArray(allStores) && allStores
                            .filter((store: any) =>
                              store.name?.toLowerCase().includes(searchTerm.toLowerCase())
                            )
                            .map((store: any) => (
                              <TableRow key={store.id}>
                                <TableCell>
                                  <div className="flex items-center">
                                    <div className="w-10 h-10 bg-gray-200 rounded-lg flex items-center justify-center">
                                      <Store className="h-5 w-5 text-gray-500" />
                                    </div>
                                    <div className="ml-3">
                                      <p className="font-medium">{store.name}</p>
                                      <p className="text-sm text-gray-500">{store.description?.substring(0, 50)}...</p>
                                    </div>
                                  </div>
                                </TableCell>
                                <TableCell>
                                  <Badge variant="outline">{store.type}</Badge>
                                </TableCell>
                                <TableCell>{store.ownerName || "N/A"}</TableCell>
                                <TableCell>
                                  <StatusBadge status={store.status || "active"} />
                                </TableCell>
                                <TableCell>{store.productCount || 0}</TableCell>
                                <TableCell>
                                  <div className="flex items-center space-x-2">
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      onClick={() => {
                                        setSelectedStore(store);
                                        setShowStoreDialog(true);
                                      }}
                                    >
                                      <Eye className="h-4 w-4" />
                                    </Button>
                                    <Button size="sm" variant="outline">
                                      <Edit className="h-4 w-4" />
                                    </Button>
                                  </div>
                                </TableCell>
                              </TableRow>
                            ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                </div>
              )}

              {activeTab === "pending" && (
                <div className="space-y-6">
                  <Card>
                    <CardHeader>
                      <CardTitle>Pending User Approvals</CardTitle>
                      <CardDescription>
                        Users waiting for admin approval to access the platform
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      {pendingUsers.length === 0 ? (
                        <div className="text-center py-8">
                          <CheckCircle className="h-16 w-16 text-green-500 mx-auto mb-4" />
                          <h3 className="text-lg font-medium text-gray-900 mb-2">
                            All caught up!
                          </h3>
                          <p className="text-gray-500">
                            No pending user approvals at the moment.
                          </p>
                        </div>
                      ) : (
                        <div className="space-y-4">
                          {Array.isArray(pendingUsers) && pendingUsers.map((user: any) => (
                            <Card key={user.id} className="border-l-4 border-l-yellow-400">
                              <CardContent className="p-6">
                                <div className="flex items-center justify-between">
                                  <div className="flex items-center space-x-4">
                                    <Avatar className="h-12 w-12">
                                      <AvatarFallback className="bg-yellow-100 text-yellow-600">
                                        {user.fullName?.charAt(0) || "U"}
                                      </AvatarFallback>
                                    </Avatar>
                                    <div>
                                      <h3 className="font-medium text-gray-900">{user.fullName}</h3>
                                      <p className="text-sm text-gray-500">{user.email}</p>
                                      <div className="flex items-center mt-2 space-x-4">
                                        <Badge variant="outline">{user.role}</Badge>
                                        <span className="text-xs text-gray-500">
                                          Applied: {user.createdAt ? new Date(user.createdAt).toLocaleDateString() : "N/A"}
                                        </span>
                                      </div>
                                    </div>
                                  </div>
                                  <div className="flex space-x-3">
                                    <Button
                                      onClick={() => approveUserMutation.mutate(user.id)}
                                      disabled={approveUserMutation.isPending || rejectUserMutation.isPending}
                                      className="bg-green-600 hover:bg-green-700 disabled:opacity-50 transition-all duration-200"
                                    >
                                      {approveUserMutation.isPending ? (
                                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                                      ) : (
                                        <CheckCircle className="h-4 w-4 mr-2" />
                                      )}
                                      {approveUserMutation.isPending ? "Approving..." : "Approve"}
                                    </Button>
                                    <Button
                                      variant="destructive"
                                      onClick={() => rejectUserMutation.mutate({ userId: user.id, reason: "Admin rejection" })}
                                      disabled={approveUserMutation.isPending || rejectUserMutation.isPending}
                                      className="disabled:opacity-50 transition-all duration-200"
                                    >
                                      {rejectUserMutation.isPending ? (
                                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                                      ) : (
                                        <XCircle className="h-4 w-4 mr-2" />
                                      )}
                                      {rejectUserMutation.isPending ? "Rejecting..." : "Reject"}
                                    </Button>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                  
                  {/* Delivery Partner Approvals Section */}
                  <Card>
                    <CardHeader>
                      <CardTitle>Pending Delivery Partner Approvals</CardTitle>
                      <CardDescription>
                        Delivery partners waiting for admin approval to start working
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      {(() => {
                        const pendingPartners = deliveryPartners.filter((partner: any) => partner.status === 'pending');
                        return pendingPartners.length === 0 ? (
                          <div className="text-center py-8">
                            <CheckCircle className="h-16 w-16 text-green-500 mx-auto mb-4" />
                            <h3 className="text-lg font-medium text-gray-900 mb-2">
                              All caught up!
                            </h3>
                            <p className="text-gray-500">
                              No pending delivery partner approvals at the moment.
                            </p>
                          </div>
                        ) : (
                          <div className="space-y-4">
                            {pendingPartners.map((partner: any) => {
                              const partnerUser = allUsers.find((user: any) => user.id === partner.userId);
                              return (
                                <Card key={partner.id} className="border-l-4 border-l-orange-400">
                                  <CardContent className="p-6">
                                    <div className="flex items-center justify-between">
                                      <div className="flex items-center space-x-4">
                                        <Avatar className="h-12 w-12">
                                          <AvatarFallback className="bg-orange-100 text-orange-600">
                                            <Truck className="h-6 w-6" />
                                          </AvatarFallback>
                                        </Avatar>
                                        <div>
                                          <h3 className="font-medium text-gray-900">{partnerUser?.fullName || "Unknown User"}</h3>
                                          <p className="text-sm text-gray-500">{partnerUser?.email}</p>
                                          <div className="flex items-center mt-2 space-x-4">
                                            <Badge variant="outline" className="text-orange-600 border-orange-300">
                                              {partner.vehicleType} • {partner.vehicleNumber}
                                            </Badge>
                                            <span className="text-xs text-gray-500">
                                              Applied: {partner.createdAt ? new Date(partner.createdAt).toLocaleDateString() : "N/A"}
                                            </span>
                                          </div>
                                          <div className="flex items-center mt-1 space-x-2">
                                            <span className="text-xs text-gray-500">Areas:</span>
                                            {partner.deliveryAreas?.map((area: string, index: number) => (
                                              <Badge key={index} variant="secondary" className="text-xs px-1 py-0">
                                                {area}
                                              </Badge>
                                            ))}
                                          </div>
                                        </div>
                                      </div>
                                      <div className="flex space-x-3">
                                        <Button
                                          onClick={() => approvePartnerMutation.mutate(partner.id)}
                                          disabled={approvePartnerMutation.isPending || rejectPartnerMutation.isPending}
                                          className="bg-green-600 hover:bg-green-700 disabled:opacity-50 transition-all duration-200"
                                        >
                                          {approvePartnerMutation.isPending ? (
                                            <>
                                              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                                              Approving...
                                            </>
                                          ) : (
                                            <>
                                              <CheckCircle className="h-4 w-4 mr-2" />
                                              Approve
                                            </>
                                          )}
                                        </Button>
                                        <AlertDialog>
                                          <AlertDialogTrigger asChild>
                                            <Button 
                                              variant="destructive" 
                                              disabled={approvePartnerMutation.isPending || rejectPartnerMutation.isPending}
                                            >
                                              <X className="h-4 w-4 mr-2" />
                                              Reject
                                            </Button>
                                          </AlertDialogTrigger>
                                          <AlertDialogContent>
                                            <AlertDialogHeader>
                                              <AlertDialogTitle>Reject Delivery Partner</AlertDialogTitle>
                                              <AlertDialogDescription>
                                                Are you sure you want to reject {partnerUser?.fullName}? Please provide a reason for rejection.
                                              </AlertDialogDescription>
                                            </AlertDialogHeader>
                                            <Textarea
                                              placeholder="Reason for rejection..."
                                              id={`reject-reason-${partner.id}`}
                                              className="mt-2"
                                            />
                                            <AlertDialogFooter>
                                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                                              <AlertDialogAction
                                                onClick={() => {
                                                  const reason = (document.getElementById(`reject-reason-${partner.id}`) as HTMLTextAreaElement)?.value || "Application does not meet requirements";
                                                  rejectPartnerMutation.mutate({ partnerId: partner.id, reason });
                                                }}
                                                className="bg-red-600 hover:bg-red-700"
                                              >
                                                {rejectPartnerMutation.isPending ? (
                                                  <>
                                                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                                                    Rejecting...
                                                  </>
                                                ) : (
                                                  "Reject Partner"
                                                )}
                                              </AlertDialogAction>
                                            </AlertDialogFooter>
                                          </AlertDialogContent>
                                        </AlertDialog>
                                      </div>
                                    </div>
                                  </CardContent>
                                </Card>
                              );
                            })}
                          </div>
                        );
                      })()}
                    </CardContent>
                  </Card>
                </div>
              )}

              {activeTab === "products" && (
                <div className="space-y-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                        <Input
                          placeholder="Search products..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          className="pl-10 w-80"
                        />
                      </div>
                    </div>
                    <Button>
                      <Plus className="h-4 w-4 mr-2" />
                      Add Product
                    </Button>
                  </div>

                  <Card>
                    <CardContent className="p-0">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Product</TableHead>
                            <TableHead>Store</TableHead>
                            <TableHead>Price</TableHead>
                            <TableHead>Stock</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {Array.isArray(allProducts) && allProducts
                            .filter((product: any) =>
                              product.name?.toLowerCase().includes(searchTerm.toLowerCase())
                            )
                            .map((product: any) => (
                              <TableRow key={product.id}>
                                <TableCell>
                                  <div className="flex items-center">
                                    <div className="w-10 h-10 bg-gray-200 rounded-lg flex items-center justify-center">
                                      <Package className="h-5 w-5 text-gray-500" />
                                    </div>
                                    <div className="ml-3">
                                      <p className="font-medium">{product.name}</p>
                                      <p className="text-sm text-gray-500">{product.description?.substring(0, 50)}...</p>
                                    </div>
                                  </div>
                                </TableCell>
                                <TableCell>{product.storeName || "N/A"}</TableCell>
                                <TableCell>${product.price}</TableCell>
                                <TableCell>{product.stock || 0}</TableCell>
                                <TableCell>
                                  <StatusBadge status={product.isActive ? "active" : "inactive"} />
                                </TableCell>
                                <TableCell>
                                  <div className="flex items-center space-x-2">
                                    <Button size="sm" variant="outline">
                                      <Eye className="h-4 w-4" />
                                    </Button>
                                    <Button size="sm" variant="outline">
                                      <Edit className="h-4 w-4" />
                                    </Button>
                                  </div>
                                </TableCell>
                              </TableRow>
                            ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                </div>
              )}

              {activeTab === "orders" && (
                <div className="space-y-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                        <Input
                          placeholder="Search orders..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          className="pl-10 w-80"
                        />
                      </div>
                      <Select value={filterStatus} onValueChange={setFilterStatus}>
                        <SelectTrigger className="w-40">
                          <SelectValue placeholder="Filter by status" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">All Status</SelectItem>
                          <SelectItem value="pending">Pending</SelectItem>
                          <SelectItem value="confirmed">Confirmed</SelectItem>
                          <SelectItem value="shipped">Shipped</SelectItem>
                          <SelectItem value="delivered">Delivered</SelectItem>
                          <SelectItem value="cancelled">Cancelled</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <Card>
                    <CardContent className="p-0">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Order ID</TableHead>
                            <TableHead>Customer</TableHead>
                            <TableHead>Total</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Date</TableHead>
                            <TableHead>Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {Array.isArray(allOrders) && allOrders
                            .filter((order: any) => {
                              const matchesStatus = filterStatus === "all" || order.status === filterStatus;
                              return matchesStatus;
                            })
                            .map((order: any) => (
                              <TableRow key={order.id}>
                                <TableCell>
                                  <span className="font-mono text-sm">#{order.id}</span>
                                </TableCell>
                                <TableCell>{order.customerName || "N/A"}</TableCell>
                                <TableCell>${order.totalAmount || order.total || 0}</TableCell>
                                <TableCell>
                                  <StatusBadge status={order.status} />
                                </TableCell>
                                <TableCell>
                                  {order.createdAt ? new Date(order.createdAt).toLocaleDateString() : "N/A"}
                                </TableCell>
                                <TableCell>
                                  <div className="flex items-center space-x-2">
                                    <Button size="sm" variant="outline">
                                      <Eye className="h-4 w-4" />
                                    </Button>
                                    <Button size="sm" variant="outline">
                                      <Edit className="h-4 w-4" />
                                    </Button>
                                  </div>
                                </TableCell>
                              </TableRow>
                            ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                </div>
              )}

              {activeTab === "coupons" && (
                <div className="space-y-6">
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-medium">Coupon Management</h3>
                    <Button>
                      <Plus className="h-4 w-4 mr-2" />
                      Add Coupon
                    </Button>
                  </div>

                  <Card>
                    <CardContent className="p-0">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Code</TableHead>
                            <TableHead>Discount</TableHead>
                            <TableHead>Min Order</TableHead>
                            <TableHead>Usage</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Expires</TableHead>
                            <TableHead>Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {Array.isArray(coupons) && coupons.map((coupon: any) => (
                            <TableRow key={coupon.id}>
                              <TableCell>
                                <code className="bg-gray-100 px-2 py-1 rounded text-sm">
                                  {coupon.code}
                                </code>
                              </TableCell>
                              <TableCell>
                                {coupon.discountType === 'percentage' ? 
                                  `${coupon.discountValue}%` : 
                                  `$${coupon.discountValue}`
                                }
                              </TableCell>
                              <TableCell>${coupon.minimumOrderAmount || 0}</TableCell>
                              <TableCell>
                                {coupon.usedCount || 0} / {coupon.usageLimit || '∞'}
                              </TableCell>
                              <TableCell>
                                <StatusBadge status={coupon.isActive ? "active" : "inactive"} />
                              </TableCell>
                              <TableCell>
                                {coupon.expiresAt ? new Date(coupon.expiresAt).toLocaleDateString() : "Never"}
                              </TableCell>
                              <TableCell>
                                <div className="flex items-center space-x-2">
                                  <Button size="sm" variant="outline">
                                    <Edit className="h-4 w-4" />
                                  </Button>
                                  <Button size="sm" variant="destructive">
                                    <Trash2 className="h-4 w-4" />
                                  </Button>
                                </div>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                </div>
              )}

              {activeTab === "delivery" && (
                <div className="space-y-6">
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-medium">Delivery Zone Management</h3>
                    <Button onClick={() => setShowCreateZone(true)}>
                      <Plus className="h-4 w-4 mr-2" />
                      Add Zone
                    </Button>
                  </div>

                  <Card>
                    <CardContent className="p-6">
                      {Array.isArray(deliveryZones) && deliveryZones.length === 0 ? (
                        <div className="text-center py-8">
                          <Truck className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                          <h3 className="text-lg font-medium text-gray-900 mb-2">
                            No delivery zones configured
                          </h3>
                          <p className="text-gray-500 mb-4">
                            Set up delivery zones to manage shipping fees and coverage areas.
                          </p>
                          <Button>
                            <Plus className="h-4 w-4 mr-2" />
                            Create First Zone
                          </Button>
                        </div>
                      ) : (
                        <div className="space-y-4">
                          {Array.isArray(deliveryZones) && deliveryZones.map((zone: any) => (
                            <Card key={zone.id} className="border">
                              <CardContent className="p-4">
                                <div className="flex items-center justify-between">
                                  <div>
                                    <h4 className="font-medium">{zone.name}</h4>
                                    <p className="text-sm text-gray-500">
                                      {zone.minDistance}km - {zone.maxDistance}km
                                    </p>
                                    <p className="text-sm text-gray-600">
                                      Base fee: ${zone.baseFee} + ${zone.perKmRate}/km
                                    </p>
                                  </div>
                                  <div className="flex items-center space-x-2">
                                    <Switch 
                                      checked={zone.isActive} 
                                      className="data-[state=checked]:bg-green-600"
                                    />
                                    <Button 
                                      size="sm" 
                                      variant="outline"
                                      onClick={() => {
                                        setEditingZone(zone);
                                        setShowEditZoneDialog(true);
                                      }}
                                    >
                                      <Edit className="h-4 w-4" />
                                    </Button>
                                    <Button size="sm" variant="destructive">
                                      <Trash2 className="h-4 w-4" />
                                    </Button>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </div>
              )}

              {activeTab === "settings" && (
                <div className="space-y-6">
                  <h3 className="text-lg font-medium">System Settings</h3>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Admin Profile Management */}
                    <Card>
                      <CardHeader>
                        <CardTitle>Admin Profile</CardTitle>
                        <CardDescription>
                          Manage your admin account details
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div>
                          <Label htmlFor="admin-name">Full Name</Label>
                          <Input
                            id="admin-name"
                            value={adminUser?.fullName || ""}
                            readOnly
                            className="mt-1 bg-gray-50"
                          />
                        </div>
                        <div>
                          <Label htmlFor="admin-email">Email</Label>
                          <Input
                            id="admin-email"
                            value={adminUser?.email || ""}
                            readOnly
                            className="mt-1 bg-gray-50"
                          />
                        </div>
                        <div className="flex space-x-2">
                          <Dialog open={showEditProfileDialog} onOpenChange={setShowEditProfileDialog}>
                            <DialogTrigger asChild>
                              <Button variant="outline" size="sm">
                                <Edit className="h-4 w-4 mr-2" />
                                Edit Profile
                              </Button>
                            </DialogTrigger>
                            <DialogContent>
                              <DialogHeader>
                                <DialogTitle>Edit Admin Profile</DialogTitle>
                                <DialogDescription>
                                  Update your admin account information
                                </DialogDescription>
                              </DialogHeader>
                              <div className="space-y-4">
                                <div>
                                  <Label htmlFor="edit-name">Full Name</Label>
                                  <Input
                                    id="edit-name"
                                    defaultValue={adminUser?.fullName || ""}
                                    placeholder="Enter your full name"
                                  />
                                </div>
                                <div>
                                  <Label htmlFor="edit-email">Email</Label>
                                  <Input
                                    id="edit-email"
                                    type="email"
                                    defaultValue={adminUser?.email || ""}
                                    placeholder="Enter your email"
                                  />
                                </div>
                                <div className="flex justify-end space-x-2">
                                  <Button 
                                    variant="outline" 
                                    onClick={() => setShowEditProfileDialog(false)}
                                  >
                                    Cancel
                                  </Button>
                                  <Button 
                                    onClick={() => {
                                      const nameInput = document.getElementById('edit-name') as HTMLInputElement;
                                      const emailInput = document.getElementById('edit-email') as HTMLInputElement;

                                      if (!nameInput.value || !emailInput.value) {
                                        toast({
                                          title: "Error",
                                          description: "Please fill in all fields.",
                                          variant: "destructive",
                                        });
                                        return;
                                      }

                                      updateProfileMutation.mutate({
                                        fullName: nameInput.value,
                                        email: emailInput.value,
                                      });
                                    }}
                                    disabled={updateProfileMutation.isPending}
                                  >
                                    Save Changes
                                  </Button>
                                </div>
                              </div>
                            </DialogContent>
                          </Dialog>

                          <Dialog>
                            <DialogTrigger asChild>
                              <Button variant="outline" size="sm">
                                <Shield className="h-4 w-4 mr-2" />
                                Change Password
                              </Button>
                            </DialogTrigger>
                            <DialogContent>
                              <DialogHeader>
                                <DialogTitle>Change Admin Password</DialogTitle>
                                <DialogDescription>
                                  Enter your current password and choose a new secure password
                                </DialogDescription>
                              </DialogHeader>
                              <div className="space-y-4">
                                <div>
                                  <Label htmlFor="current-password">Current Password</Label>
                                  <Input
                                    id="current-password"
                                    type="password"
                                    placeholder="Enter your current password"
                                  />
                                </div>
                                <div>
                                  <Label htmlFor="new-password">New Password</Label>
                                  <Input
                                    id="new-password"
                                    type="password"
                                    placeholder="Enter new password"
                                  />
                                </div>
                                <div>
                                  <Label htmlFor="confirm-password">Confirm New Password</Label>
                                  <Input
                                    id="confirm-password"
                                    type="password"
                                    placeholder="Confirm new password"
                                  />
                                </div>
                                <div className="flex justify-end space-x-2">
                                  <DialogTrigger asChild>
                                    <Button variant="outline">Cancel</Button>
                                  </DialogTrigger>
                                  <Button 
                                    onClick={async () => {
                                      const currentPasswordInput = document.getElementById('current-password') as HTMLInputElement;
                                      const newPasswordInput = document.getElementById('new-password') as HTMLInputElement;
                                      const confirmPasswordInput = document.getElementById('confirm-password') as HTMLInputElement;

                                      if (!currentPasswordInput.value || !newPasswordInput.value) {
                                        toast({
                                          title: "Error",
                                          description: "Please fill in all password fields.",
                                          variant: "destructive",
                                        });
                                        return;
                                      }

                                      if (newPasswordInput.value !== confirmPasswordInput.value) {
                                        toast({
                                          title: "Error",
                                          description: "New passwords do not match.",
                                          variant: "destructive",
                                        });
                                        return;
                                      }

                                      if (newPasswordInput.value.length < 6) {
                                        toast({
                                          title: "Error",
                                          description: "New password must be at least 6 characters long.",
                                          variant: "destructive",
                                        });
                                        return;
                                      }

                                      try {
                                        const response = await apiRequest("/api/admin/change-password", {
                                          method: "PUT",
                                          headers: { "Content-Type": "application/json" },
                                          body: JSON.stringify({
                                            adminId: adminUser.id,
                                            currentPassword: currentPasswordInput.value,
                                            newPassword: newPasswordInput.value,
                                          }),
                                        });

                                        const result = await response.json();

                                        if (response.ok) {
                                          toast({
                                            title: "Password Changed",
                                            description: "Your admin password has been changed successfully.",
                                          });
                                          // Clear the form
                                          currentPasswordInput.value = "";
                                          newPasswordInput.value = "";
                                          confirmPasswordInput.value = "";
                                        } else {
                                          toast({
                                            title: "Error",
                                            description: result.error || "Failed to change password.",
                                            variant: "destructive",
                                          });
                                        }
                                      } catch (error) {
                                        toast({
                                          title: "Error",
                                          description: "Network error. Please try again.",
                                          variant: "destructive",
                                        });
                                      }
                                    }}
                                  >
                                    Change Password
                                  </Button>
                                </div>
                              </div>
                            </DialogContent>
                          </Dialog>
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle>Platform Settings</CardTitle>
                        <CardDescription>
                          Configure general platform settings
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div className="flex items-center justify-between">
                          <Label htmlFor="maintenance">Maintenance Mode</Label>
                          <Switch id="maintenance" />
                        </div>
                        <div className="flex items-center justify-between">
                          <Label htmlFor="registration">Allow New Registrations</Label>
                          <Switch id="registration" defaultChecked />
                        </div>
                        <div className="flex items-center justify-between">
                          <Label htmlFor="notifications">Email Notifications</Label>
                          <Switch id="notifications" defaultChecked />
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle>Commission Settings</CardTitle>
                        <CardDescription>
                          Set platform commission rates
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div>
                          <Label htmlFor="store-commission">Store Commission (%)</Label>
                          <Input
                            id="store-commission"
                            type="number"
                            defaultValue="5"
                            className="mt-1"
                          />
                        </div>
                        <div>
                          <Label htmlFor="restaurant-commission">Restaurant Commission (%)</Label>
                          <Input
                            id="restaurant-commission"
                            type="number"
                            defaultValue="8"
                            className="mt-1"
                          />
                        </div>
                        <div>
                          <Label htmlFor="delivery-commission">Delivery Commission (%)</Label>
                          <Input
                            id="delivery-commission"
                            type="number"
                            defaultValue="3"
                            className="mt-1"
                          />
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle>Payment Settings</CardTitle>
                        <CardDescription>
                          Configure payment options
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div className="flex items-center justify-between">
                          <Label htmlFor="cod">Cash on Delivery</Label>
                          <Switch id="cod" defaultChecked />
                        </div>
                        <div className="flex items-center justify-between">
                          <Label htmlFor="stripe">Stripe Payments</Label>
                          <Switch id="stripe" defaultChecked />
                        </div>
                        <div className="flex items-center justify-between">
                          <Label htmlFor="paypal">PayPal Payments</Label>
                          <Switch id="paypal" />
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle>Security Settings</CardTitle>
                        <CardDescription>
                          Manage security configurations
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div>
                          <Label htmlFor="session-timeout">Session Timeout (minutes)</Label>
                          <Input
                            id="session-timeout"
                            type="number"
                            defaultValue="60"
                            className="mt-1"
                          />
                        </div>
                        <div className="flex items-center justify-between">
                          <Label htmlFor="two-factor">Two-Factor Authentication</Label>
                          <Switch id="two-factor" />
                        </div>
                        <div className="flex items-center justify-between">
                          <Label htmlFor="password-policy">Strong Password Policy</Label>
                          <Switch id="password-policy" defaultChecked />
                        </div>
                      </CardContent>
                    </Card>
                  </div>

                  <Card>
                    <CardHeader>
                      <CardTitle>System Information</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                          <Label className="text-sm font-medium text-gray-600">Platform Version</Label>
                          <p className="mt-1 text-lg font-semibold">v2.1.0</p>
                        </div>
                        <div>
                          <Label className="text-sm font-medium text-gray-600">Database Status</Label>
                          <p className="mt-1 text-lg font-semibold text-green-600">Connected</p>
                        </div>
                        <div>
                          <Label className="text-sm font-medium text-gray-600">Last Backup</Label>
                          <p className="mt-1 text-lg font-semibold">{new Date().toLocaleDateString()}</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}

              {activeTab === "analytics" && (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <Card>
                      <CardHeader>
                        <CardTitle>Platform Growth</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          <div>
                            <div className="flex justify-between text-sm">
                              <span>User Growth</span>
                              <span>85%</span>
                            </div>
                            <Progress value={85} className="mt-2" />
                          </div>
                          <div>
                            <div className="flex justify-between text-sm">
                              <span>Store Growth</span>
                              <span>72%</span>
                            </div>
                            <Progress value={72} className="mt-2" />
                          </div>
                          <div>
                            <div className="flex justify-between text-sm">
                              <span>Revenue Growth</span>
                              <span>91%</span>
                            </div>
                            <Progress value={91} className="mt-2" />
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle>Quick Stats</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-2 gap-4">
                          <div className="text-center">
                            <div className="text-2xl font-bold text-blue-600">{totalUsers}</div>
                            <div className="text-sm text-gray-500">Total Users</div>
                          </div>
                          <div className="text-center">
                            <div className="text-2xl font-bold text-green-600">{totalStores}</div>
                            <div className="text-sm text-gray-500">Total Stores</div>
                          </div>
                          <div className="text-center">
                            <div className="text-2xl font-bold text-purple-600">{totalOrders}</div>
                            <div className="text-sm text-gray-500">Total Orders</div>
                          </div>
                          <div className="text-center">
                            <div className="text-2xl font-bold text-yellow-600">{totalProducts}</div>
                            <div className="text-sm text-gray-500">Total Products</div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              )}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      {/* Enhanced User Detail Dialog */}
      <Dialog open={showUserDialog} onOpenChange={setShowUserDialog}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Complete User Registration Details</DialogTitle>
          </DialogHeader>
          {selectedUser && (
            <div className="space-y-6">
              {/* User Header */}
              <div className="flex items-center space-x-4">
                <Avatar className="h-16 w-16">
                  <AvatarFallback className="text-lg">
                    {selectedUser.fullName?.charAt(0) || "U"}
                  </AvatarFallback>
                </Avatar>
                <div>
                  <h3 className="text-xl font-semibold">{selectedUser.fullName}</h3>
                  <p className="text-gray-500">{selectedUser.email}</p>
                  <div className="flex items-center space-x-2 mt-2">
                    <Badge variant="outline">{selectedUser.role}</Badge>
                    <StatusBadge status={selectedUser.status} />
                  </div>
                </div>
              </div>

              <Separator />

              {/* Basic Information */}
              <div>
                <h4 className="text-lg font-semibold mb-3 text-blue-600">Basic Information</h4>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-sm font-medium text-gray-600">User ID</Label>
                    <p className="mt-1">{selectedUser.id}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-gray-600">Phone</Label>
                    <p className="mt-1">{selectedUser.phone || "Not provided"}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-gray-600">Email</Label>
                    <p className="mt-1">{selectedUser.email}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-gray-600">Firebase UID</Label>
                    <p className="mt-1 text-xs text-gray-500">{selectedUser.firebaseUid || "Not linked"}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-gray-600">Address</Label>
                    <p className="mt-1">{selectedUser.address || "Not provided"}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-gray-600">Joined Date</Label>
                    <p className="mt-1">
                      {selectedUser.createdAt ? new Date(selectedUser.createdAt).toLocaleDateString() : "N/A"}
                    </p>
                  </div>
                </div>
              </div>

              {/* Role-Specific Information */}
              {selectedUser.role === 'shopkeeper' && (
                <>
                  <Separator />
                  <div>
                    <h4 className="text-lg font-semibold mb-3 text-green-600">Shopkeeper Details</h4>
                    {(() => {
                      const userStore = allStores.find((store: any) => store.ownerId === selectedUser.id);
                      return userStore ? (
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <Label className="text-sm font-medium text-gray-600">Store Name</Label>
                            <p className="mt-1">{userStore.name}</p>
                          </div>
                          <div>
                            <Label className="text-sm font-medium text-gray-600">Store Type</Label>
                            <p className="mt-1">
                              <Badge variant="outline">{userStore.type}</Badge>
                            </p>
                          </div>
                          <div>
                            <Label className="text-sm font-medium text-gray-600">Store Address</Label>
                            <p className="mt-1">{userStore.address || "Not provided"}</p>
                          </div>
                          <div>
                            <Label className="text-sm font-medium text-gray-600">Store Description</Label>
                            <p className="mt-1">{userStore.description || "No description"}</p>
                          </div>
                          <div>
                            <Label className="text-sm font-medium text-gray-600">Store Phone</Label>
                            <p className="mt-1">{userStore.phone || "Not provided"}</p>
                          </div>
                          <div>
                            <Label className="text-sm font-medium text-gray-600">Store Approval Status</Label>
                            <p className="mt-1">
                              <StatusBadge status={userStore.status || "active"} />
                            </p>
                          </div>
                          {userStore.type === 'restaurant' && (
                            <>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Delivery Fee</Label>
                                <p className="mt-1">₹{userStore.deliveryFee || "Not set"}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Minimum Order</Label>
                                <p className="mt-1">₹{userStore.minimumOrder || "Not set"}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Cuisine Type</Label>
                                <p className="mt-1">{userStore.cuisineType || "Not specified"}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Opening Hours</Label>
                                <p className="mt-1">{userStore.openingHours || "Not specified"}</p>
                              </div>
                            </>
                          )}
                        </div>
                      ) : (
                        <p className="text-gray-500 italic">No store information found for this shopkeeper.</p>
                      );
                    })()}
                  </div>
                </>
              )}

              {selectedUser.role === 'delivery_partner' && (
                <>
                  <Separator />
                  <div>
                    <h4 className="text-lg font-semibold mb-4 text-orange-600 flex items-center">
                      <Truck className="h-5 w-5 mr-2" />
                      Comprehensive Delivery Partner Information
                    </h4>
                    {(() => {
                      const partnerDetails = deliveryPartners.find((partner: any) => partner.userId === selectedUser.id);
                      return partnerDetails ? (
                        <div className="space-y-6">
                          {/* Status & Basic Info */}
                          <div className="bg-orange-50 p-4 rounded-lg">
                            <div className="grid grid-cols-3 gap-4">
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Partner ID</Label>
                                <p className="mt-1 font-semibold">{partnerDetails.id}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Approval Status</Label>
                                <p className="mt-1">
                                  <StatusBadge status={partnerDetails.status} />
                                </p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Registration Date</Label>
                                <p className="mt-1 text-sm">
                                  {partnerDetails.createdAt ? new Date(partnerDetails.createdAt).toLocaleDateString() : "N/A"}
                                </p>
                              </div>
                            </div>
                          </div>

                          {/* Vehicle Information */}
                          <div>
                            <h5 className="text-md font-medium text-gray-800 mb-3 flex items-center">
                              <Car className="h-4 w-4 mr-2" />
                              Vehicle Details
                            </h5>
                            <div className="grid grid-cols-3 gap-4 bg-gray-50 p-4 rounded-lg">
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Type</Label>
                                <p className="mt-1">
                                  <Badge variant="outline">{partnerDetails.vehicleType}</Badge>
                                </p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Number</Label>
                                <p className="mt-1 font-mono">{partnerDetails.vehicleNumber}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Brand</Label>
                                <p className="mt-1">{partnerDetails.vehicleBrand || "Not specified"}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Model</Label>
                                <p className="mt-1">{partnerDetails.vehicleModel || "Not specified"}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Year</Label>
                                <p className="mt-1">{partnerDetails.vehicleYear || "Not specified"}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Color</Label>
                                <p className="mt-1">{partnerDetails.vehicleColor || "Not specified"}</p>
                              </div>
                            </div>
                          </div>

                          {/* License & Documents */}
                          <div>
                            <h5 className="text-md font-medium text-gray-800 mb-3 flex items-center">
                              <FileText className="h-4 w-4 mr-2" />
                              License & Documents
                            </h5>
                            <div className="grid grid-cols-2 gap-4 bg-gray-50 p-4 rounded-lg">
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Driving License</Label>
                                <p className="mt-1 font-mono">{partnerDetails.drivingLicense || "Not provided"}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">License Expiry</Label>
                                <p className="mt-1">{partnerDetails.licenseExpiryDate || "Not specified"}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">ID Proof Type</Label>
                                <p className="mt-1">
                                  <Badge variant="secondary">{partnerDetails.idProofType}</Badge>
                                </p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">ID Proof Number</Label>
                                <p className="mt-1 font-mono">{partnerDetails.idProofNumber}</p>
                              </div>
                            </div>
                          </div>

                          {/* Banking Information */}
                          <div>
                            <h5 className="text-md font-medium text-gray-800 mb-3 flex items-center">
                              <CreditCard className="h-4 w-4 mr-2" />
                              Banking Information
                            </h5>
                            <div className="grid grid-cols-2 gap-4 bg-gray-50 p-4 rounded-lg">
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Account Number</Label>
                                <p className="mt-1 font-mono">{partnerDetails.bankAccountNumber}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">IFSC Code</Label>
                                <p className="mt-1 font-mono">{partnerDetails.ifscCode}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Bank Name</Label>
                                <p className="mt-1">{partnerDetails.bankName || "Not specified"}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Account Holder</Label>
                                <p className="mt-1">{partnerDetails.accountHolderName || "Not specified"}</p>
                              </div>
                            </div>
                          </div>

                          {/* Emergency Contact */}
                          <div>
                            <h5 className="text-md font-medium text-gray-800 mb-3 flex items-center">
                              <Phone className="h-4 w-4 mr-2" />
                              Emergency Contact
                            </h5>
                            <div className="grid grid-cols-3 gap-4 bg-gray-50 p-4 rounded-lg">
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Contact Number</Label>
                                <p className="mt-1 font-mono">{partnerDetails.emergencyContact}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Contact Name</Label>
                                <p className="mt-1">{partnerDetails.emergencyContactName || "Not specified"}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Relationship</Label>
                                <p className="mt-1">{partnerDetails.emergencyContactRelation || "Not specified"}</p>
                              </div>
                            </div>
                          </div>

                          {/* Working Preferences & Experience */}
                          <div>
                            <h5 className="text-md font-medium text-gray-800 mb-3 flex items-center">
                              <Clock className="h-4 w-4 mr-2" />
                              Working Preferences & Experience
                            </h5>
                            <div className="bg-gray-50 p-4 rounded-lg space-y-3">
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Delivery Areas</Label>
                                <div className="mt-1 flex flex-wrap gap-1">
                                  {partnerDetails.deliveryAreas?.length > 0 ? (
                                    partnerDetails.deliveryAreas.map((area: string, index: number) => (
                                      <Badge key={index} variant="secondary" className="text-xs">
                                        {area}
                                      </Badge>
                                    ))
                                  ) : (
                                    <span className="text-gray-500">No areas specified</span>
                                  )}
                                </div>
                              </div>
                              <div className="grid grid-cols-2 gap-4">
                                <div>
                                  <Label className="text-sm font-medium text-gray-600">Working Hours</Label>
                                  <p className="mt-1">{partnerDetails.workingHours || "Not specified"}</p>
                                </div>
                                <div>
                                  <Label className="text-sm font-medium text-gray-600">Experience</Label>
                                  <p className="mt-1">{partnerDetails.experience || "Not specified"}</p>
                                </div>
                              </div>
                              {partnerDetails.previousEmployment && (
                                <div>
                                  <Label className="text-sm font-medium text-gray-600">Previous Employment</Label>
                                  <p className="mt-1 text-sm">{partnerDetails.previousEmployment}</p>
                                </div>
                              )}
                              {partnerDetails.references && (
                                <div>
                                  <Label className="text-sm font-medium text-gray-600">References</Label>
                                  <p className="mt-1 text-sm">{partnerDetails.references}</p>
                                </div>
                              )}
                            </div>
                          </div>

                          {/* Document URLs */}
                          {(partnerDetails.idProofUrl || partnerDetails.drivingLicenseUrl || partnerDetails.vehicleRegistrationUrl || partnerDetails.insuranceUrl || partnerDetails.photoUrl) && (
                            <div>
                              <h5 className="text-md font-medium text-gray-800 mb-3 flex items-center">
                                <FileText className="h-4 w-4 mr-2" />
                                Uploaded Documents
                              </h5>
                              <div className="bg-gray-50 p-4 rounded-lg">
                                <div className="flex flex-wrap gap-2">
                                  {partnerDetails.idProofUrl && (
                                    <Button size="sm" variant="outline" onClick={() => window.open(partnerDetails.idProofUrl, '_blank')}>
                                      <FileText className="h-3 w-3 mr-1" />
                                      ID Proof
                                    </Button>
                                  )}
                                  {partnerDetails.drivingLicenseUrl && (
                                    <Button size="sm" variant="outline" onClick={() => window.open(partnerDetails.drivingLicenseUrl, '_blank')}>
                                      <FileText className="h-3 w-3 mr-1" />
                                      Driving License
                                    </Button>
                                  )}
                                  {partnerDetails.vehicleRegistrationUrl && (
                                    <Button size="sm" variant="outline" onClick={() => window.open(partnerDetails.vehicleRegistrationUrl, '_blank')}>
                                      <FileText className="h-3 w-3 mr-1" />
                                      Vehicle Registration
                                    </Button>
                                  )}
                                  {partnerDetails.insuranceUrl && (
                                    <Button size="sm" variant="outline" onClick={() => window.open(partnerDetails.insuranceUrl, '_blank')}>
                                      <FileText className="h-3 w-3 mr-1" />
                                      Insurance
                                    </Button>
                                  )}
                                  {partnerDetails.photoUrl && (
                                    <Button size="sm" variant="outline" onClick={() => window.open(partnerDetails.photoUrl, '_blank')}>
                                      <User className="h-3 w-3 mr-1" />
                                      Photo
                                    </Button>
                                  )}
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Current Status & Performance */}
                          <div>
                            <h5 className="text-md font-medium text-gray-800 mb-3 flex items-center">
                              <TrendingUp className="h-4 w-4 mr-2" />
                              Current Status & Performance
                            </h5>
                            <div className="grid grid-cols-3 gap-4 bg-blue-50 p-4 rounded-lg">
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Current Availability</Label>
                                <p className="mt-1">
                                  <Badge variant={partnerDetails.isAvailable ? "default" : "secondary"}>
                                    {partnerDetails.isAvailable ? "Available" : "Offline"}
                                  </Badge>
                                </p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Total Deliveries</Label>
                                <p className="mt-1 text-lg font-bold text-blue-700">{partnerDetails.totalDeliveries || 0}</p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Rating</Label>
                                <p className="mt-1 text-lg font-bold text-blue-700">
                                  {partnerDetails.rating ? `${parseFloat(partnerDetails.rating).toFixed(1)}★` : "No ratings yet"}
                                </p>
                              </div>
                              <div>
                                <Label className="text-sm font-medium text-gray-600">Total Earnings</Label>
                                <p className="mt-1 text-lg font-bold text-blue-700">₹{parseFloat(partnerDetails.totalEarnings || "0").toFixed(2)}</p>
                              </div>
                              {partnerDetails.approvalDate && (
                                <div>
                                  <Label className="text-sm font-medium text-gray-600">Approved On</Label>
                                  <p className="mt-1 text-sm">
                                    {new Date(partnerDetails.approvalDate).toLocaleDateString()}
                                  </p>
                                </div>
                              )}
                              {partnerDetails.rejectionReason && (
                                <div>
                                  <Label className="text-sm font-medium text-red-600">Rejection Reason</Label>
                                  <p className="mt-1 text-red-600 text-sm">{partnerDetails.rejectionReason}</p>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      ) : (
                        <p className="text-gray-500 italic">No delivery partner information found for this user.</p>
                      );
                    })()}
                  </div>
                </>
              )}

              {selectedUser.role === 'customer' && (
                <>
                  <Separator />
                  <div>
                    <h4 className="text-lg font-semibold mb-3 text-purple-600">Customer Activity</h4>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <Label className="text-sm font-medium text-gray-600">Total Orders</Label>
                        <p className="mt-1">{allOrders.filter((order: any) => order.userId === selectedUser.id).length}</p>
                      </div>
                      <div>
                        <Label className="text-sm font-medium text-gray-600">Account Status</Label>
                        <p className="mt-1">
                          <StatusBadge status={selectedUser.status} />
                        </p>
                      </div>
                      <div>
                        <Label className="text-sm font-medium text-gray-600">Location</Label>
                        <p className="mt-1">{selectedUser.address || "Not provided"}</p>
                      </div>
                      <div>
                        <Label className="text-sm font-medium text-gray-600">Last Active</Label>
                        <p className="mt-1">
                          {selectedUser.updatedAt ? new Date(selectedUser.updatedAt).toLocaleDateString() : "Unknown"}
                        </p>
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Store Detail Dialog */}
      <Dialog open={showStoreDialog} onOpenChange={setShowStoreDialog}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Store Details</DialogTitle>
          </DialogHeader>
          {selectedStore && (
            <div className="space-y-6">
              <div className="flex items-center space-x-4">
                <div className="w-16 h-16 bg-gray-200 rounded-lg flex items-center justify-center">
                  <Store className="h-8 w-8 text-gray-500" />
                </div>
                <div>
                  <h3 className="text-xl font-semibold">{selectedStore.name}</h3>
                  <p className="text-gray-500">{selectedStore.description}</p>
                  <div className="flex items-center space-x-2 mt-2">
                    <Badge variant="outline">{selectedStore.type}</Badge>
                    <StatusBadge status={selectedStore.status || "active"} />
                  </div>
                </div>
              </div>

              <Separator />

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-sm font-medium text-gray-600">Store ID</Label>
                  <p className="mt-1">{selectedStore.id}</p>
                </div>
                <div>
                  <Label className="text-sm font-medium text-gray-600">Owner</Label>
                  <p className="mt-1">{selectedStore.ownerName || "N/A"}</p>
                </div>
                <div>
                  <Label className="text-sm font-medium text-gray-600">Address</Label>
                  <p className="mt-1">{selectedStore.address || "Not provided"}</p>
                </div>
                <div>
                  <Label className="text-sm font-medium text-gray-600">Products</Label>
                  <p className="mt-1">{selectedStore.productCount || 0}</p>
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
       {/* Edit Delivery Zone Dialog */}
       <Dialog open={showEditZoneDialog} onOpenChange={setShowEditZoneDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Delivery Zone</DialogTitle>
          </DialogHeader>
          {editingZone && (
            <div className="space-y-4">
              <div>
                <Label htmlFor="name">Name</Label>
                <Input
                  id="name"
                  value={editingZone.name}
                  onChange={(e) => setEditingZone({...editingZone, name: e.target.value})}
                  className="mt-1"
                />
              </div>
              <div>
                <Label htmlFor="minDistance">Min Distance (km)</Label>
                <Input
                  id="minDistance"
                  type="number"
                  value={editingZone.minDistance}
                  onChange={(e) => setEditingZone({...editingZone, minDistance: e.target.value})}
                  className="mt-1"
                />
              </div>
              <div>
                <Label htmlFor="maxDistance">Max Distance (km)</Label>
                <Input
                  id="maxDistance"
                  type="number"
                  value={editingZone.maxDistance}
                  onChange={(e) => setEditingZone({...editingZone, maxDistance: e.target.value})}
                  className="mt-1"
                />
              </div>
              <div>
                <Label htmlFor="baseFee">Base Fee</Label>
                <Input
                  id="baseFee"
                  type="number"
                  step="0.01"
                  value={editingZone.baseFee}
                  onChange={(e) => setEditingZone({...editingZone, baseFee: e.target.value})}
                  className="mt-1"
                />
              </div>
              <div>
                <Label htmlFor="perKmRate">Per KM Rate</Label>
                <Input
                  id="perKmRate"
                  type="number"
                  step="0.01"
                  value={editingZone.perKmRate}
                  onChange={(e) => setEditingZone({...editingZone, perKmRate: e.target.value})}
                  className="mt-1"
                />
              </div>
              <div className="flex items-center justify-between">
                <Label htmlFor="isActive">Active</Label>
                <Switch
                  id="isActive"
                  checked={editingZone.isActive}
                  onCheckedChange={(checked) => setEditingZone({...editingZone, isActive: checked})}
                  className="data-[state=checked]:bg-green-600"
                />
              </div>
              <div className="flex justify-end space-x-2 pt-4">
                <Button variant="outline" onClick={() => setShowEditZoneDialog(false)}>
                  Cancel
                </Button>
                <Button 
                  onClick={() => {
                    const formData = new FormData();
                    const inputs = document.querySelectorAll('#name, #minDistance, #maxDistance, #baseFee, #perKmRate');
                    const data: any = {};

                    inputs.forEach((input: any) => {
                      if (input.type === 'number') {
                        data[input.id] = parseFloat(input.value) || 0;
                      } else {
                        data[input.id] = input.value;
                      }
                    });

                    data.isActive = editingZone.isActive;

                    updateZoneMutation.mutate({ id: editingZone.id, data });
                  }}
                  disabled={updateZoneMutation.isPending}
                >
                  {updateZoneMutation.isPending ? "Saving..." : "Update Zone"}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Create Delivery Zone Dialog */}
      <Dialog open={showCreateZone} onOpenChange={setShowCreateZone}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Create New Delivery Zone</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="new-name">Name</Label>
              <Input
                id="new-name"
                value={newZone.name}
                onChange={(e) => setNewZone({...newZone, name: e.target.value})}
                className="mt-1"
                placeholder="e.g., Inner City"
              />
            </div>
            <div>
              <Label htmlFor="new-minDistance">Min Distance (km)</Label>
              <Input
                id="new-minDistance"
                type="number"
                step="0.01"
                value={newZone.minDistance}
                onChange={(e) => setNewZone({...newZone, minDistance: e.target.value})}
                className="mt-1"
                placeholder="0"
              />
            </div>
            <div>
              <Label htmlFor="new-maxDistance">Max Distance (km)</Label>
              <Input
                id="new-maxDistance"
                type="number"
                step="0.01"
                value={newZone.maxDistance}
                onChange={(e) => setNewZone({...newZone, maxDistance: e.target.value})}
                className="mt-1"
                placeholder="5"
              />
            </div>
            <div>
              <Label htmlFor="new-baseFee">Base Fee</Label>
              <Input
                id="new-baseFee"
                type="number"
                step="0.01"
                value={newZone.baseFee}
                onChange={(e) => setNewZone({...newZone, baseFee: e.target.value})}
                className="mt-1"
                placeholder="30.00"
              />
            </div>
            <div>
              <Label htmlFor="new-perKmRate">Per KM Rate</Label>
              <Input
                id="new-perKmRate"
                type="number"
                step="0.01"
                value={newZone.perKmRate}
                onChange={(e) => setNewZone({...newZone, perKmRate: e.target.value})}
                className="mt-1"
                placeholder="5.00"
              />
            </div>
            <div className="flex items-center justify-between">
              <Label htmlFor="new-isActive">Active</Label>
              <Switch
                id="new-isActive"
                checked={newZone.isActive}
                onCheckedChange={(checked) => setNewZone({...newZone, isActive: checked})}
                className="data-[state=checked]:bg-green-600"
              />
            </div>
            <div className="flex justify-end space-x-2 pt-4">
              <Button variant="outline" onClick={() => setShowCreateZone(false)}>
                Cancel
              </Button>
              <Button 
                onClick={() => createZoneMutation.mutate(newZone)}
                disabled={createZoneMutation.isPending}
              >
                {createZoneMutation.isPending ? "Creating..." : "Create Zone"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}