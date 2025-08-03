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
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import {
  Users, Store, Package, ShoppingCart, DollarSign, TrendingUp, AlertTriangle, 
  Eye, Edit, Trash2, Plus, Download, Upload, Search, Filter, MoreHorizontal,
  CheckCircle, XCircle, Clock, Ban, Settings, Bell, Shield, CreditCard,
  BarChart3, FileText, MessageSquare, Tag, Image, Globe, Zap, UserCheck,
  LogOut, RefreshCw, Calendar, Mail, Phone, MapPin, Truck
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

export default function ComprehensiveAdminDashboard() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [adminUser, setAdminUser] = useState<any>(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [searchTerm, setSearchTerm] = useState("");
  const [filterStatus, setFilterStatus] = useState("all");
  const [processingApprovals, setProcessingApprovals] = useState<Set<number>>(new Set());
  const [processingRejections, setProcessingRejections] = useState<Set<number>>(new Set());
  const [editingZone, setEditingZone] = useState<any>(null);
  const [showCreateZone, setShowCreateZone] = useState(false);
  const [newZone, setNewZone] = useState({
    name: "",
    minDistance: "",
    maxDistance: "",
    baseFee: "",
    perKmRate: "",
    isActive: true
  });

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
  }) as { data: any };

  const { data: allUsers = [] } = useQuery({
    queryKey: ["/api/admin/users"],
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

  const { data: transactions = [] } = useQuery({
    queryKey: ["/api/admin/transactions"],
    enabled: !!adminUser,
  }) as { data: any[] };

  const { data: coupons = [] } = useQuery({
    queryKey: ["/api/admin/coupons"],
    enabled: !!adminUser,
  }) as { data: any[] };

  const { data: supportTickets = [] } = useQuery({
    queryKey: ["/api/admin/support-tickets"],
    enabled: !!adminUser,
  }) as { data: any[] };

  const { data: vendorVerifications = [] } = useQuery({
    queryKey: ["/api/admin/vendor-verifications"],
    enabled: !!adminUser,
  }) as { data: any[] };

  const { data: fraudAlerts = [] } = useQuery({
    queryKey: ["/api/admin/fraud-alerts"],
    enabled: !!adminUser,
  }) as { data: any[] };

  const { data: inventoryAlerts = [] } = useQuery({
    queryKey: ["/api/admin/inventory/alerts"],
    enabled: !!adminUser,
  }) as { data: any[] };

  const { data: analytics } = useQuery({
    queryKey: ["/api/admin/analytics"],
    enabled: !!adminUser,
  });

  const { data: siteSettings = [] } = useQuery({
    queryKey: ["/api/admin/site-settings"],
    enabled: !!adminUser,
  });

  const { data: deliveryZones = [] } = useQuery({
    queryKey: ["/api/delivery-zones"],
    enabled: !!adminUser,
  });

  const { data: deliveryPartners = [] } = useQuery({
    queryKey: ["/api/delivery-partners"],
    enabled: !!adminUser,
  }) as { data: any[] };

  // Settings form state
  const [settingsForm, setSettingsForm] = useState({
    siteName: "Siraha Bazaar",
    siteDescription: "Multi-vendor e-commerce platform",
    adminEmail: "sirahabazzar@gmail.com",
    contactPhone: "+9779805916598",
    commissionRate: "5",
    minOrder: "100",
    deliveryFee: "50",
    taxRate: "13",
    sessionTimeout: "30",
    emailNotifications: true,
    smsNotifications: true,
    orderAlerts: true,
    lowStockAlerts: true,
    twoFactorAuth: false,
    loginNotifications: true,
    fraudDetection: true,
  });

  // Mutations
  const updateOrderStatusMutation = useMutation({
    mutationFn: async ({ orderId, status }: { orderId: number; status: string }) => {
      return apiRequest(`/api/admin/orders/${orderId}/status`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status })
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/orders"] });
      toast({ title: "Order status updated successfully" });
    },
  });

  const createCouponMutation = useMutation({
    mutationFn: async (couponData: any) => {
      return apiRequest("/api/admin/coupons", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(couponData)
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/coupons"] });
      toast({ title: "Coupon created successfully" });
    },
  });

  const updateFraudAlertMutation = useMutation({
    mutationFn: async ({ alertId, status }: { alertId: number; status: string }) => {
      return apiRequest(`/api/admin/fraud-alerts/${alertId}/status`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status })
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/fraud-alerts"] });
      toast({ title: "Fraud alert updated successfully" });
    },
  });

  const approveVendorMutation = useMutation({
    mutationFn: async (verificationId: number) => {
      return apiRequest(`/api/admin/vendor-verifications/${verificationId}/approve`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser?.id })
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/vendor-verifications"] });
      toast({ title: "Vendor verification approved" });
    },
  });

  // User approval mutations
  const approveUserMutation = useMutation({
    mutationFn: async (userId: number) => {
      setProcessingApprovals(prev => new Set(prev).add(userId));
      return apiRequest(`/api/admin/users/${userId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser?.id })
      });
    },
    onSuccess: (_, userId) => {
      setTimeout(() => {
        setProcessingApprovals(prev => {
          const next = new Set(prev);
          next.delete(userId);
          return next;
        });
        queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
        toast({ title: "User approved successfully", description: "The user has been activated and can now access their account." });
      }, 1000);
    },
    onError: (_, userId) => {
      setProcessingApprovals(prev => {
        const next = new Set(prev);
        next.delete(userId);
        return next;
      });
    },
  });

  const rejectUserMutation = useMutation({
    mutationFn: async ({ userId, reason }: { userId: number; reason: string }) => {
      setProcessingRejections(prev => new Set(prev).add(userId));
      return apiRequest(`/api/admin/users/${userId}/reject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser?.id, reason })
      });
    },
    onSuccess: (_, { userId }) => {
      setTimeout(() => {
        setProcessingRejections(prev => {
          const next = new Set(prev);
          next.delete(userId);
          return next;
        });
        queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
        toast({ title: "User rejected successfully", description: "The application has been declined." });
      }, 1000);
    },
    onError: (_, { userId }) => {
      setProcessingRejections(prev => {
        const next = new Set(prev);
        next.delete(userId);
        return next;
      });
    },
  });

  // Delivery partner approval mutations
  const approvePartnerMutation = useMutation({
    mutationFn: async (partnerId: number) => {
      return apiRequest(`/api/delivery-partners/${partnerId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser?.id })
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-partners"] });
      toast({ title: "Delivery partner approved successfully" });
    },
  });

  const rejectPartnerMutation = useMutation({
    mutationFn: async ({ partnerId, reason }: { partnerId: number; reason: string }) => {
      return apiRequest(`/api/delivery-partners/${partnerId}/reject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser?.id, reason })
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-partners"] });
      toast({ title: "Delivery partner rejected successfully" });
    },
  });

  // Vendor management mutations
  const banVendorMutation = useMutation({
    mutationFn: async (storeId: number) => {
      return apiRequest(`/api/admin/stores/${storeId}/ban`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser?.id })
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/stores"] });
      toast({ title: "Vendor banned successfully" });
    },
  });

  const suspendVendorMutation = useMutation({
    mutationFn: async (storeId: number) => {
      return apiRequest(`/api/admin/stores/${storeId}/suspend`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser?.id })
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/stores"] });
      toast({ title: "Vendor suspended successfully" });
    },
  });

  const activateVendorMutation = useMutation({
    mutationFn: async (storeId: number) => {
      return apiRequest(`/api/admin/stores/${storeId}/activate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser?.id })
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/stores"] });
      toast({ title: "Vendor activated successfully" });
    },
  });

  // Delivery Zone Mutations
  const createZoneMutation = useMutation({
    mutationFn: async (zoneData: any) => {
      return apiRequest("/api/delivery-zones", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(zoneData)
      });
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
      toast({ title: "Delivery zone created successfully" });
    },
  });

  const updateZoneMutation = useMutation({
    mutationFn: async ({ id, data }: { id: number; data: any }) => {
      return apiRequest(`/api/delivery-zones/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-zones"] });
      setEditingZone(null);
      toast({ title: "Delivery zone updated successfully" });
    },
  });

  const deleteZoneMutation = useMutation({
    mutationFn: async (zoneId: number) => {
      return apiRequest(`/api/delivery-zones/${zoneId}`, {
        method: "DELETE"
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-zones"] });
      toast({ title: "Delivery zone deleted successfully" });
    },
  });

  const updateSettingMutation = useMutation({
    mutationFn: async ({ key, value }: { key: string; value: string }) => {
      return apiRequest(`/api/admin/site-settings/${key}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ value })
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/site-settings"] });
      toast({ title: "Setting updated successfully" });
    },
  });






  const handleSaveSettings = async () => {
    try {
      const settingsToUpdate = [
        { key: "site_name", value: settingsForm.siteName },
        { key: "site_description", value: settingsForm.siteDescription },
        { key: "admin_email", value: settingsForm.adminEmail },
        { key: "contact_phone", value: settingsForm.contactPhone },
        { key: "commission_rate", value: settingsForm.commissionRate },
        { key: "min_order", value: settingsForm.minOrder },
        { key: "delivery_fee", value: settingsForm.deliveryFee },
        { key: "tax_rate", value: settingsForm.taxRate },
        { key: "session_timeout", value: settingsForm.sessionTimeout },
        { key: "email_notifications", value: settingsForm.emailNotifications.toString() },
        { key: "sms_notifications", value: settingsForm.smsNotifications.toString() },
        { key: "order_alerts", value: settingsForm.orderAlerts.toString() },
        { key: "low_stock_alerts", value: settingsForm.lowStockAlerts.toString() },
        { key: "two_factor_auth", value: settingsForm.twoFactorAuth.toString() },
        { key: "login_notifications", value: settingsForm.loginNotifications.toString() },
        { key: "fraud_detection", value: settingsForm.fraudDetection.toString() },
      ];

      for (const setting of settingsToUpdate) {
        await updateSettingMutation.mutateAsync(setting);
      }

      toast({ title: "All settings saved successfully" });
    } catch (error) {
      toast({ 
        title: "Error saving settings", 
        description: "Some settings may not have been saved",
        variant: "destructive" 
      });
    }
  };

  const handleInputChange = (field: string, value: string | boolean) => {
    setSettingsForm(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleLogout = () => {
    localStorage.removeItem("adminUser");
    setLocation("/admin/login");
  };

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-NP', {
      style: 'currency',
      currency: 'NPR',
    }).format(amount);
  };

  const formatDate = (date: string) => {
    return new Date(date).toLocaleDateString('en-NP', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (!adminUser) {
    return <div>Loading...</div>;
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-primary" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Siraha Bazaar Admin</h1>
                <p className="text-sm text-muted-foreground">Comprehensive management dashboard</p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <span className="text-sm text-muted-foreground">Welcome, {adminUser.fullName}</span>
              <Button variant="outline" size="sm" onClick={handleLogout}>
                <LogOut className="h-4 w-4 mr-2" />
                Logout
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-14">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="approvals">Approvals</TabsTrigger>
            <TabsTrigger value="users">Users</TabsTrigger>
            <TabsTrigger value="orders">Orders</TabsTrigger>
            <TabsTrigger value="delivery-partners">🚴 Delivery</TabsTrigger>
            <TabsTrigger value="payments">Payments</TabsTrigger>
            <TabsTrigger value="vendors">Vendors</TabsTrigger>
            <TabsTrigger value="coupons">Coupons</TabsTrigger>
            <TabsTrigger value="delivery-zones">Delivery Zones</TabsTrigger>
            <TabsTrigger value="inventory">Inventory</TabsTrigger>
            <TabsTrigger value="analytics">Analytics</TabsTrigger>
            <TabsTrigger value="support">Support</TabsTrigger>
            <TabsTrigger value="security">Security</TabsTrigger>
            <TabsTrigger value="settings">Settings</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Total Users</p>
                      <p className="text-2xl font-bold">{dashboardStats?.totalUsers || 0}</p>
                    </div>
                    <Users className="h-8 w-8 text-blue-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Total Revenue</p>
                      <p className="text-2xl font-bold">{formatCurrency(dashboardStats?.totalRevenue || 0)}</p>
                    </div>
                    <DollarSign className="h-8 w-8 text-green-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Total Orders</p>
                      <p className="text-2xl font-bold">{dashboardStats?.totalOrders || 0}</p>
                    </div>
                    <ShoppingCart className="h-8 w-8 text-purple-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Active Stores</p>
                      <p className="text-2xl font-bold">{dashboardStats?.totalStores || 0}</p>
                    </div>
                    <Store className="h-8 w-8 text-orange-600" />
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Quick Actions */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <Card className="p-4 hover:shadow-md transition-shadow cursor-pointer" onClick={() => setActiveTab("orders")}>
                <div className="flex items-center">
                  <ShoppingCart className="h-6 w-6 text-purple-600" />
                  <div className="ml-3">
                    <p className="font-medium">Pending Orders</p>
                    <p className="text-sm text-gray-500">{dashboardStats?.pendingOrders || 0} orders awaiting processing</p>
                  </div>
                </div>
              </Card>

              <Card className="p-4 hover:shadow-md transition-shadow cursor-pointer" onClick={() => setActiveTab("delivery-partners")}>
                <div className="flex items-center">
                  <div className="h-6 w-6 text-green-600 flex items-center justify-center text-lg">🚴</div>
                  <div className="ml-3">
                    <p className="font-medium">Delivery Partners</p>
                    <p className="text-sm text-gray-500">{(allUsers.filter((u: any) => u.role === 'delivery_partner') || []).length} active partners</p>
                  </div>
                </div>
              </Card>

              <Card className="p-4 hover:shadow-md transition-shadow cursor-pointer" onClick={() => setActiveTab("vendors")}>
                <div className="flex items-center">
                  <UserCheck className="h-6 w-6 text-blue-600" />
                  <div className="ml-3">
                    <p className="font-medium">Vendor Approvals</p>
                    <p className="text-sm text-gray-500">{dashboardStats?.pendingVerifications || 0} pending verifications</p>
                  </div>
                </div>
              </Card>

              <Card className="p-4 hover:shadow-md transition-shadow cursor-pointer" onClick={() => setActiveTab("security")}>
                <div className="flex items-center">
                  <Shield className="h-6 w-6 text-red-600" />
                  <div className="ml-3">
                    <p className="font-medium">Security Alerts</p>
                    <p className="text-sm text-gray-500">{dashboardStats?.fraudAlerts || 0} active alerts</p>
                  </div>
                </div>
              </Card>
            </div>
          </TabsContent>

          {/* Approvals Tab */}
          <TabsContent value="approvals" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">User Approvals</h2>
              <Badge variant="secondary" className="text-sm">
                {allUsers.filter((user: any) => user.status === 'pending').length} pending approvals
              </Badge>
            </div>

            <Tabs defaultValue="shopkeepers" className="w-full">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="shopkeepers">Pending Shopkeepers</TabsTrigger>
                <TabsTrigger value="delivery-partners">Pending Delivery Partners</TabsTrigger>
              </TabsList>

              <TabsContent value="shopkeepers" className="space-y-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Store className="h-5 w-5" />
                      Shopkeeper Applications
                    </CardTitle>
                    <CardDescription>
                      Review and approve shopkeeper account applications
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {allUsers
                        .filter((user: any) => user.role === 'shopkeeper' && user.status === 'pending')
                        .map((user: any) => (
                          <Card key={user.id} className="border-l-4 border-l-yellow-400">
                            <CardContent className="p-4">
                              <div className="flex items-center justify-between">
                                <div className="space-y-2">
                                  <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                                      <Users className="h-5 w-5 text-blue-600" />
                                    </div>
                                    <div>
                                      <h4 className="font-semibold">{user.fullName}</h4>
                                      <p className="text-sm text-muted-foreground">{user.email}</p>
                                    </div>
                                  </div>
                                  <div className="grid grid-cols-2 gap-4 text-sm">
                                    <div>
                                      <span className="font-medium">Phone:</span> {user.phone || 'Not provided'}
                                    </div>
                                    <div>
                                      <span className="font-medium">City:</span> {user.city || 'Not provided'}
                                    </div>
                                    <div>
                                      <span className="font-medium">Applied:</span> {formatDate(user.createdAt)}
                                    </div>
                                    <div>
                                      <span className="font-medium">Status:</span> 
                                      <Badge variant="secondary" className="ml-1">Pending</Badge>
                                    </div>
                                  </div>
                                </div>
                                <div className="flex flex-col gap-2">
                                  <motion.div
                                    whileHover={{ scale: 1.02 }}
                                    whileTap={{ scale: 0.98 }}
                                  >
                                    <Button
                                      size="sm"
                                      onClick={() => approveUserMutation.mutate(user.id)}
                                      disabled={processingApprovals.has(user.id) || processingRejections.has(user.id)}
                                      className={`${
                                        processingApprovals.has(user.id) 
                                          ? "bg-green-500 text-white" 
                                          : "bg-green-600 hover:bg-green-700"
                                      } transition-all duration-300`}
                                    >
                                      <AnimatePresence mode="wait">
                                        {processingApprovals.has(user.id) ? (
                                          <motion.div
                                            key="approved"
                                            initial={{ opacity: 0, scale: 0.5 }}
                                            animate={{ opacity: 1, scale: 1 }}
                                            exit={{ opacity: 0, scale: 0.5 }}
                                            className="flex items-center"
                                          >
                                            <CheckCircle className="h-4 w-4 mr-1" />
                                            Approved!
                                          </motion.div>
                                        ) : (
                                          <motion.div
                                            key="approve"
                                            initial={{ opacity: 0 }}
                                            animate={{ opacity: 1 }}
                                            exit={{ opacity: 0 }}
                                            className="flex items-center"
                                          >
                                            <CheckCircle className="h-4 w-4 mr-1" />
                                            Approve
                                          </motion.div>
                                        )}
                                      </AnimatePresence>
                                    </Button>
                                  </motion.div>

                                  <motion.div
                                    whileHover={{ scale: 1.02 }}
                                    whileTap={{ scale: 0.98 }}
                                  >
                                    <Button
                                      size="sm"
                                      variant="destructive"
                                      onClick={() => rejectUserMutation.mutate({ 
                                        userId: user.id, 
                                        reason: "Application review incomplete" 
                                      })}
                                      disabled={processingApprovals.has(user.id) || processingRejections.has(user.id)}
                                      className={`${
                                        processingRejections.has(user.id) 
                                          ? "bg-red-500 text-white" 
                                          : ""
                                      } transition-all duration-300`}
                                    >
                                      <AnimatePresence mode="wait">
                                        {processingRejections.has(user.id) ? (
                                          <motion.div
                                            key="rejected"
                                            initial={{ opacity: 0, scale: 0.5 }}
                                            animate={{ opacity: 1, scale: 1 }}
                                            exit={{ opacity: 0, scale: 0.5 }}
                                            className="flex items-center"
                                          >
                                            <XCircle className="h-4 w-4 mr-1" />
                                            Rejected!
                                          </motion.div>
                                        ) : (
                                          <motion.div
                                            key="reject"
                                            initial={{ opacity: 0 }}
                                            animate={{ opacity: 1 }}
                                            exit={{ opacity: 0 }}
                                            className="flex items-center"
                                          >
                                            <XCircle className="h-4 w-4 mr-1" />
                                            Reject
                                          </motion.div>
                                        )}
                                      </AnimatePresence>
                                    </Button>
                                  </motion.div>
                                </div>
                              </div>
                            </CardContent>
                          </Card>
                        ))}

                      {allUsers.filter((user: any) => user.role === 'shopkeeper' && user.status === 'pending').length === 0 && (
                        <div className="text-center py-8 text-muted-foreground">
                          <Store className="h-12 w-12 mx-auto mb-4 opacity-50" />
                          <p>No pending shopkeeper applications</p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="delivery-partners" className="space-y-4">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Truck className="h-5 w-5" />
                      Delivery Partner Applications
                    </CardTitle>
                    <CardDescription>
                      Review and approve delivery partner account applications
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {(deliveryPartners as any[])
                        .filter((partner: any) => partner.status === 'pending')
                        .map((partner: any) => (
                          <Card key={partner.id} className="border-l-4 border-l-blue-400">
                            <CardContent className="p-4">
                              <div className="flex items-center justify-between">
                                <div className="space-y-2">
                                  <div className="flex items-center gap-3">
                                    <div className="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center">
                                      <Truck className="h-5 w-5 text-green-600" />
                                    </div>
                                    <div>
                                      ```text

                                      <h4 className="font-semibold">Delivery Partner #{partner.id}</h4>
                                      <p className="text-sm text-muted-foreground">User ID: {partner.userId}</p>
                                    </div>
                                  </div>
                                  <div className="grid grid-cols-2 gap-4 text-sm">
                                    <div>
                                      <span className="font-medium">Vehicle:</span> {partner.vehicleType} - {partner.vehicleNumber}
                                    </div>
                                    <div>
                                      <span className="font-medium">License:</span> {partner.drivingLicense}
                                    </div>
                                    <div>
                                      <span className="font-medium">ID Proof:</span> {partner.idProofType} - {partner.idProofNumber}
                                    </div>
                                    <div>
                                      <span className="font-medium">Areas:</span> {partner.deliveryAreas?.join(', ') || 'Not specified'}
                                    </div>
                                    <div>
                                      <span className="font-medium">Emergency Contact:</span> {partner.emergencyContact}
                                    </div>
                                    <div>
                                      <span className="font-medium">Applied:</span> {formatDate(partner.createdAt)}
                                    </div>
                                  </div>
                                </div>
                                <div className="flex flex-col gap-2">
                                  <Button
                                    size="sm"
                                    onClick={() => approvePartnerMutation.mutate(partner.id)}
                                    disabled={approvePartnerMutation.isPending}
                                    className="bg-green-600 hover:bg-green-700"
                                  >
                                    <CheckCircle className="h-4 w-4 mr-1" />
                                    Approve
                                  </Button>
                                  <Button
                                    size="sm"
                                    variant="destructive"
                                    onClick={() => rejectPartnerMutation.mutate({ 
                                      partnerId: partner.id, 
                                      reason: "Application review incomplete" 
                                    })}
                                    disabled={rejectPartnerMutation.isPending}
                                  >
                                    <XCircle className="h-4 w-4 mr-1" />
                                    Reject
                                  </Button>
                                </div>
                              </div>
                            </CardContent>
                          </Card>
                        ))}

                      {(deliveryPartners as any[]).filter((partner: any) => partner.status === 'pending').length === 0 && (
                        <div className="text-center py-8 text-muted-foreground">
                          <Truck className="h-12 w-12 mx-auto mb-4 opacity-50" />
                          <p>No pending delivery partner applications</p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </TabsContent>

          {/* Users Tab */}
          <TabsContent value="users" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">User Management</h2>
              <div className="flex space-x-2">
                <Input 
                  placeholder="Search users..." 
                  className="w-64"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
                <Select value={filterStatus} onValueChange={setFilterStatus}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Filter by role" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Users</SelectItem>
                    <SelectItem value="customer">Customers</SelectItem>
                    <SelectItem value="shopkeeper">Shopkeepers</SelectItem>
                    <SelectItem value="delivery_partner">Delivery Partners</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Total Users</p>
                      <p className="text-2xl font-bold">{allUsers.length}</p>
                    </div>
                    <Users className="h-8 w-8 text-blue-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Customers</p>
                      <p className="text-2xl font-bold">
                        {allUsers.filter((u: any) => u.role === 'customer').length}
                      </p>
                    </div>
                    <UserCheck className="h-8 w-8 text-green-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Shopkeepers</p>
                      <p className="text-2xl font-bold">
                        {allUsers.filter((u: any) => u.role === 'shopkeeper').length}
                      </p>
                    </div>
                    <Store className="h-8 w-8 text-orange-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Pending Approvals</p>
                      <p className="text-2xl font-bold">
                        {allUsers.filter((u: any) => u.status === 'pending').length}
                      </p>
                    </div>
                    <Clock className="h-8 w-8 text-yellow-600" />
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>User</TableHead>
                      <TableHead>Email</TableHead>
                      <TableHead>Role</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Phone</TableHead>
                      <TableHead>Location</TableHead>
                      <TableHead>Joined</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {allUsers
                      .filter((user: any) => 
                        (filterStatus === "all" || user.role === filterStatus) &&
                        (searchTerm === "" || 
                         user.fullName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.username?.toLowerCase().includes(searchTerm.toLowerCase()))
                      )
                      .map((user: any) => (
                        <TableRow key={user.id}>
                          <TableCell>
                            <div className="flex items-center gap-3">
                              <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                                <Users className="h-4 w-4 text-blue-600" />
                              </div>
                              <div>
                                <p className="font-medium">{user.fullName}</p>
                                <p className="text-sm text-muted-foreground">@{user.username}</p>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>{user.email}</TableCell>
                          <TableCell>
                            <Badge 
                              variant={
                                user.role === 'customer' ? 'default' :
                                user.role === 'shopkeeper' ? 'secondary' :
                                user.role === 'delivery_partner' ? 'outline' : 'default'
                              }
                            >
                              {user.role}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge 
                              variant={
                                user.status === 'active' ? 'default' :
                                user.status === 'pending' ? 'secondary' :
                                user.status === 'suspended' ? 'destructive' : 'outline'
                              }
                            >
                              {user.status}
                            </Badge>
                          </TableCell>
                          <TableCell>{user.phone || 'N/A'}</TableCell>
                          <TableCell>{user.city || 'N/A'}</TableCell>
                          <TableCell>{formatDate(user.createdAt)}</TableCell>
                          <TableCell>
                            <div className="flex space-x-1">
                              <Button size="sm" variant="outline">
                                <Eye className="h-4 w-4" />
                              </Button>
                              {user.status === 'pending' && (
                                <>
                                  <Button
                                    size="sm"
                                    onClick={() => approveUserMutation.mutate(user.id)}
                                    disabled={approveUserMutation.isPending}
                                    className="bg-green-600 hover:bg-green-700"
                                  >
                                    <CheckCircle className="h-4 w-4" />
                                  </Button>
                                  <Button
                                    size="sm"
                                    variant="destructive"
                                    onClick={() => rejectUserMutation.mutate({ 
                                      userId: user.id, 
                                      reason: "Admin review" 
                                    })}
                                  >
                                    <XCircle className="h-4 w-4" />
                                  </Button>
                                </>
                              )}
                              {user.status === 'active' && user.role !== 'customer' && (
                                <Button size="sm" variant="outline">
                                  <Ban className="h-4 w-4" />
                                </Button>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Orders Tab */}
          <TabsContent value="orders" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Order Management</h2>
              <div className="flex space-x-2">
                <Input 
                  placeholder="Search orders..." 
                  className="w-64"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
                <Select value={filterStatus} onValueChange={setFilterStatus}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Filter by status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Orders</SelectItem>
                    <SelectItem value="pending">Pending</SelectItem>
                    <SelectItem value="processing">Processing</SelectItem>
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
                      <TableHead>Total Amount</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Date</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {allOrders
                      .filter((order: any) => 
                        (filterStatus === "all" || order.status === filterStatus) &&
                        (searchTerm === "" || 
                         order.id.toString().includes(searchTerm) ||
                         order.customerName.toLowerCase().includes(searchTerm.toLowerCase()))
                      )
                      .map((order: any) => (
                        <TableRow key={order.id}>
                          <TableCell className="font-medium">#{order.id}</TableCell>
                          <TableCell>{order.customerName}</TableCell>
                          <TableCell>{formatCurrency(parseFloat(order.totalAmount))}</TableCell>
                          <TableCell>
                            <Badge 
                              variant={
                                order.status === 'delivered' ? 'default' :
                                order.status === 'cancelled' ? 'destructive' :
                                order.status === 'shipped' ? 'secondary' : 'outline'
                              }
                            >
                              {order.status}
                            </Badge>
                          </TableCell>
                          <TableCell>{formatDate(order.createdAt)}</TableCell>
                          <TableCell>
                            <Select 
                              value={order.status}
                              onValueChange={(status) => 
                                updateOrderStatusMutation.mutate({ orderId: order.id, status })
                              }
                            >
                              <SelectTrigger className="w-32">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="pending">Pending</SelectItem>
                                <SelectItem value="processing">Processing</SelectItem>
                                <SelectItem value="shipped">Shipped</SelectItem>
                                <SelectItem value="delivered">Delivered</SelectItem>
                                <SelectItem value="cancelled">Cancelled</SelectItem>
                              </SelectContent>
                            </Select>
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Payments Tab */}
          <TabsContent value="payments" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Payment Management</h2>
              <Button>
                <Download className="h-4 w-4 mr-2" />
                Export Report
              </Button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Total Transactions</p>
                      <p className="text-2xl font-bold">{transactions.length}</p>
                    </div>
                    <CreditCard className="h-8 w-8 text-blue-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Successful Payments</p>
                      <p className="text-2xl font-bold">
                        {transactions.filter((t: any) => t.status === 'completed').length}
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
                      <p className="text-sm font-medium text-muted-foreground">Failed Payments</p>
                      <p className="text-2xl font-bold">
                        {transactions.filter((t: any) => t.status === 'failed').length}
                      </p>
                    </div>
                    <XCircle className="h-8 w-8 text-red-600" />
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Transaction ID</TableHead>
                      <TableHead>Order ID</TableHead>
                      <TableHead>Amount</TableHead>
                      <TableHead>Payment Method</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Date</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {transactions.map((transaction: any) => (
                      <TableRow key={transaction.id}>
                        <TableCell className="font-medium">{transaction.transactionId}</TableCell>
                        <TableCell>#{transaction.orderId}</TableCell>
                        <TableCell>{formatCurrency(parseFloat(transaction.amount))}</TableCell>
                        <TableCell>{transaction.paymentMethod}</TableCell>
                        <TableCell>
                          <Badge 
                            variant={
                              transaction.status === 'completed' ? 'default' :
                              transaction.status === 'failed' ? 'destructive' : 'outline'
                            }
                          >
                            {transaction.status}
                          </Badge>
                        </TableCell>
                        <TableCell>{formatDate(transaction.createdAt)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Vendors Tab */}
          <TabsContent value="vendors" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Vendor Management</h2>
              <div className="flex space-x-2">
                <Input placeholder="Search vendors..." className="w-64" />
                <Button variant="outline">
                  <Filter className="h-4 w-4 mr-2" />
                  Filter
                </Button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Pending Verifications</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {vendorVerifications
                    .filter((v: any) => v.status === 'pending')
                    .map((verification: any) => (
                      <div key={verification.id} className="flex items-center justify-between p-4 border rounded-lg">
                        <div>
                          <p className="font-medium">Store ID: {verification.storeId}</p>
                          <p className="text-sm text-muted-foreground">{verification.documentType}</p>
                        </div>
                        <div className="flex space-x-2">
                          <Button 
                            size="sm" 
                            onClick={() => approveVendorMutation.mutate(verification.id)}
                          >
                            <CheckCircle className="h-4 w-4 mr-1" />
                            Approve
                          </Button>
                          <Button size="sm" variant="outline">
                            <XCircle className="h-4 w-4 mr-1" />
                            Reject
                          </Button>
                        </div>
                      </div>
                    ))}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Active Vendors</CardTitle>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Store Name</TableHead>
                        <TableHead>Owner</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Revenue</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {allStores.map((store: any) => (
                        <TableRow key={store.id}>
                          <TableCell>
                            <div className="flex items-center gap-3">
                              <div className="w-8 h-8 bg-orange-100 rounded-full flex items-center justify-center">
                                <Store className="h-4 w-4 text-orange-600" />
                              </div>
                              <div>
                                <p className="font-medium">{store.name}</p>
                                <p className="text-sm text-muted-foreground">{store.slug}</p>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>{store.ownerName || 'N/A'}</TableCell>
                          <TableCell>
                            <Badge variant="outline">
                              {store.storeType === 'restaurant' ? 'Restaurant' : 'Retail'}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <span className="font-medium text-green-600">
                              ${(Math.random() * 5000).toFixed(2)}
                            </span>
                          </TableCell>
                          <TableCell>
                            <Badge variant={
                              store.isActive ? 'default' : 
                              store.status === 'suspended' ? 'secondary' :
                              store.status === 'banned' ? 'destructive' : 'outline'
                            }>
                              {store.isActive ? 'Active' : store.status || 'Inactive'}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <div className="flex space-x-1">
                              <Button size="sm" variant="outline" title="View Details">
                                <Eye className="h-4 w-4" />
                              </Button>
                              <Button size="sm" variant="outline" title="Edit Store">
                                <Edit className="h-4 w-4" />
                              </Button>
                              {store.isActive && (
                                <>
                                  <Button 
                                    size="sm" 
                                    variant="secondary"
                                    onClick={() => suspendVendorMutation.mutate(store.id)}
                                    disabled={suspendVendorMutation.isPending}
                                    title="Suspend Vendor"
                                  >
                                    <Clock className="h-4 w-4" />
                                  </Button>
                                  <Button 
                                    size="sm" 
                                    variant="destructive"
                                    onClick={() => banVendorMutation.mutate(store.id)}
                                    disabled={banVendorMutation.isPending}
                                    title="Ban Vendor"
                                  >
                                    <Ban className="h-4 w-4" />
                                  </Button>
                                </>
                              )}
                              {!store.isActive && (
                                <Button 
                                  size="sm" 
                                  className="bg-green-600 hover:bg-green-700"
                                  onClick={() => activateVendorMutation.mutate(store.id)}
                                  disabled={activateVendorMutation.isPending}
                                  title="Activate Vendor"
                                >
                                  <CheckCircle className="h-4 w-4" />
                                </Button>
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
          </TabsContent>

          {/* Coupons Tab */}
          <TabsContent value="coupons" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Coupon Management</h2>
              <Dialog>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="h-4 w-4 mr-2" />
                    Create Coupon
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Create New Coupon</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="coupon-code">Coupon Code</Label>
                      <Input id="coupon-code" placeholder="Enter coupon code" />
                    </div>
                    <div>
                      <Label htmlFor="coupon-title">Title</Label>
                      <Input id="coupon-title" placeholder="Enter coupon title" />
                    </div>
                    <div>
                      <Label htmlFor="discount-value">Discount Value</Label>
                      <Input id="discount-value" type="number" placeholder="Enter discount amount" />
                    </div>
                    <div>
                      <Label htmlFor="discount-type">Discount Type</Label>
                      <Select>
                        <SelectTrigger>
                          <SelectValue placeholder="Select discount type" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="percentage">Percentage</SelectItem>
                          <SelectItem value="fixed">Fixed Amount</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <Button className="w-full">Create Coupon</Button>
                  </div>
                </DialogContent>
              </Dialog>
            </div>

            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Code</TableHead>
                      <TableHead>Title</TableHead>
                      <TableHead>Discount</TableHead>
                      <TableHead>Used/Limit</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Expires</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {coupons.map((coupon: any) => (
                      <TableRow key={coupon.id}>
                        <TableCell className="font-medium">{coupon.code}</TableCell>
                        <TableCell>{coupon.title}</TableCell>
                        <TableCell>
                          {coupon.discountType === 'percentage' 
                            ? `${coupon.discountValue}%` 
                            : formatCurrency(parseFloat(coupon.discountValue))
                          }
                        </TableCell>
                        <TableCell>{coupon.usedCount}/{coupon.usageLimit || '∞'}</TableCell>
                        <TableCell>
                          <Badge variant={coupon.isActive ? 'default' : 'destructive'}>
                            {coupon.isActive ? 'Active' : 'Inactive'}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {coupon.expiresAt ? formatDate(coupon.expiresAt) : 'Never'}
                        </TableCell>
                        <TableCell>
                          <div className="flex space-x-2">
                            <Button size="sm" variant="outline">
                              <Edit className="h-4 w-4" />
                            </Button>
                            <Button size="sm" variant="outline">
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
          </TabsContent>

          {/* Delivery Zones Management */}
          <TabsContent value="delivery-zones" className="space-y-6">
            <Card>
              <CardHeader>
                <div className="flex justify-between items-center">
                  <CardTitle className="flex items-center gap-2">
                    <MapPin className="h-5 w-5" />
                    Delivery Zone Management
                  </CardTitle>
                  <Dialog open={showCreateZone} onOpenChange={setShowCreateZone}>
                    <DialogTrigger asChild>
                      <Button>
                        <Plus className="h-4 w-4 mr-2" />
                        Add Zone
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>Create New Delivery Zone</DialogTitle>
                      </DialogHeader>
                      <div className="grid gap-4 py-4">
                        <div className="grid grid-cols-4 items-center gap-4">
                          <Label htmlFor="name" className="text-right">Name</Label>
                          <Input
                            id="name"
                            value={newZone.name}
                            onChange={(e) => setNewZone({ ...newZone, name: e.target.value })}
                            className="col-span-3"
                            placeholder="e.g., Inner City"
                          />
                        </div>
                        <div className="grid grid-cols-4 items-center gap-4">
                          <Label htmlFor="minDistance" className="text-right">Min Distance (km)</Label>
                          <Input
                            id="minDistance"
                            type="number"
                            step="0.01"
                            value={newZone.minDistance}
                            onChange={(e) => setNewZone({ ...newZone, minDistance: e.target.value })}
                            className="col-span-3"
                            placeholder="0"
                          />
                        </div>
                        <div className="grid grid-cols-4 items-center gap-4">
                          <Label htmlFor="maxDistance" className="text-right">Max Distance (km)</Label>
                          <Input
                            id="maxDistance"
                            type="number"
                            step="0.01"
                            value={newZone.maxDistance}
                            onChange={(e) => setNewZone({ ...newZone, maxDistance: e.target.value })}
                            className="col-span-3"
                            placeholder="5"
                          />
                        </div>
                        <div className="grid grid-cols-4 items-center gap-4">
                          <Label htmlFor="baseFee" className="text-right">Base Fee (Rs.)</Label>
                          <Input
                            id="baseFee"
                            type="number"
                            step="0.01"
                            value={newZone.baseFee}
                            onChange={(e) => setNewZone({ ...newZone, baseFee: e.target.value })}
                            className="col-span-3"
                            placeholder="30.00"
                          />
                        </div>
                        <div className="grid grid-cols-4 items-center gap-4">
                          <Label htmlFor="perKmRate" className="text-right">Per km Rate (Rs.)</Label>
                          <Input
                            id="perKmRate"
                            type="number"
                            step="0.01"
                            value={newZone.perKmRate}
                            onChange={(e) => setNewZone({ ...newZone, perKmRate: e.target.value })}
                            className="col-span-3"
                            placeholder="5.00"
                          />
                        </div>
                      </div>
                      <div className="flex justify-end space-x-2">
                        <Button variant="outline" onClick={() => setShowCreateZone(false)}>
                          Cancel
                        </Button>
                        <Button 
                          onClick={() => createZoneMutation.mutate(newZone)}
                          disabled={createZoneMutation.isPending}
                        >
                          Create Zone
                        </Button>
                      </div>
                    </DialogContent>
                  </Dialog>
                </div>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Zone Name</TableHead>
                      <TableHead>Distance Range</TableHead>
                      <TableHead>Base Fee</TableHead>
                      <TableHead>Per Km Rate</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Sample Fee (10km)</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(deliveryZones as any[]).map((zone) => (
                      <TableRow key={zone.id}>
                        <TableCell className="font-medium">{zone.name}</TableCell>
                        <TableCell>{zone.minDistance} - {zone.maxDistance} km</TableCell>
                        <TableCell>Rs. {zone.baseFee}</TableCell>
                        <TableCell>Rs. {zone.perKmRate}/km</TableCell>
                        <TableCell>
                          {zone.isActive ? (
                            <Badge variant="default" className="bg-green-100 text-green-800">
                              <CheckCircle className="h-3 w-3 mr-1" />Active
                            </Badge>
                          ) : (
                            <Badge variant="secondary">Inactive</Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          Rs. {(parseFloat(zone.baseFee) + (10 * parseFloat(zone.perKmRate))).toFixed(2)}
                        </TableCell>
                        <TableCell>
                          <div className="flex space-x-2">
                            <Dialog>
                              <DialogTrigger asChild>
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => setEditingZone({ ...zone })}
                                >
                                  <Edit className="h-4 w-4 mr-1" />
                                  Edit
                                </Button>
                              </DialogTrigger>
                              <DialogContent>
                                <DialogHeader>
                                  <DialogTitle>Edit Delivery Zone</DialogTitle>
                                </DialogHeader>
                                {editingZone && (
                                  <div className="grid gap-4 py-4">
                                    <div className="grid grid-cols-4 items-center gap-4">
                                      <Label htmlFor="edit-name" className="text-right">Name</Label>
                                      <Input
                                        id="edit-name"
                                        value={editingZone.name}
                                        onChange={(e) => setEditingZone({ ...editingZone, name: e.target.value })}
                                        className="col-span-3"
                                      />
                                    </div>
                                    <div className="grid grid-cols-4 items-center gap-4">
                                      <Label htmlFor="edit-minDistance" className="text-right">Min Distance (km)</Label>
                                      <Input
                                        id="edit-minDistance"
                                        type="number"
                                        step="0.01"
                                        value={editingZone.minDistance}
                                        onChange={(e) => setEditingZone({ ...editingZone, minDistance: e.target.value })}
                                        className="col-span-3"
                                      />
                                    </div>
                                    <div className="grid grid-cols-4 items-center gap-4">
                                      <Label htmlFor="edit-maxDistance" className="text-right">Max Distance (km)</Label>
                                      <Input
                                        id="edit-maxDistance"
                                        type="number"
                                        step="0.01"
                                        value={editingZone.maxDistance}
                                        onChange={(e) => setEditingZone({ ...editingZone, maxDistance: e.target.value })}
                                        className="col-span-3"
                                      />
                                    </div>
                                    <div className="grid grid-cols-4 items-center gap-4">
                                      <Label htmlFor="edit-baseFee" className="text-right">Base Fee (Rs.)</Label>
                                      <Input
                                        id="edit-baseFee"
                                        type="number"
                                        step="0.01"
                                        value={editingZone.baseFee}
                                        onChange={(e) => setEditingZone({ ...editingZone, baseFee: e.target.value })}
                                        className="col-span-3"
                                      />
                                    </div>
                                    <div className="grid grid-cols-4 items-center gap-4">
                                      <Label htmlFor="edit-perKmRate" className="text-right">Per km Rate (Rs.)</Label>
                                      <Input
                                        id="edit-perKmRate"
                                        type="number"
                                        step="0.01"
                                        value={editingZone.perKmRate}
                                        onChange={(e) => setEditingZone({ ...editingZone, perKmRate: e.target.value })}
                                        className="col-span-3"
                                      />
                                    </div>
                                  </div>
                                )}
                                <div className="flex justify-end space-x-2">
                                  <Button variant="outline" onClick={() => setEditingZone(null)}>
                                    Cancel
                                  </Button>
                                  <Button 
                                    onClick={() => updateZoneMutation.mutate({ 
                                      id: editingZone.id, 
                                      data: editingZone 
                                    })}
                                    disabled={updateZoneMutation.isPending}
                                  >
                                    Update Zone
                                  </Button>
                                </div>
                              </DialogContent>
                            </Dialog>
                            <Button
                              size="sm"
                              variant="destructive"
                              onClick={() => deleteZoneMutation.mutate(zone.id)}
                              disabled={deleteZoneMutation.isPending}
                            >
                              <Trash2 className="h-4 w-4 mr-1" />
                              Delete
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>

                {/* Delivery Fee Preview */}
                <div className="mt-6 p-4 bg-blue-50 rounded-lg">
                  <h3 className="font-semibold mb-3">Delivery Fee Calculator Preview</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {(deliveryZones as any[]).filter(zone => zone.isActive).map((zone) => (
                      <div key={zone.id} className="bg-white p-3 rounded border">
                        <h4 className="font-medium text-sm">{zone.name}</h4>
                        <p className="text-xs text-gray-600">{zone.minDistance}-{zone.maxDistance}km</p>
                        <div className="mt-2 space-y-1 text-xs">
                          <div>5km: Rs. {(parseFloat(zone.baseFee) + (5 * parseFloat(zone.perKmRate))).toFixed(2)}</div>
                          <div>10km: Rs. {(parseFloat(zone.baseFee) + (10 * parseFloat(zone.perKmRate))).toFixed(2)}</div>
                          <div>15km: Rs. {(parseFloat(zone.baseFee) + (15 * parseFloat(zone.perKmRate))).toFixed(2)}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Inventory Tab */}
          <TabsContent value="inventory" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Inventory Management</h2>
              <div className="flex space-x-2">
                <Button variant="outline">
                  <Download className="h-4 w-4 mr-2" />
                  Export
                </Button>
                <Button>
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Refresh
                </Button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Low Stock Items</p>
                      <p className="text-2xl font-bold text-red-600">{inventoryAlerts.length}</p>
                    </div>
                    <AlertTriangle className="h-8 w-8 text-red-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Total Products</p>
                      <p className="text-2xl font-bold">{allProducts.length}</p>
                    </div>
                    <Package className="h-8 w-8 text-blue-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Out of Stock</p>
                      <p className="text-2xl font-bold">
                        {allProducts.filter((p: any) => (p.stock || 0) === 0).length}
                      </p>
                    </div>
                    <XCircle className="h-8 w-8 text-orange-600" />
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Low Stock Alerts</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Product</TableHead>
                      <TableHead>Store</TableHead>
                      <TableHead>Current Stock</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {allProducts
                      .filter((product: any) => (product.stock || 0) <= 10)
                      .map((product: any) => (
                        <TableRow key={product.id}>
                          <TableCell className="font-medium">{product.name}</TableCell>
                          <TableCell>{product.storeName || 'N/A'}</TableCell>
                          <TableCell>
                            <span className={`font-medium ${(product.stock || 0) === 0 ? 'text-red-600' : 'text-orange-600'}`}>
                              {product.stock || 0}
                            </span>
                          </TableCell>
                          <TableCell>
                            <Badge variant={(product.stock || 0) === 0 ? 'destructive' : 'secondary'}>
                              {(product.stock || 0) === 0 ? 'Out of Stock' : 'Low Stock'}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Button size="sm" variant="outline">
                              <Bell className="h-4 w-4 mr-1" />
                              Notify Store
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Analytics Tab */}
          <TabsContent value="analytics" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Analytics & Reports</h2>
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
                <Button>
                  <Download className="h-4 w-4 mr-2" />
                  Export Report
                </Button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Revenue Growth</p>
                      <p className="text-2xl font-bold text-green-600">+12.5%</p>
                    </div>
                    <TrendingUp className="h-8 w-8 text-green-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">New Customers</p>
                      <p className="text-2xl font-bold">
                        {allUsers.filter((u: any) => u.role === 'customer').length}
                      </p>
                    </div>
                    <Users className="h-8 w-8 text-blue-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Conversion Rate</p>
                      <p className="text-2xl font-bold">3.2%</p>
                    </div>
                    <BarChart3 className="h-8 w-8 text-purple-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Avg Order Value</p>
                      <p className="text-2xl font-bold">{formatCurrency(1250)}</p>
                    </div>
                    <DollarSign className="h-8 w-8 text-orange-600" />
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Analytics Charts Placeholder */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Revenue Trend</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="h-64 flex items-center justify-center bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <p className="text-muted-foreground">Revenue chart would be displayed here</p>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Top Products</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {allProducts.slice(0, 5).map((product: any, index: number) => (
                      <div key={product.id} className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <span className="text-sm font-medium text-muted-foreground">#{index + 1}</span>
                          <span className="font-medium">{product.name}</span>
                        </div>
                        <span className="text-sm text-muted-foreground">{product.totalReviews || 0} reviews</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Support Tab */}
          <TabsContent value="support" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Support Management</h2>
              <div className="flex space-x-2">
                <Select defaultValue="all">
                  <SelectTrigger className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Tickets</SelectItem>
                    <SelectItem value="open">Open</SelectItem>
                    <SelectItem value="in_progress">In Progress</SelectItem>
                    <SelectItem value="resolved">Resolved</SelectItem>
                  </SelectContent>
                </Select>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  New Ticket
                </Button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Open Tickets</p>
                      <p className="text-2xl font-bold">
                        {supportTickets.filter((t: any) => t.status === 'open').length}
                      </p>
                    </div>
                    <MessageSquare className="h-8 w-8 text-blue-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">In Progress</p>
                      <p className="text-2xl font-bold">
                        {supportTickets.filter((t: any) => t.status === 'in_progress').length}
                      </p>
                    </div>
                    <Clock className="h-8 w-8 text-orange-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Resolved</p>
                      <p className="text-2xl font-bold">
                        {supportTickets.filter((t: any) => t.status === 'resolved').length}
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
                      <p className="text-sm font-medium text-muted-foreground">Avg Response</p>
                      <p className="text-2xl font-bold">2.4h</p>
                    </div>
                    <Calendar className="h-8 w-8 text-purple-600" />
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Ticket ID</TableHead>
                      <TableHead>Subject</TableHead>
                      <TableHead>Customer</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {supportTickets.map((ticket: any) => (
                      <TableRow key={ticket.id}>
                        <TableCell className="font-medium">#{ticket.id}</TableCell>
                        <TableCell>{ticket.subject}</TableCell>
                        <TableCell>{ticket.customerName || 'Anonymous'}</TableCell>
                        <TableCell>
                          <Badge 
                            variant={
                              ticket.priority === 'urgent' ? 'destructive' :
                              ticket.priority === 'high' ? 'secondary' : 'outline'
                            }
                          >
                            {ticket.priority}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge 
                            variant={
                              ticket.status === 'resolved' ? 'default' :
                              ticket.status === 'in_progress' ? 'secondary' : 'outline'
                            }
                          >
                            {ticket.status}
                          </Badge>
                        </TableCell>
                        <TableCell>{formatDate(ticket.createdAt)}</TableCell>
                        <TableCell>
                          <div className="flex space-x-2">
                            <Button size="sm" variant="outline">
                              <Eye className="h-4 w-4" />
                            </Button>
                            <Button size="sm" variant="outline">
                              <MessageSquare className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Security Tab */}
          <TabsContent value="security" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">Security & Fraud Detection</h2>
              <Button>
                <Shield className="h-4 w-4 mr-2" />
                Run Security Scan
              </Button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Active Alerts</p>
                      <p className="text-2xl font-bold text-red-600">{fraudAlerts.length}</p>
                    </div>
                    <AlertTriangle className="h-8 w-8 text-red-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Blocked Users</p>
                      <p className="text-2xl font-bold">
                        {allUsers.filter((u: any) => u.status === 'suspended').length}
                      </p>
                    </div>
                    <Ban className="h-8 w-8 text-orange-600" />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-muted-foreground">Security Score</p>
                      <p className="text-2xl font-bold text-green-600">94%</p>
                    </div>
                    <Shield className="h-8 w-8 text-green-600" />
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Fraud Alerts</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Alert ID</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Risk Score</TableHead>
                      <TableHead>Description</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Date</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {fraudAlerts.map((alert: any) => (
                      <TableRow key={alert.id}>
                        <TableCell className="font-medium">#{alert.id}</TableCell>
                        <TableCell>{alert.alertType}</TableCell>
                        <TableCell>
                          <span className={`font-medium ${
                            alert.riskScore >= 80 ? 'text-red-600' :
                            alert.riskScore >= 50 ? 'text-orange-600' : 'text-yellow-600'
                          }`}>
                            {alert.riskScore}/100
                          </span>
                        </TableCell>
                        <TableCell>{alert.description}</TableCell>
                        <TableCell>
                          <Badge 
                            variant={
                              alert.status === 'resolved' ? 'default' :
                              alert.status === 'investigating' ? 'secondary' : 'destructive'
                            }
                          >
                            {alert.status}
                          </Badge>
                        </TableCell>
                        <TableCell>{formatDate(alert.createdAt)}</TableCell>
                        <TableCell>
                          <Select 
                            value={alert.status}
                            onValueChange={(status) => 
                              updateFraudAlertMutation.mutate({ alertId: alert.id, status })
                            }
                          >
                            <SelectTrigger className="w-32">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="open">Open</SelectItem>
                              <SelectItem value="investigating">Investigating</SelectItem>
                              <SelectItem value="resolved">Resolved</SelectItem>
                              <SelectItem value="false_positive">False Positive</SelectItem>
                            </SelectContent>
                          </Select>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Settings Tab */}
          <TabsContent value="settings" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">System Settings</h2>
              <Button 
                onClick={handleSaveSettings}
                disabled={updateSettingMutation.isPending}
              >
                <Settings className="h-4 w-4 mr-2" />
                {updateSettingMutation.isPending ? "Saving..." : "Save Changes"}
              </Button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>General Settings</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label htmlFor="site-name">Site Name</Label>
                    <Input 
                      id="site-name" 
                      value={settingsForm.siteName}
                      onChange={(e) => handleInputChange('siteName', e.target.value)}
                    />
                  </div>
                  <div>
                    <Label htmlFor="site-description">Site Description</Label>
                    <Textarea 
                      id="site-description" 
                      value={settingsForm.siteDescription}
                      onChange={(e) => handleInputChange('siteDescription', e.target.value)}
                    />
                  </div>
                  <div>
                    <Label htmlFor="admin-email">Admin Email</Label>
                    <Input 
                      id="admin-email" 
                      type="email" 
                      value={settingsForm.adminEmail}
                      onChange={(e) => handleInputChange('adminEmail', e.target.value)}
                    />
                  </div>
                  <div>
                    <Label htmlFor="contact-phone">Contact Phone</Label>
                    <Input 
                      id="contact-phone" 
                      value={settingsForm.contactPhone}
                      onChange={(e) => handleInputChange('contactPhone', e.target.value)}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Business Settings</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label htmlFor="commission-rate">Commission Rate (%)</Label>
                    <Input 
                      id="commission-rate" 
                      type="number" 
                      value={settingsForm.commissionRate}
                      onChange={(e) => handleInputChange('commissionRate', e.target.value)}
                    />
                  </div>
                  <div>
                    <Label htmlFor="min-order">Minimum Order Amount</Label>
                    <Input 
                      id="min-order" 
                      type="number" 
                      value={settingsForm.minOrder}
                      onChange={(e) => handleInputChange('minOrder', e.target.value)}
                    />
                  </div>
                  <div>
                    <Label htmlFor="delivery-fee">Default Delivery Fee</Label>
                    <Input 
                      id="delivery-fee" 
                      type="number" 
                      value={settingsForm.deliveryFee}
                      onChange={(e) => handleInputChange('deliveryFee', e.target.value)}
                    />
                  </div>
                  <div>
                    <Label htmlFor="tax-rate">Tax Rate (%)</Label>
                    <Input 
                      id="tax-rate" 
                      type="number" 
                      value={settingsForm.taxRate}
                      onChange={(e) => handleInputChange('taxRate', e.target.value)}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Notification Settings</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between">
                    <Label>Email Notifications</Label>
                    <input 
                      type="checkbox" 
                      checked={settingsForm.emailNotifications}
                      onChange={(e) => handleInputChange('emailNotifications', e.target.checked)}
                      className="toggle" 
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <Label>SMS Notifications</Label>
                    <input 
                      type="checkbox" 
                      checked={settingsForm.smsNotifications}
                      onChange={(e) => handleInputChange('smsNotifications', e.target.checked)}
                      className="toggle" 
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <Label>Order Alerts</Label>
                    <input 
                      type="checkbox" 
                      checked={settingsForm.orderAlerts}
                      onChange={(e) => handleInputChange('orderAlerts', e.target.checked)}
                      className="toggle" 
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <Label>Low Stock Alerts</Label>
                    <input 
                      type="checkbox" 
                      checked={settingsForm.lowStockAlerts}
                      onChange={(e) => handleInputChange('lowStockAlerts', e.target.checked)}
                      className="toggle" 
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Security Settings</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between">
                    <Label>Two-Factor Authentication</Label>
                    <input 
                      type="checkbox" 
                      checked={settingsForm.twoFactorAuth}
                      onChange={(e) => handleInputChange('twoFactorAuth', e.target.checked)}
                      className="toggle" 
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <Label>Login Notifications</Label>
                    <input 
                      type="checkbox" 
                      checked={settingsForm.loginNotifications}
                      onChange={(e) => handleInputChange('loginNotifications', e.target.checked)}
                      className="toggle" 
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <Label>Fraud Detection</Label>
                    <input 
                      type="checkbox" 
                      checked={settingsForm.fraudDetection}
                      onChange={(e) => handleInputChange('fraudDetection', e.target.checked)}
                      className="toggle" 
                    />
                  </div>
                  <div>
                    <Label htmlFor="session-timeout">Session Timeout (minutes)</Label>
                    <Input 
                      id="session-timeout" 
                      type="number" 
                      value={settingsForm.sessionTimeout}
                      onChange={(e) => handleInputChange('sessionTimeout', e.target.value)}
                    />
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}