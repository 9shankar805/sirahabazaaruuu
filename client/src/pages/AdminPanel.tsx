import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { 
  Users, 
  UserCheck, 
  UserX, 
  Clock, 
  Shield, 
  Store, 
  Eye,
  CheckCircle,
  XCircle,
  AlertCircle,
  MapPin,
  Plus,
  Edit,
  Trash2,
  Save,
  Truck,
  Settings,
  Key,
  User,
  Package,
  MoreHorizontal
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { User as UserType } from "@shared/schema";

export default function AdminPanel() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedUser, setSelectedUser] = useState<UserType | null>(null);
  const [rejectReason, setRejectReason] = useState("");
  const [adminUser, setAdminUser] = useState<any>(null);
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
  const [activeTab, setActiveTab] = useState("pending");
  const [showProfileDialog, setShowProfileDialog] = useState(false);
  const [showPasswordDialog, setShowPasswordDialog] = useState(false);
  const [profileData, setProfileData] = useState({
    fullName: "",
    email: "",
    currentPassword: "",
    newPassword: "",
    confirmPassword: ""
  });
  const [selectedProducts, setSelectedProducts] = useState<number[]>([]);

  useEffect(() => {
    const storedAdmin = localStorage.getItem("adminUser");
    if (!storedAdmin) {
      setLocation("/admin/login");
      return;
    }
    setAdminUser(JSON.parse(storedAdmin));
  }, [setLocation]);

  const { data: allUsers = [], isLoading: usersLoading } = useQuery({
    queryKey: ["/api/admin/users"],
    enabled: !!adminUser,
  });

  const { data: pendingUsers = [], isLoading: pendingLoading } = useQuery({
    queryKey: ["/api/admin/users/pending"],
    enabled: !!adminUser,
  });

  const { data: deliveryZones = [], isLoading: zonesLoading } = useQuery({
    queryKey: ["/api/delivery-zones"],
    enabled: !!adminUser,
  });

  const { data: deliveryPartners = [], isLoading: partnersLoading } = useQuery({
    queryKey: ["/api/delivery-partners"],
    enabled: !!adminUser,
  });

  const { data: allProducts = [], isLoading: productsLoading } = useQuery({
    queryKey: ["/api/products"],
    enabled: !!adminUser,
  });

  const { data: adminProfile } = useQuery({
    queryKey: ["/api/admin/profile", adminUser?.id],
    enabled: !!adminUser?.id,
  });

  const approveMutation = useMutation({
    mutationFn: async (userId: number) => {
      return await apiRequest(`/api/admin/users/${userId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser.id }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users/pending"] });
      toast({
        title: "User approved",
        description: "The shopkeeper account has been approved successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Approval failed",
        description: "Failed to approve user. Please try again.",
        variant: "destructive",
      });
    },
  });

  const rejectMutation = useMutation({
    mutationFn: async ({ userId, reason }: { userId: number; reason: string }) => {
      return await apiRequest(`/api/admin/users/${userId}/reject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser.id, reason }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users/pending"] });
      setSelectedUser(null);
      setRejectReason("");
      toast({
        title: "User rejected",
        description: "The shopkeeper application has been rejected.",
      });
    },
    onError: () => {
      toast({
        title: "Rejection failed",
        description: "Failed to reject user. Please try again.",
        variant: "destructive",
      });
    },
  });

  const createZoneMutation = useMutation({
    mutationFn: async (zoneData: any) => {
      return await apiRequest("/api/admin/delivery-zones", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...zoneData, adminId: adminUser.id }),
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
      toast({
        title: "Zone created",
        description: "Delivery zone has been created successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Creation failed",
        description: "Failed to create delivery zone.",
        variant: "destructive",
      });
    },
  });

  const updateZoneMutation = useMutation({
    mutationFn: async ({ id, data }: { id: number; data: any }) => {
      return await apiRequest(`/api/admin/delivery-zones/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...data, adminId: adminUser.id }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-zones"] });
      setEditingZone(null);
      toast({
        title: "Zone updated",
        description: "Delivery zone has been updated successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Update failed",
        description: "Failed to update delivery zone.",
        variant: "destructive",
      });
    },
  });

  const deleteZoneMutation = useMutation({
    mutationFn: async (id: number) => {
      return await apiRequest(`/api/admin/delivery-zones/${id}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser.id }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-zones"] });
      toast({
        title: "Zone deleted",
        description: "Delivery zone has been deleted successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Deletion failed",
        description: "Failed to delete delivery zone.",
        variant: "destructive",
      });
    },
  });

  const approvePartnerMutation = useMutation({
    mutationFn: async (partnerId: number) => {
      return await apiRequest(`/api/delivery-partners/${partnerId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser.id }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-partners"] });
      toast({
        title: "Partner approved",
        description: "Delivery partner has been approved successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Approval failed",
        description: "Failed to approve delivery partner. Please try again.",
        variant: "destructive",
      });
    },
  });

  const rejectPartnerMutation = useMutation({
    mutationFn: async ({ partnerId, reason }: { partnerId: number; reason: string }) => {
      return await apiRequest(`/api/delivery-partners/${partnerId}/reject`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser.id, reason }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/delivery-partners"] });
      toast({
        title: "Partner rejected",
        description: "Delivery partner application has been rejected.",
      });
    },
    onError: () => {
      toast({
        title: "Rejection failed",
        description: "Failed to reject delivery partner. Please try again.",
        variant: "destructive",
      });
    },
  });

  const updateProfileMutation = useMutation({
    mutationFn: async (data: any) => {
      return await apiRequest(`/api/admin/profile/${adminUser.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/profile", adminUser.id] });
      setShowProfileDialog(false);
      setProfileData({
        fullName: "",
        email: "",
        currentPassword: "",
        newPassword: "",
        confirmPassword: ""
      });
      toast({
        title: "Profile updated",
        description: "Admin profile has been updated successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Update failed",
        description: "Failed to update profile. Please try again.",
        variant: "destructive",
      });
    },
  });

  const changePasswordMutation = useMutation({
    mutationFn: async (data: any) => {
      return await apiRequest("/api/admin/change-password", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser.id, ...data }),
      });
    },
    onSuccess: () => {
      setShowPasswordDialog(false);
      setProfileData({
        fullName: "",
        email: "",
        currentPassword: "",
        newPassword: "",
        confirmPassword: ""
      });
      toast({
        title: "Password changed",
        description: "Admin password has been changed successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Password change failed",
        description: "Failed to change password. Please check your current password.",
        variant: "destructive",
      });
    },
  });

  const deleteProductMutation = useMutation({
    mutationFn: async (productId: number) => {
      return await apiRequest(`/api/admin/products/${productId}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId: adminUser.id }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/products"] });
      toast({
        title: "Product deleted",
        description: "Product has been deleted successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Deletion failed",
        description: "Failed to delete product. Please try again.",
        variant: "destructive",
      });
    },
  });

  const bulkDeleteProductsMutation = useMutation({
    mutationFn: async (productIds: number[]) => {
      return await apiRequest("/api/admin/products/bulk-delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ productIds, adminId: adminUser.id }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/products"] });
      setSelectedProducts([]);
      toast({
        title: "Products deleted",
        description: "Selected products have been deleted successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Bulk deletion failed",
        description: "Failed to delete selected products. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleLogout = () => {
    localStorage.removeItem("adminUser");
    setLocation("/admin/login");
    toast({
      title: "Logged out",
      description: "You have been logged out successfully.",
    });
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "active":
        return <Badge variant="default" className="bg-green-100 text-green-800"><CheckCircle className="h-3 w-3 mr-1" />Active</Badge>;
      case "pending":
        return <Badge variant="secondary" className="bg-yellow-100 text-yellow-800"><Clock className="h-3 w-3 mr-1" />Pending</Badge>;
      case "rejected":
        return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" />Rejected</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  if (!adminUser) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Admin Panel</h1>
                <p className="text-sm text-gray-500">Siraha Bazaar Administration</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600">Welcome, {adminUser.fullName}</span>
              
              <Dialog open={showProfileDialog} onOpenChange={setShowProfileDialog}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm">
                    <Settings className="h-4 w-4 mr-2" />
                    Settings
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Admin Profile Settings</DialogTitle>
                    <DialogDescription>
                      Update your admin profile information
                    </DialogDescription>
                  </DialogHeader>
                  <div className="grid gap-4 py-4">
                    <div className="grid grid-cols-4 items-center gap-4">
                      <Label htmlFor="admin-name" className="text-right">Full Name</Label>
                      <Input
                        id="admin-name"
                        value={profileData.fullName || adminProfile?.fullName || ""}
                        onChange={(e) => setProfileData({ ...profileData, fullName: e.target.value })}
                        className="col-span-3"
                      />
                    </div>
                    <div className="grid grid-cols-4 items-center gap-4">
                      <Label htmlFor="admin-email" className="text-right">Email</Label>
                      <Input
                        id="admin-email"
                        type="email"
                        value={profileData.email || adminProfile?.email || ""}
                        onChange={(e) => setProfileData({ ...profileData, email: e.target.value })}
                        className="col-span-3"
                      />
                    </div>
                  </div>
                  <DialogFooter>
                    <Button variant="outline" onClick={() => setShowProfileDialog(false)}>
                      Cancel
                    </Button>
                    <Button 
                      onClick={() => updateProfileMutation.mutate(profileData)}
                      disabled={updateProfileMutation.isPending}
                    >
                      <Save className="h-4 w-4 mr-2" />
                      Update Profile
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>

              <Dialog open={showPasswordDialog} onOpenChange={setShowPasswordDialog}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm">
                    <Key className="h-4 w-4 mr-2" />
                    Change Password
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Change Admin Password</DialogTitle>
                    <DialogDescription>
                      Enter your current password and choose a new one
                    </DialogDescription>
                  </DialogHeader>
                  <div className="grid gap-4 py-4">
                    <div className="grid grid-cols-4 items-center gap-4">
                      <Label htmlFor="current-password" className="text-right">Current Password</Label>
                      <Input
                        id="current-password"
                        type="password"
                        value={profileData.currentPassword}
                        onChange={(e) => setProfileData({ ...profileData, currentPassword: e.target.value })}
                        className="col-span-3"
                      />
                    </div>
                    <div className="grid grid-cols-4 items-center gap-4">
                      <Label htmlFor="new-password" className="text-right">New Password</Label>
                      <Input
                        id="new-password"
                        type="password"
                        value={profileData.newPassword}
                        onChange={(e) => setProfileData({ ...profileData, newPassword: e.target.value })}
                        className="col-span-3"
                      />
                    </div>
                    <div className="grid grid-cols-4 items-center gap-4">
                      <Label htmlFor="confirm-password" className="text-right">Confirm Password</Label>
                      <Input
                        id="confirm-password"
                        type="password"
                        value={profileData.confirmPassword}
                        onChange={(e) => setProfileData({ ...profileData, confirmPassword: e.target.value })}
                        className="col-span-3"
                      />
                    </div>
                  </div>
                  <DialogFooter>
                    <Button variant="outline" onClick={() => setShowPasswordDialog(false)}>
                      Cancel
                    </Button>
                    <Button 
                      onClick={() => {
                        if (profileData.newPassword !== profileData.confirmPassword) {
                          toast({
                            title: "Password mismatch",
                            description: "New password and confirm password don't match.",
                            variant: "destructive",
                          });
                          return;
                        }
                        changePasswordMutation.mutate({
                          currentPassword: profileData.currentPassword,
                          newPassword: profileData.newPassword
                        });
                      }}
                      disabled={changePasswordMutation.isPending || !profileData.currentPassword || !profileData.newPassword}
                    >
                      <Key className="h-4 w-4 mr-2" />
                      Change Password
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>

              <Button variant="outline" onClick={handleLogout}>
                Logout
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <Users className="h-8 w-8 text-blue-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Users</p>
                  <p className="text-2xl font-bold text-gray-900">{allUsers.length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <Clock className="h-8 w-8 text-yellow-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Pending Approval</p>
                  <p className="text-2xl font-bold text-gray-900">{pendingUsers.length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <UserCheck className="h-8 w-8 text-green-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Active Shopkeepers</p>
                  <p className="text-2xl font-bold text-gray-900">
                    {allUsers.filter(u => u.role === 'shopkeeper' && u.status === 'active').length}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <Store className="h-8 w-8 text-purple-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Customers</p>
                  <p className="text-2xl font-bold text-gray-900">
                    {allUsers.filter(u => u.role === 'customer').length}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Pending Approvals Alert */}
        {pendingUsers.length > 0 && (
          <Alert className="mb-6">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              You have {pendingUsers.length} pending shopkeeper application{pendingUsers.length > 1 ? 's' : ''} waiting for approval.
            </AlertDescription>
          </Alert>
        )}

        {/* Navigation Sidebar */}
        <div className="flex gap-6">
          {/* Sidebar */}
          <div className="w-64 bg-white shadow-sm rounded-lg p-4 h-fit">
            <nav className="space-y-2">
              <h3 className="font-semibold text-gray-900 mb-4">Admin Navigation</h3>
              <div className="space-y-1">
                <button
                  onClick={() => setActiveTab("pending")}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeTab === "pending" 
                      ? "bg-blue-100 text-blue-700 border-l-4 border-blue-700" 
                      : "text-gray-600 hover:bg-gray-100"
                  }`}
                >
                  <Clock className="h-4 w-4" />
                  Pending Approvals
                  {pendingUsers.length > 0 && (
                    <Badge variant="secondary" className="ml-auto">
                      {pendingUsers.length}
                    </Badge>
                  )}
                </button>
                
                <button
                  onClick={() => setActiveTab("delivery-partners")}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeTab === "delivery-partners" 
                      ? "bg-green-100 text-green-700 border-l-4 border-green-700" 
                      : "text-gray-600 hover:bg-gray-100"
                  }`}
                >
                  <Truck className="h-4 w-4" />
                  Delivery Partners
                  {deliveryPartners.filter((p: any) => p.status === 'pending').length > 0 && (
                    <Badge variant="secondary" className="ml-auto bg-orange-100 text-orange-800">
                      {deliveryPartners.filter((p: any) => p.status === 'pending').length}
                    </Badge>
                  )}
                </button>
                
                <button
                  onClick={() => setActiveTab("all")}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeTab === "all" 
                      ? "bg-purple-100 text-purple-700 border-l-4 border-purple-700" 
                      : "text-gray-600 hover:bg-gray-100"
                  }`}
                >
                  <Users className="h-4 w-4" />
                  All Users
                  <Badge variant="outline" className="ml-auto">
                    {allUsers.length}
                  </Badge>
                </button>
                
                <button
                  onClick={() => setActiveTab("products")}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeTab === "products" 
                      ? "bg-orange-100 text-orange-700 border-l-4 border-orange-700" 
                      : "text-gray-600 hover:bg-gray-100"
                  }`}
                >
                  <Package className="h-4 w-4" />
                  Products
                  <Badge variant="outline" className="ml-auto">
                    {allProducts.length}
                  </Badge>
                </button>
                
                <button
                  onClick={() => setActiveTab("delivery-zones")}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeTab === "delivery-zones" 
                      ? "bg-indigo-100 text-indigo-700 border-l-4 border-indigo-700" 
                      : "text-gray-600 hover:bg-gray-100"
                  }`}
                >
                  <MapPin className="h-4 w-4" />
                  Delivery Zones
                  <Badge variant="outline" className="ml-auto">
                    {deliveryZones.length}
                  </Badge>
                </button>
              </div>
            </nav>
          </div>

          {/* Main Content */}
          <div className="flex-1">
            <Tabs value={activeTab} className="space-y-6">
              <div className="hidden">
                <TabsList>
                  <TabsTrigger value="pending">Pending Approvals</TabsTrigger>
                  <TabsTrigger value="all">All Users</TabsTrigger>
                  <TabsTrigger value="delivery-partners">Delivery Partners</TabsTrigger>
                  <TabsTrigger value="products">Products</TabsTrigger>
                  <TabsTrigger value="delivery-zones">Delivery Zones</TabsTrigger>
                </TabsList>
              </div>

          <TabsContent value="pending">
            <Card>
              <CardHeader>
                <CardTitle>Pending Shopkeeper Applications</CardTitle>
              </CardHeader>
              <CardContent>
                {pendingLoading ? (
                  <div className="text-center py-8">Loading...</div>
                ) : pendingUsers.length === 0 ? (
                  <div className="text-center py-8 text-gray-500">
                    No pending applications
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Name</TableHead>
                        <TableHead>Email</TableHead>
                        <TableHead>Phone</TableHead>
                        <TableHead>Applied Date</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {pendingUsers.map((user) => (
                        <TableRow key={user.id}>
                          <TableCell className="font-medium">{user.fullName}</TableCell>
                          <TableCell>{user.email}</TableCell>
                          <TableCell>{user.phone}</TableCell>
                          <TableCell>{formatDate(user.createdAt)}</TableCell>
                          <TableCell>
                            <div className="flex space-x-2">
                              <Button
                                size="sm"
                                onClick={() => approveMutation.mutate(user.id)}
                                disabled={approveMutation.isPending}
                              >
                                <UserCheck className="h-4 w-4 mr-1" />
                                Approve
                              </Button>
                              <Dialog>
                                <DialogTrigger asChild>
                                  <Button
                                    size="sm"
                                    variant="destructive"
                                    onClick={() => setSelectedUser(user)}
                                  >
                                    <UserX className="h-4 w-4 mr-1" />
                                    Reject
                                  </Button>
                                </DialogTrigger>
                                <DialogContent>
                                  <DialogHeader>
                                    <DialogTitle>Reject Application</DialogTitle>
                                    <DialogDescription>
                                      Are you sure you want to reject {user.fullName}'s shopkeeper application?
                                    </DialogDescription>
                                  </DialogHeader>
                                  <div>
                                    <Textarea
                                      placeholder="Enter reason for rejection (optional)"
                                      value={rejectReason}
                                      onChange={(e) => setRejectReason(e.target.value)}
                                    />
                                  </div>
                                  <DialogFooter>
                                    <Button variant="outline" onClick={() => {
                                      setSelectedUser(null);
                                      setRejectReason("");
                                    }}>
                                      Cancel
                                    </Button>
                                    <Button
                                      variant="destructive"
                                      onClick={() => rejectMutation.mutate({
                                        userId: user.id,
                                        reason: rejectReason
                                      })}
                                      disabled={rejectMutation.isPending}
                                    >
                                      Reject Application
                                    </Button>
                                  </DialogFooter>
                                </DialogContent>
                              </Dialog>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="delivery-partners">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <svg className="h-6 w-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3a2 2 0 012-2h4a2 2 0 012 2v4m-6 0V6a2 2 0 012-2h2a2 2 0 012 2v1m-6 0h6m0 0v.5a2 2 0 01-2 2H10a2 2 0 01-2-2V7m8 4l3 3-3 3m-3-3h12" />
                      </svg>
                      Delivery Partner Management
                    </CardTitle>
                    <p className="text-sm text-gray-600 mt-1">
                      Review and manage delivery partner applications
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Badge variant="secondary" className="bg-yellow-100 text-yellow-800">
                      {deliveryPartners.filter((p: any) => p.status === 'pending').length} Pending
                    </Badge>
                    <Badge variant="default" className="bg-green-100 text-green-800">
                      {deliveryPartners.filter((p: any) => p.status === 'approved').length} Approved
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                {partnersLoading ? (
                  <div className="text-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
                    <p>Loading delivery partners...</p>
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Partner ID</TableHead>
                        <TableHead>User ID</TableHead>
                        <TableHead>Vehicle</TableHead>
                        <TableHead>License</TableHead>
                        <TableHead>Areas</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Rating</TableHead>
                        <TableHead>Total Deliveries</TableHead>
                        <TableHead>Earnings</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {(deliveryPartners as any[]).map((partner) => (
                        <TableRow key={partner.id}>
                          <TableCell className="font-medium">#{partner.id}</TableCell>
                          <TableCell>{partner.userId}</TableCell>
                          <TableCell>
                            <div>
                              <p className="font-medium">{partner.vehicleType}</p>
                              <p className="text-sm text-gray-500">{partner.vehicleNumber}</p>
                            </div>
                          </TableCell>
                          <TableCell>{partner.drivingLicense}</TableCell>
                          <TableCell>
                            {partner.deliveryAreas && partner.deliveryAreas.length > 0 
                              ? partner.deliveryAreas.join(', ') 
                              : 'Not specified'
                            }
                          </TableCell>
                          <TableCell>
                            {partner.status === 'approved' ? (
                              <Badge variant="default" className="bg-green-100 text-green-800">
                                <CheckCircle className="h-3 w-3 mr-1" />
                                Approved
                              </Badge>
                            ) : partner.status === 'pending' ? (
                              <Badge variant="secondary" className="bg-yellow-100 text-yellow-800">
                                <Clock className="h-3 w-3 mr-1" />
                                Pending
                              </Badge>
                            ) : (
                              <Badge variant="destructive">
                                <XCircle className="h-3 w-3 mr-1" />
                                {partner.status}
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center">
                              <span className="font-medium">{partner.rating || '0.00'}</span>
                              <span className="text-sm text-gray-500 ml-1">/5.00</span>
                            </div>
                          </TableCell>
                          <TableCell>{partner.totalDeliveries || 0}</TableCell>
                          <TableCell>Rs. {partner.totalEarnings || '0.00'}</TableCell>
                          <TableCell>
                            <div className="flex space-x-2">
                              <Button size="sm" variant="outline">
                                <Eye className="h-4 w-4 mr-1" />
                                View
                              </Button>
                              {partner.status === 'pending' && (
                                <>
                                  <Button
                                    size="sm"
                                    onClick={() => approvePartnerMutation.mutate(partner.id)}
                                    disabled={approvePartnerMutation.isPending}
                                    className="bg-green-600 hover:bg-green-700"
                                  >
                                    <CheckCircle className="h-4 w-4 mr-1" />
                                    Approve
                                  </Button>
                                  <Dialog>
                                    <DialogTrigger asChild>
                                      <Button size="sm" variant="destructive">
                                        <XCircle className="h-4 w-4 mr-1" />
                                        Reject
                                      </Button>
                                    </DialogTrigger>
                                    <DialogContent>
                                      <DialogHeader>
                                        <DialogTitle>Reject Delivery Partner</DialogTitle>
                                        <DialogDescription>
                                          Are you sure you want to reject this delivery partner application?
                                        </DialogDescription>
                                      </DialogHeader>
                                      <div>
                                        <Textarea
                                          placeholder="Enter reason for rejection (optional)"
                                          value={rejectReason}
                                          onChange={(e) => setRejectReason(e.target.value)}
                                        />
                                      </div>
                                      <DialogFooter>
                                        <Button variant="outline" onClick={() => setRejectReason("")}>
                                          Cancel
                                        </Button>
                                        <Button
                                          variant="destructive"
                                          onClick={() => rejectPartnerMutation.mutate({
                                            partnerId: partner.id,
                                            reason: rejectReason
                                          })}
                                          disabled={rejectPartnerMutation.isPending}
                                        >
                                          Reject Application
                                        </Button>
                                      </DialogFooter>
                                    </DialogContent>
                                  </Dialog>
                                </>
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
                
                {(deliveryPartners as any[]).length === 0 && !partnersLoading && (
                  <div className="text-center py-8 text-gray-500">
                    <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No delivery partners found</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="all">
            <Card>
              <CardHeader>
                <CardTitle>All Users</CardTitle>
              </CardHeader>
              <CardContent>
                {usersLoading ? (
                  <div className="text-center py-8">Loading...</div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Name</TableHead>
                        <TableHead>Email</TableHead>
                        <TableHead>Role</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Joined Date</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {allUsers.map((user) => (
                        <TableRow key={user.id}>
                          <TableCell className="font-medium">{user.fullName}</TableCell>
                          <TableCell>{user.email}</TableCell>
                          <TableCell>
                            <Badge variant={user.role === 'shopkeeper' ? 'default' : 'secondary'}>
                              {user.role}
                            </Badge>
                          </TableCell>
                          <TableCell>{getStatusBadge(user.status)}</TableCell>
                          <TableCell>{formatDate(user.createdAt)}</TableCell>
                          <TableCell>
                            <Button size="sm" variant="outline">
                              <Eye className="h-4 w-4 mr-1" />
                              View
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="products">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Package className="h-6 w-6 text-orange-600" />
                      Product Management
                    </CardTitle>
                    <p className="text-sm text-gray-600 mt-1">
                      Manage all products across the platform
                    </p>
                  </div>
                  <div className="flex gap-2">
                    {selectedProducts.length > 0 && (
                      <Button
                        variant="destructive"
                        onClick={() => bulkDeleteProductsMutation.mutate(selectedProducts)}
                        disabled={bulkDeleteProductsMutation.isPending}
                      >
                        <Trash2 className="h-4 w-4 mr-2" />
                        Delete Selected ({selectedProducts.length})
                      </Button>
                    )}
                    <Badge variant="outline">
                      {allProducts.length} Total Products
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                {productsLoading ? (
                  <div className="text-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
                    <p>Loading products...</p>
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-12">
                          <input
                            type="checkbox"
                            checked={selectedProducts.length === allProducts.length && allProducts.length > 0}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setSelectedProducts(allProducts.map((p: any) => p.id));
                              } else {
                                setSelectedProducts([]);
                              }
                            }}
                            className="rounded"
                          />
                        </TableHead>
                        <TableHead>Product</TableHead>
                        <TableHead>Store</TableHead>
                        <TableHead>Category</TableHead>
                        <TableHead>Price</TableHead>
                        <TableHead>Stock</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {(allProducts as any[]).map((product) => (
                        <TableRow key={product.id}>
                          <TableCell>
                            <input
                              type="checkbox"
                              checked={selectedProducts.includes(product.id)}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setSelectedProducts([...selectedProducts, product.id]);
                                } else {
                                  setSelectedProducts(selectedProducts.filter(id => id !== product.id));
                                }
                              }}
                              className="rounded"
                            />
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center space-x-3">
                              {product.imageUrl && (
                                <img
                                  src={product.imageUrl}
                                  alt={product.name}
                                  className="w-10 h-10 rounded object-cover"
                                />
                              )}
                              <div>
                                <p className="font-medium">{product.name}</p>
                                <p className="text-sm text-gray-500">ID: {product.id}</p>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>{product.storeName || 'Unknown Store'}</TableCell>
                          <TableCell>{product.category || 'Uncategorized'}</TableCell>
                          <TableCell>Rs. {product.price}</TableCell>
                          <TableCell>
                            <span className={`font-medium ${product.stock < 10 ? 'text-red-600' : 'text-green-600'}`}>
                              {product.stock}
                            </span>
                          </TableCell>
                          <TableCell>
                            {product.isActive ? (
                              <Badge variant="default" className="bg-green-100 text-green-800">
                                Active
                              </Badge>
                            ) : (
                              <Badge variant="secondary">Inactive</Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex space-x-2">
                              <Button size="sm" variant="outline">
                                <Eye className="h-4 w-4 mr-1" />
                                View
                              </Button>
                              <Dialog>
                                <DialogTrigger asChild>
                                  <Button size="sm" variant="destructive">
                                    <Trash2 className="h-4 w-4 mr-1" />
                                    Delete
                                  </Button>
                                </DialogTrigger>
                                <DialogContent>
                                  <DialogHeader>
                                    <DialogTitle>Delete Product</DialogTitle>
                                    <DialogDescription>
                                      Are you sure you want to delete "{product.name}"? This action cannot be undone.
                                    </DialogDescription>
                                  </DialogHeader>
                                  <DialogFooter>
                                    <Button variant="outline">Cancel</Button>
                                    <Button
                                      variant="destructive"
                                      onClick={() => deleteProductMutation.mutate(product.id)}
                                      disabled={deleteProductMutation.isPending}
                                    >
                                      Delete Product
                                    </Button>
                                  </DialogFooter>
                                </DialogContent>
                              </Dialog>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
                
                {(allProducts as any[]).length === 0 && !productsLoading && (
                  <div className="text-center py-8 text-gray-500">
                    <Package className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No products found</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="delivery-zones">
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
                        <DialogDescription>
                          Add a new delivery zone with custom pricing.
                        </DialogDescription>
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
                        <div className="flex items-center space-x-2">
                          <Switch
                            id="isActive"
                            checked={newZone.isActive}
                            onCheckedChange={(checked) => setNewZone({ ...newZone, isActive: checked })}
                          />
                          <Label htmlFor="isActive">Active Zone</Label>
                        </div>
                      </div>
                      <DialogFooter>
                        <Button variant="outline" onClick={() => setShowCreateZone(false)}>
                          Cancel
                        </Button>
                        <Button 
                          onClick={() => createZoneMutation.mutate(newZone)}
                          disabled={createZoneMutation.isPending}
                        >
                          <Save className="h-4 w-4 mr-2" />
                          Create Zone
                        </Button>
                      </DialogFooter>
                    </DialogContent>
                  </Dialog>
                </div>
              </CardHeader>
              <CardContent>
                {zonesLoading ? (
                  <div className="text-center py-8">Loading delivery zones...</div>
                ) : (
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
                                    <DialogDescription>
                                      Modify the delivery zone pricing and settings.
                                    </DialogDescription>
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
                                      <div className="flex items-center space-x-2">
                                        <Switch
                                          id="edit-isActive"
                                          checked={editingZone.isActive}
                                          onCheckedChange={(checked) => setEditingZone({ ...editingZone, isActive: checked })}
                                        />
                                        <Label htmlFor="edit-isActive">Active Zone</Label>
                                      </div>
                                    </div>
                                  )}
                                  <DialogFooter>
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
                                      <Save className="h-4 w-4 mr-2" />
                                      Update Zone
                                    </Button>
                                  </DialogFooter>
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
                )}
                
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
            </Tabs>
          </div>
        </div>
      </div>
    </div>
  );
}