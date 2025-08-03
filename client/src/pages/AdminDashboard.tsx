
import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { 
  Users, 
  ShoppingCart, 
  Package, 
  DollarSign, 
  TrendingUp, 
  UserCheck, 
  UserX, 
  Clock, 
  Shield, 
  Store, 
  Eye,
  CheckCircle,
  XCircle,
  AlertCircle,
  Settings,
  BarChart3,
  Gift,
  Ticket,
  MessageSquare,
  Image,
  Tags,
  CreditCard,
  FileText,
  Ban,
  RefreshCw,
  Download,
  Search,
  Filter,
  MapPin,
  Phone,
  Mail,
  Calendar,
  UserMinus,
  Edit
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { User, Product, Order, Coupon, Banner, PaymentTransaction, SupportTicket } from "@shared/schema";

export default function AdminDashboard() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [adminUser, setAdminUser] = useState<any>(null);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [rejectReason, setRejectReason] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [filterRole, setFilterRole] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [showUserDetails, setShowUserDetails] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem("adminUser");
    if (stored) {
      setAdminUser(JSON.parse(stored));
    } else {
      setLocation("/admin/login");
    }
  }, [setLocation]);

  // Fetch dashboard data
  const { data: allUsers = [], refetch: refetchUsers } = useQuery({
    queryKey: ["/api/admin/users"],
    enabled: !!adminUser,
  });

  const { data: pendingUsers = [] } = useQuery({
    queryKey: ["/api/admin/users/pending"],
    enabled: !!adminUser,
  });

  const { data: allProducts = [] } = useQuery({
    queryKey: ["/api/products"],
    enabled: !!adminUser,
  });

  const { data: allOrders = [] } = useQuery({
    queryKey: ["/api/admin/orders"],
    enabled: !!adminUser,
  });

  const { data: allStores = [] } = useQuery({
    queryKey: ["/api/stores"],
    enabled: !!adminUser,
  });

  const { data: analytics } = useQuery({
    queryKey: ["/api/admin/analytics/stats"],
    enabled: !!adminUser,
  });

  const { data: coupons = [] } = useQuery({
    queryKey: ["/api/admin/coupons"],
    enabled: !!adminUser,
  });

  const { data: banners = [] } = useQuery({
    queryKey: ["/api/admin/banners"],
    enabled: !!adminUser,
  });

  const { data: transactions = [] } = useQuery({
    queryKey: ["/api/admin/transactions"],
    enabled: !!adminUser,
  });

  const { data: supportTickets = [] } = useQuery({
    queryKey: ["/api/admin/support-tickets"],
    enabled: !!adminUser,
  });

  // User approval mutations
  const approveMutation = useMutation({
    mutationFn: async (userId: number) => {
      const response = await apiRequest("POST", `/api/admin/users/${userId}/approve`, { adminId: adminUser.id });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users/pending"] });
      toast({
        title: "User approved",
        description: "Shopkeeper account has been approved successfully.",
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
      const response = await apiRequest("POST", `/api/admin/users/${userId}/reject`, { 
        adminId: adminUser.id, 
        reason 
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users/pending"] });
      setRejectReason("");
      toast({
        title: "User rejected",
        description: "Shopkeeper account has been rejected.",
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

  const banUserMutation = useMutation({
    mutationFn: async (userId: number) => {
      const response = await apiRequest("PUT", `/api/admin/users/${userId}/ban`, { 
        reason: "Banned by admin" 
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      toast({
        title: "User banned",
        description: "User has been banned successfully.",
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

  const handleRefresh = async () => {
    try {
      await refetchUsers();
      toast({
        title: "Data refreshed",
        description: "User data has been refreshed successfully.",
      });
    } catch (error) {
      toast({
        title: "Refresh failed",
        description: "Failed to refresh data. Please try again.",
        variant: "destructive",
      });
    }
  };

  const handleExport = () => {
    try {
      const filteredUsers = getFilteredUsers();
      const csvData = [
        // CSV Header
        ['ID', 'Full Name', 'Username', 'Email', 'Phone', 'Role', 'Status', 'City', 'State', 'Address', 'Created Date', 'Approval Date', 'Approved By', 'Rejection Reason'].join(','),
        // CSV Data
        ...filteredUsers.map(user => [
          user.id,
          `"${user.fullName}"`,
          `"${user.username || ''}"`,
          `"${user.email}"`,
          `"${user.phone || ''}"`,
          user.role,
          user.status,
          `"${user.city || ''}"`,
          `"${user.state || ''}"`,
          `"${user.address || ''}"`,
          new Date(user.createdAt).toLocaleDateString(),
          user.approvalDate ? new Date(user.approvalDate).toLocaleDateString() : '',
          user.approvedBy || '',
          `"${user.rejectionReason || ''}"`
        ].join(','))
      ].join('\n');

      const blob = new Blob([csvData], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `users_export_${new Date().toISOString().split('T')[0]}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      toast({
        title: "Export successful",
        description: `Exported ${filteredUsers.length} users to CSV file.`,
      });
    } catch (error) {
      toast({
        title: "Export failed",
        description: "Failed to export data. Please try again.",
        variant: "destructive",
      });
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "active":
        return <Badge variant="default" className="bg-green-100 text-green-800"><CheckCircle className="h-3 w-3 mr-1" />Active</Badge>;
      case "pending":
        return <Badge variant="secondary" className="bg-yellow-100 text-yellow-800"><Clock className="h-3 w-3 mr-1" />Pending</Badge>;
      case "rejected":
        return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" />Rejected</Badge>;
      case "suspended":
        return <Badge variant="destructive" className="bg-red-100 text-red-800"><Ban className="h-3 w-3 mr-1" />Banned</Badge>;
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

  const formatCurrency = (amount: string | number) => {
    return `Rs. ${parseFloat(amount.toString()).toLocaleString()}`;
  };

  const getFilteredUsers = () => {
    return allUsers.filter((user: User) => {
      const matchesSearch = !searchTerm || 
        user.fullName.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.username?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.phone?.includes(searchTerm);
      
      const matchesRole = filterRole === "all" || user.role === filterRole;
      const matchesStatus = filterStatus === "all" || user.status === filterStatus;
      
      return matchesSearch && matchesRole && matchesStatus;
    });
  };

  if (!adminUser) {
    return null;
  }

  const activeShopkeepers = allUsers.filter(user => user.role === "shopkeeper" && user.status === "active").length;
  const totalRevenue = transactions.reduce((sum: number, transaction: PaymentTransaction) => {
    return transaction.status === "completed" ? sum + parseFloat(transaction.amount) : sum;
  }, 0);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Admin Dashboard</h1>
                <p className="text-sm text-gray-500">Siraha Bazaar Administration</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600">Welcome, {adminUser.fullName}</span>
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
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
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
                <Store className="h-8 w-8 text-green-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Active Stores</p>
                  <p className="text-2xl font-bold text-gray-900">{allStores.length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <Package className="h-8 w-8 text-purple-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Products</p>
                  <p className="text-2xl font-bold text-gray-900">{allProducts.length}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <DollarSign className="h-8 w-8 text-yellow-600" />
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Total Revenue</p>
                  <p className="text-2xl font-bold text-gray-900">{formatCurrency(totalRevenue)}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Enhanced User Management Section */}
        <Card>
          <CardHeader>
            <div className="flex justify-between items-center">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Users className="h-5 w-5" />
                  User Management
                </CardTitle>
                <p className="text-sm text-gray-600 mt-1">Manage all users and their details</p>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={handleRefresh}>
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Refresh
                </Button>
                <Button variant="outline" size="sm" onClick={handleExport}>
                  <Download className="h-4 w-4 mr-2" />
                  Export CSV
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {/* Filters */}
            <div className="flex flex-col sm:flex-row gap-4 mb-6">
              <div className="flex-1">
                <Input
                  placeholder="Search by name, email, username, or phone..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full"
                />
              </div>
              <Select value={filterRole} onValueChange={setFilterRole}>
                <SelectTrigger className="w-40">
                  <SelectValue placeholder="Filter by role" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Roles</SelectItem>
                  <SelectItem value="customer">Customers</SelectItem>
                  <SelectItem value="shopkeeper">Shopkeepers</SelectItem>
                  <SelectItem value="delivery_partner">Delivery Partners</SelectItem>
                </SelectContent>
              </Select>
              <Select value={filterStatus} onValueChange={setFilterStatus}>
                <SelectTrigger className="w-40">
                  <SelectValue placeholder="Filter by status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="active">Active</SelectItem>
                  <SelectItem value="pending">Pending</SelectItem>
                  <SelectItem value="rejected">Rejected</SelectItem>
                  <SelectItem value="suspended">Banned</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Stats Row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <div className="bg-blue-50 p-3 rounded-lg">
                <p className="text-sm text-blue-600">Total Users</p>
                <p className="text-xl font-bold text-blue-900">{getFilteredUsers().length}</p>
              </div>
              <div className="bg-green-50 p-3 rounded-lg">
                <p className="text-sm text-green-600">Active</p>
                <p className="text-xl font-bold text-green-900">
                  {getFilteredUsers().filter(u => u.status === 'active').length}
                </p>
              </div>
              <div className="bg-yellow-50 p-3 rounded-lg">
                <p className="text-sm text-yellow-600">Pending</p>
                <p className="text-xl font-bold text-yellow-900">
                  {getFilteredUsers().filter(u => u.status === 'pending').length}
                </p>
              </div>
              <div className="bg-red-50 p-3 rounded-lg">
                <p className="text-sm text-red-600">Banned</p>
                <p className="text-xl font-bold text-red-900">
                  {getFilteredUsers().filter(u => u.status === 'suspended').length}
                </p>
              </div>
            </div>

            {/* Users Table */}
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>Contact</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Location</TableHead>
                    <TableHead>Joined</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {getFilteredUsers().map((user: User) => (
                    <TableRow key={user.id}>
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                            <Users className="h-4 w-4 text-blue-600" />
                          </div>
                          <div>
                            <p className="font-medium">{user.fullName}</p>
                            <p className="text-sm text-gray-500">@{user.username}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <Mail className="h-3 w-3 text-gray-400" />
                            <span className="text-sm">{user.email}</span>
                          </div>
                          {user.phone && (
                            <div className="flex items-center gap-2">
                              <Phone className="h-3 w-3 text-gray-400" />
                              <span className="text-sm">{user.phone}</span>
                            </div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge 
                          variant={
                            user.role === 'customer' ? 'default' :
                            user.role === 'shopkeeper' ? 'secondary' :
                            user.role === 'delivery_partner' ? 'outline' : 'default'
                          }
                        >
                          {user.role.replace('_', ' ')}
                        </Badge>
                      </TableCell>
                      <TableCell>{getStatusBadge(user.status)}</TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          {user.city && (
                            <div className="flex items-center gap-2">
                              <MapPin className="h-3 w-3 text-gray-400" />
                              <span className="text-sm">{user.city}{user.state && `, ${user.state}`}</span>
                            </div>
                          )}
                          {user.address && (
                            <p className="text-xs text-gray-500 truncate max-w-32" title={user.address}>
                              {user.address}
                            </p>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Calendar className="h-3 w-3 text-gray-400" />
                          <span className="text-sm">{formatDate(user.createdAt)}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-1">
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => {
                              setSelectedUser(user);
                              setShowUserDetails(true);
                            }}
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          {user.status === 'pending' && user.role === 'shopkeeper' && (
                            <>
                              <Button
                                size="sm"
                                onClick={() => approveMutation.mutate(user.id)}
                                disabled={approveMutation.isPending}
                                className="bg-green-600 hover:bg-green-700"
                              >
                                <CheckCircle className="h-4 w-4" />
                              </Button>
                              <Dialog>
                                <DialogTrigger asChild>
                                  <Button
                                    size="sm"
                                    variant="destructive"
                                    onClick={() => setSelectedUser(user)}
                                  >
                                    <XCircle className="h-4 w-4" />
                                  </Button>
                                </DialogTrigger>
                                <DialogContent>
                                  <DialogHeader>
                                    <DialogTitle>Reject User Application</DialogTitle>
                                    <DialogDescription>
                                      Are you sure you want to reject {user.fullName}'s application?
                                    </DialogDescription>
                                  </DialogHeader>
                                  <div className="space-y-4">
                                    <Textarea
                                      placeholder="Reason for rejection..."
                                      value={rejectReason}
                                      onChange={(e) => setRejectReason(e.target.value)}
                                    />
                                  </div>
                                  <DialogFooter>
                                    <Button
                                      variant="destructive"
                                      onClick={() => rejectMutation.mutate({ userId: user.id, reason: rejectReason })}
                                      disabled={rejectMutation.isPending}
                                    >
                                      Reject Application
                                    </Button>
                                  </DialogFooter>
                                </DialogContent>
                              </Dialog>
                            </>
                          )}
                          {user.status === 'active' && user.role !== 'customer' && (
                            <Button 
                              size="sm" 
                              variant="destructive"
                              onClick={() => banUserMutation.mutate(user.id)}
                              disabled={banUserMutation.isPending}
                            >
                              <Ban className="h-4 w-4" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>

            {getFilteredUsers().length === 0 && (
              <div className="text-center py-8 text-gray-500">
                <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No users found matching your criteria</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* User Details Dialog */}
        <Dialog open={showUserDetails} onOpenChange={setShowUserDetails}>
          <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Users className="h-5 w-5" />
                User Details
              </DialogTitle>
            </DialogHeader>
            {selectedUser && (
              <div className="space-y-6">
                {/* Basic Info */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="font-medium text-sm text-gray-500 mb-1">Full Name</h4>
                    <p className="text-sm font-medium">{selectedUser.fullName}</p>
                  </div>
                  <div>
                    <h4 className="font-medium text-sm text-gray-500 mb-1">Username</h4>
                    <p className="text-sm">{selectedUser.username || 'Not set'}</p>
                  </div>
                  <div>
                    <h4 className="font-medium text-sm text-gray-500 mb-1">Email</h4>
                    <p className="text-sm">{selectedUser.email}</p>
                  </div>
                  <div>
                    <h4 className="font-medium text-sm text-gray-500 mb-1">Phone</h4>
                    <p className="text-sm">{selectedUser.phone || 'Not provided'}</p>
                  </div>
                  <div>
                    <h4 className="font-medium text-sm text-gray-500 mb-1">Role</h4>
                    <Badge variant="secondary">{selectedUser.role.replace('_', ' ')}</Badge>
                  </div>
                  <div>
                    <h4 className="font-medium text-sm text-gray-500 mb-1">Status</h4>
                    {getStatusBadge(selectedUser.status)}
                  </div>
                </div>

                {/* Location Info */}
                {(selectedUser.address || selectedUser.city || selectedUser.state) && (
                  <div>
                    <h4 className="font-medium text-sm text-gray-500 mb-2">Location Information</h4>
                    <div className="bg-gray-50 p-3 rounded-lg space-y-2">
                      {selectedUser.address && (
                        <div>
                          <span className="text-xs font-medium text-gray-500">Address:</span>
                          <p className="text-sm">{selectedUser.address}</p>
                        </div>
                      )}
                      <div className="grid grid-cols-2 gap-4">
                        {selectedUser.city && (
                          <div>
                            <span className="text-xs font-medium text-gray-500">City:</span>
                            <p className="text-sm">{selectedUser.city}</p>
                          </div>
                        )}
                        {selectedUser.state && (
                          <div>
                            <span className="text-xs font-medium text-gray-500">State:</span>
                            <p className="text-sm">{selectedUser.state}</p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* Account Info */}
                <div>
                  <h4 className="font-medium text-sm text-gray-500 mb-2">Account Information</h4>
                  <div className="bg-gray-50 p-3 rounded-lg space-y-2">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <span className="text-xs font-medium text-gray-500">User ID:</span>
                        <p className="text-sm">#{selectedUser.id}</p>
                      </div>
                      <div>
                        <span className="text-xs font-medium text-gray-500">Registration Date:</span>
                        <p className="text-sm">{formatDate(selectedUser.createdAt)}</p>
                      </div>
                      {selectedUser.approvalDate && (
                        <div>
                          <span className="text-xs font-medium text-gray-500">Approval Date:</span>
                          <p className="text-sm">{formatDate(selectedUser.approvalDate)}</p>
                        </div>
                      )}
                      {selectedUser.approvedBy && (
                        <div>
                          <span className="text-xs font-medium text-gray-500">Approved By:</span>
                          <p className="text-sm">Admin #{selectedUser.approvedBy}</p>
                        </div>
                      )}
                    </div>
                    {selectedUser.rejectionReason && (
                      <div>
                        <span className="text-xs font-medium text-gray-500">Rejection Reason:</span>
                        <p className="text-sm text-red-600">{selectedUser.rejectionReason}</p>
                      </div>
                    )}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex gap-2 pt-4 border-t">
                  {selectedUser.status === 'pending' && selectedUser.role === 'shopkeeper' && (
                    <>
                      <Button
                        onClick={() => {
                          approveMutation.mutate(selectedUser.id);
                          setShowUserDetails(false);
                        }}
                        disabled={approveMutation.isPending}
                        className="bg-green-600 hover:bg-green-700"
                      >
                        <CheckCircle className="h-4 w-4 mr-2" />
                        Approve User
                      </Button>
                      <Button
                        variant="destructive"
                        onClick={() => {
                          setShowUserDetails(false);
                          // Open reject dialog
                        }}
                      >
                        <XCircle className="h-4 w-4 mr-2" />
                        Reject User
                      </Button>
                    </>
                  )}
                  {selectedUser.status === 'active' && selectedUser.role !== 'customer' && (
                    <Button
                      variant="destructive"
                      onClick={() => {
                        banUserMutation.mutate(selectedUser.id);
                        setShowUserDetails(false);
                      }}
                      disabled={banUserMutation.isPending}
                    >
                      <Ban className="h-4 w-4 mr-2" />
                      Ban User
                    </Button>
                  )}
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}
