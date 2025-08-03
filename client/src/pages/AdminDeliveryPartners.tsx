import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Truck, Clock, CheckCircle, XCircle, Eye, Phone, CreditCard } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useState } from "react";

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
  approvedBy: number | null;
  rejectionReason: string | null;
  createdAt: string;
  approvalDate: string | null;
}

export default function AdminDeliveryPartners() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedPartner, setSelectedPartner] = useState<DeliveryPartner | null>(null);
  const [rejectionReason, setRejectionReason] = useState("");
  const [showRejectDialog, setShowRejectDialog] = useState(false);

  const { data: allPartners = [], isLoading: allLoading } = useQuery({
    queryKey: ['/api/delivery-partners'],
  });

  const { data: pendingPartners = [], isLoading: pendingLoading } = useQuery({
    queryKey: ['/api/delivery-partners/pending'],
  });

  const approvePartner = useMutation({
    mutationFn: async (partnerId: number) => {
      // Get the admin user ID from the admin authentication system
      const adminResponse = await fetch('/api/admin/current');
      const adminData = await adminResponse.json();
      const adminId = adminData?.id || 1; // Fallback to ID 1 if admin not found
      
      return apiRequest(`/api/delivery-partners/${partnerId}/approve`, {
        method: 'POST',
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/delivery-partners'] });
      queryClient.invalidateQueries({ queryKey: ['/api/delivery-partners/pending'] });
      toast({
        title: "Partner Approved",
        description: "Delivery partner has been approved successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to approve delivery partner.",
        variant: "destructive",
      });
    },
  });

  const rejectPartner = useMutation({
    mutationFn: async ({ partnerId, reason }: { partnerId: number; reason: string }) => {
      // Get the admin user ID from the admin authentication system
      const adminResponse = await fetch('/api/admin/current');
      const adminData = await adminResponse.json();
      const adminId = adminData?.id || 1; // Fallback to ID 1 if admin not found
      
      return apiRequest(`/api/delivery-partners/${partnerId}/reject`, {
        method: 'POST',
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ adminId, reason }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/delivery-partners'] });
      queryClient.invalidateQueries({ queryKey: ['/api/delivery-partners/pending'] });
      setShowRejectDialog(false);
      setRejectionReason("");
      setSelectedPartner(null);
      toast({
        title: "Partner Rejected",
        description: "Delivery partner application has been rejected.",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to reject delivery partner.",
        variant: "destructive",
      });
    },
  });

  const handleReject = (partner: DeliveryPartner) => {
    setSelectedPartner(partner);
    setShowRejectDialog(true);
  };

  const confirmReject = () => {
    if (selectedPartner && rejectionReason.trim()) {
      rejectPartner.mutate({ partnerId: selectedPartner.id, reason: rejectionReason });
    }
  };

  const approvedPartners = allPartners.filter((p: DeliveryPartner) => p.status === 'approved');
  const rejectedPartners = allPartners.filter((p: DeliveryPartner) => p.status === 'rejected');

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'pending':
        return <Badge variant="secondary"><Clock className="h-3 w-3 mr-1" />Pending</Badge>;
      case 'approved':
        return <Badge variant="default"><CheckCircle className="h-3 w-3 mr-1" />Approved</Badge>;
      case 'rejected':
        return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" />Rejected</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  const PartnerCard = ({ partner }: { partner: DeliveryPartner }) => (
    <Card key={partner.id}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg">Partner #{partner.id}</CardTitle>
          {getStatusBadge(partner.status)}
        </div>
        <CardDescription>
          Applied on {new Date(partner.createdAt).toLocaleDateString()}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <strong>Vehicle:</strong> {partner.vehicleType}
            </div>
            <div>
              <strong>Vehicle Number:</strong> {partner.vehicleNumber}
            </div>
            <div>
              <strong>License:</strong> {partner.drivingLicense}
            </div>
            <div>
              <strong>ID Proof:</strong> {partner.idProofType}
            </div>
            <div className="col-span-2">
              <strong>Delivery Areas:</strong> {partner.deliveryAreas.join(', ')}
            </div>
          </div>

          <div className="flex items-center gap-2 pt-3">
            <Dialog>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm">
                  <Eye className="h-4 w-4 mr-1" />
                  View Details
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>Delivery Partner Details</DialogTitle>
                  <DialogDescription>
                    Complete information for Partner #{partner.id}
                  </DialogDescription>
                </DialogHeader>
                <div className="grid grid-cols-2 gap-4 py-4">
                  <div>
                    <Label className="text-sm font-medium">Vehicle Type</Label>
                    <p className="text-sm text-muted-foreground">{partner.vehicleType}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium">Vehicle Number</Label>
                    <p className="text-sm text-muted-foreground">{partner.vehicleNumber}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium">Driving License</Label>
                    <p className="text-sm text-muted-foreground">{partner.drivingLicense}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium">ID Proof Type</Label>
                    <p className="text-sm text-muted-foreground">{partner.idProofType}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium">ID Proof Number</Label>
                    <p className="text-sm text-muted-foreground">{partner.idProofNumber}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium">Emergency Contact</Label>
                    <p className="text-sm text-muted-foreground flex items-center">
                      <Phone className="h-3 w-3 mr-1" />
                      {partner.emergencyContact}
                    </p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium">Bank Account</Label>
                    <p className="text-sm text-muted-foreground flex items-center">
                      <CreditCard className="h-3 w-3 mr-1" />
                      {partner.bankAccountNumber}
                    </p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium">IFSC Code</Label>
                    <p className="text-sm text-muted-foreground">{partner.ifscCode}</p>
                  </div>
                  <div className="col-span-2">
                    <Label className="text-sm font-medium">Delivery Areas</Label>
                    <p className="text-sm text-muted-foreground">{partner.deliveryAreas.join(', ')}</p>
                  </div>
                  {partner.status === 'approved' && (
                    <>
                      <div>
                        <Label className="text-sm font-medium">Total Deliveries</Label>
                        <p className="text-sm text-muted-foreground">{partner.totalDeliveries}</p>
                      </div>
                      <div>
                        <Label className="text-sm font-medium">Total Earnings</Label>
                        <p className="text-sm text-muted-foreground">₹{partner.totalEarnings}</p>
                      </div>
                      <div>
                        <Label className="text-sm font-medium">Rating</Label>
                        <p className="text-sm text-muted-foreground">
                          {partner.rating ? `${partner.rating.toFixed(1)}★` : "No ratings yet"}
                        </p>
                      </div>
                      <div>
                        <Label className="text-sm font-medium">Availability</Label>
                        <Badge variant={partner.isAvailable ? "default" : "secondary"}>
                          {partner.isAvailable ? "Available" : "Offline"}
                        </Badge>
                      </div>
                    </>
                  )}
                  {partner.rejectionReason && (
                    <div className="col-span-2">
                      <Label className="text-sm font-medium">Rejection Reason</Label>
                      <p className="text-sm text-muted-foreground">{partner.rejectionReason}</p>
                    </div>
                  )}
                </div>
              </DialogContent>
            </Dialog>

            {partner.status === 'pending' && (
              <>
                <Button
                  size="sm"
                  onClick={() => approvePartner.mutate(partner.id)}
                  disabled={approvePartner.isPending}
                >
                  <CheckCircle className="h-4 w-4 mr-1" />
                  Approve
                </Button>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => handleReject(partner)}
                  disabled={rejectPartner.isPending}
                >
                  <XCircle className="h-4 w-4 mr-1" />
                  Reject
                </Button>
              </>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className="container mx-auto p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold">Delivery Partner Management</h1>
          <p className="text-muted-foreground">Manage delivery partner applications and accounts</p>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Partners</CardTitle>
            <Truck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{allPartners.length}</div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Pending Applications</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{pendingPartners.length}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Approved Partners</CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{approvedPartners.length}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Partners</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {approvedPartners.filter((p: DeliveryPartner) => p.isAvailable).length}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Partner Management Tabs */}
      <Tabs defaultValue="pending" className="w-full">
        <TabsList>
          <TabsTrigger value="pending">
            Pending Applications ({pendingPartners.length})
          </TabsTrigger>
          <TabsTrigger value="approved">
            Approved Partners ({approvedPartners.length})
          </TabsTrigger>
          <TabsTrigger value="rejected">
            Rejected Applications ({rejectedPartners.length})
          </TabsTrigger>
          <TabsTrigger value="all">
            All Partners ({allPartners.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="pending" className="space-y-4">
          {pendingLoading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
              <p>Loading pending applications...</p>
            </div>
          ) : pendingPartners.length === 0 ? (
            <Card>
              <CardContent className="p-6 text-center">
                <Clock className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground">No pending applications</p>
              </CardContent>
            </Card>
          ) : (
            pendingPartners.map((partner: DeliveryPartner) => (
              <PartnerCard key={partner.id} partner={partner} />
            ))
          )}
        </TabsContent>

        <TabsContent value="approved" className="space-y-4">
          {approvedPartners.length === 0 ? (
            <Card>
              <CardContent className="p-6 text-center">
                <CheckCircle className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground">No approved partners</p>
              </CardContent>
            </Card>
          ) : (
            approvedPartners.map((partner: DeliveryPartner) => (
              <PartnerCard key={partner.id} partner={partner} />
            ))
          )}
        </TabsContent>

        <TabsContent value="rejected" className="space-y-4">
          {rejectedPartners.length === 0 ? (
            <Card>
              <CardContent className="p-6 text-center">
                <XCircle className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground">No rejected applications</p>
              </CardContent>
            </Card>
          ) : (
            rejectedPartners.map((partner: DeliveryPartner) => (
              <PartnerCard key={partner.id} partner={partner} />
            ))
          )}
        </TabsContent>

        <TabsContent value="all" className="space-y-4">
          {allLoading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
              <p>Loading all partners...</p>
            </div>
          ) : (
            allPartners.map((partner: DeliveryPartner) => (
              <PartnerCard key={partner.id} partner={partner} />
            ))
          )}
        </TabsContent>
      </Tabs>

      {/* Rejection Dialog */}
      <Dialog open={showRejectDialog} onOpenChange={setShowRejectDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reject Application</DialogTitle>
            <DialogDescription>
              Please provide a reason for rejecting this delivery partner application.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Label htmlFor="rejection-reason">Rejection Reason</Label>
            <Textarea
              id="rejection-reason"
              placeholder="Enter the reason for rejection..."
              value={rejectionReason}
              onChange={(e) => setRejectionReason(e.target.value)}
              className="mt-2"
            />
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowRejectDialog(false);
                setRejectionReason("");
                setSelectedPartner(null);
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={confirmReject}
              disabled={!rejectionReason.trim() || rejectPartner.isPending}
            >
              {rejectPartner.isPending ? "Rejecting..." : "Reject Application"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}