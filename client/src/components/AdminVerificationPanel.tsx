
import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { CheckCircle, XCircle, Clock, User, Phone, MapPin, Car } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface PendingDeliveryPartner {
  id: number;
  userId: number;
  vehicleType: string;
  vehicleNumber: string;
  deliveryArea: string;
  idProofUrl: string;
  drivingLicenseUrl?: string;
  status: string;
  user: {
    fullName: string;
    email: string;
    phone: string;
    address: string;
  };
}

interface AdminVerificationPanelProps {
  isAdmin?: boolean;
  onVerificationComplete?: () => void;
}

export default function AdminVerificationPanel({ isAdmin = false, onVerificationComplete }: AdminVerificationPanelProps) {
  const [pendingPartners, setPendingPartners] = useState<PendingDeliveryPartner[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<number | null>(null);
  const [rejectionReason, setRejectionReason] = useState<string>("");
  const [showRejectionForm, setShowRejectionForm] = useState<number | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    fetchPendingPartners();
  }, []);

  const fetchPendingPartners = async () => {
    try {
      const response = await fetch('/api/delivery-partners');
      if (response.ok) {
        const partners = await response.json();
        const pending = partners.filter((p: any) => p.status === 'pending');
        setPendingPartners(pending);
      }
    } catch (error) {
      console.error('Failed to fetch pending partners:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (partnerId: number) => {
    setActionLoading(partnerId);
    try {
      const response = await fetch(`/api/delivery-partners/${partnerId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ adminId: 1 }) // You can make this dynamic
      });

      if (response.ok) {
        toast({
          title: "Partner Approved",
          description: "Delivery partner has been approved successfully.",
        });
        await fetchPendingPartners();
        onVerificationComplete?.();
      } else {
        throw new Error('Failed to approve partner');
      }
    } catch (error) {
      toast({
        title: "Approval Failed",
        description: "Failed to approve delivery partner.",
        variant: "destructive",
      });
    } finally {
      setActionLoading(null);
    }
  };

  const handleReject = async (partnerId: number) => {
    if (!rejectionReason.trim()) {
      toast({
        title: "Rejection Reason Required",
        description: "Please provide a reason for rejection.",
        variant: "destructive",
      });
      return;
    }

    setActionLoading(partnerId);
    try {
      const response = await fetch(`/api/delivery-partners/${partnerId}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          adminId: 1, // You can make this dynamic
          reason: rejectionReason 
        })
      });

      if (response.ok) {
        toast({
          title: "Partner Rejected",
          description: "Delivery partner application has been rejected.",
        });
        await fetchPendingPartners();
        setShowRejectionForm(null);
        setRejectionReason("");
        onVerificationComplete?.();
      } else {
        throw new Error('Failed to reject partner');
      }
    } catch (error) {
      toast({
        title: "Rejection Failed",
        description: "Failed to reject delivery partner.",
        variant: "destructive",
      });
    } finally {
      setActionLoading(null);
    }
  };

  if (!isAdmin) {
    return null;
  }

  if (loading) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Loading Pending Applications...
          </CardTitle>
        </CardHeader>
      </Card>
    );
  }

  if (pendingPartners.length === 0) {
    return (
      <Card className="w-full">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <CheckCircle className="h-5 w-5 text-green-500" />
            No Pending Applications
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">
            All delivery partner applications have been processed.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5 text-orange-500" />
            Pending Delivery Partner Applications ({pendingPartners.length})
          </CardTitle>
        </CardHeader>
      </Card>

      {pendingPartners.map((partner) => (
        <Card key={partner.id} className="w-full">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <User className="h-5 w-5" />
                {partner.user.fullName}
              </CardTitle>
              <Badge variant="outline" className="text-orange-600 border-orange-600">
                <Clock className="h-3 w-3 mr-1" />
                Pending Review
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <h4 className="font-semibold">Contact Information</h4>
                <div className="space-y-1 text-sm">
                  <p className="flex items-center gap-2">
                    <User className="h-4 w-4" />
                    {partner.user.email}
                  </p>
                  <p className="flex items-center gap-2">
                    <Phone className="h-4 w-4" />
                    {partner.user.phone}
                  </p>
                  <p className="flex items-center gap-2">
                    <MapPin className="h-4 w-4" />
                    {partner.user.address}
                  </p>
                </div>
              </div>

              <div className="space-y-2">
                <h4 className="font-semibold">Vehicle Information</h4>
                <div className="space-y-1 text-sm">
                  <p className="flex items-center gap-2">
                    <Car className="h-4 w-4" />
                    {partner.vehicleType} - {partner.vehicleNumber}
                  </p>
                  <p className="flex items-center gap-2">
                    <MapPin className="h-4 w-4" />
                    Delivery Area: {partner.deliveryArea}
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="font-semibold">Documents</h4>
              <div className="flex gap-2">
                {partner.idProofUrl && (
                  <Button variant="outline" size="sm" asChild>
                    <a href={partner.idProofUrl} target="_blank" rel="noopener noreferrer">
                      View ID Proof
                    </a>
                  </Button>
                )}
                {partner.drivingLicenseUrl && (
                  <Button variant="outline" size="sm" asChild>
                    <a href={partner.drivingLicenseUrl} target="_blank" rel="noopener noreferrer">
                      View Driving License
                    </a>
                  </Button>
                )}
              </div>
            </div>

            {showRejectionForm === partner.id ? (
              <div className="space-y-3 p-4 border rounded-lg bg-red-50 dark:bg-red-950">
                <h4 className="font-semibold text-red-800 dark:text-red-200">
                  Rejection Reason
                </h4>
                <Textarea
                  placeholder="Please provide a detailed reason for rejection..."
                  value={rejectionReason}
                  onChange={(e) => setRejectionReason(e.target.value)}
                />
                <div className="flex gap-2">
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => handleReject(partner.id)}
                    disabled={actionLoading === partner.id}
                  >
                    {actionLoading === partner.id ? "Rejecting..." : "Confirm Rejection"}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setShowRejectionForm(null);
                      setRejectionReason("");
                    }}
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            ) : (
              <div className="flex gap-2">
                <Button
                  onClick={() => handleApprove(partner.id)}
                  disabled={actionLoading === partner.id}
                  className="bg-green-600 hover:bg-green-700"
                >
                  <CheckCircle className="h-4 w-4 mr-2" />
                  {actionLoading === partner.id ? "Approving..." : "Approve"}
                </Button>
                <Button
                  variant="destructive"
                  onClick={() => setShowRejectionForm(partner.id)}
                  disabled={actionLoading === partner.id}
                >
                  <XCircle className="h-4 w-4 mr-2" />
                  Reject
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
