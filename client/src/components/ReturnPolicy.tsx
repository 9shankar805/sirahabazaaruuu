import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { RefreshCw, Package, Clock, CheckCircle } from "lucide-react";
import type { ReturnPolicy, Return } from "@shared/schema";

interface ReturnPolicyProps {
  storeId?: number;
  customerId?: number;
  orderItems?: any[];
}

export default function ReturnPolicyComponent({ storeId, customerId, orderItems }: ReturnPolicyProps) {
  const [returnForm, setReturnForm] = useState({
    orderId: "",
    orderItemId: "",
    reason: "",
    description: "",
  });
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Fetch return policy for store
  const { data: returnPolicy } = useQuery<ReturnPolicy>({
    queryKey: ["/api/stores", storeId, "return-policy"],
    queryFn: async () => {
      const response = await fetch(`/api/stores/${storeId}/return-policy`);
      if (!response.ok) throw new Error("Failed to fetch return policy");
      return response.json();
    },
    enabled: !!storeId,
  });

  // Fetch customer returns
  const { data: customerReturns } = useQuery<Return[]>({
    queryKey: ["/api/returns/customer", customerId],
    queryFn: async () => {
      const response = await fetch(`/api/returns/customer/${customerId}`);
      if (!response.ok) throw new Error("Failed to fetch returns");
      return response.json();
    },
    enabled: !!customerId,
  });

  // Create return request
  const createReturnMutation = useMutation({
    mutationFn: async (returnData: any) => {
      const response = await fetch("/api/returns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...returnData,
          customerId,
        }),
      });
      if (!response.ok) throw new Error("Failed to create return request");
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/returns/customer", customerId] });
      setReturnForm({ orderId: "", orderItemId: "", reason: "", description: "" });
      toast({
        title: "Success",
        description: "Return request submitted successfully",
      });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleReturnSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createReturnMutation.mutate(returnForm);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "requested":
        return "bg-yellow-100 text-yellow-800";
      case "approved":
        return "bg-green-100 text-green-800";
      case "rejected":
        return "bg-red-100 text-red-800";
      case "completed":
        return "bg-blue-100 text-blue-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "requested":
        return <Clock className="h-4 w-4" />;
      case "approved":
        return <CheckCircle className="h-4 w-4" />;
      case "rejected":
        return <RefreshCw className="h-4 w-4" />;
      case "completed":
        return <Package className="h-4 w-4" />;
      default:
        return <Clock className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Return Policy Display */}
      {storeId && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <RefreshCw className="h-5 w-5" />
              Return Policy
            </CardTitle>
            <CardDescription>Our return policy and guidelines</CardDescription>
          </CardHeader>
          <CardContent>
            {returnPolicy ? (
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 bg-blue-50 rounded-lg">
                    <h3 className="font-semibold text-blue-900 mb-2">Return Period</h3>
                    <p className="text-blue-700">
                      {returnPolicy.returnDays} days from delivery
                    </p>
                  </div>
                  
                  <div className="p-4 bg-green-50 rounded-lg">
                    <h3 className="font-semibold text-green-900 mb-2">Status</h3>
                    <p className="text-green-700">
                      {returnPolicy.isActive ? "Active" : "Inactive"}
                    </p>
                  </div>
                </div>

                {returnPolicy.returnConditions && (
                  <div>
                    <h3 className="font-semibold mb-2">Return Conditions</h3>
                    <p className="text-gray-600 text-sm whitespace-pre-wrap">
                      {returnPolicy.returnConditions}
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <RefreshCw className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                <p>No return policy available for this store</p>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Return Request Form */}
      {customerId && (
        <Card>
          <CardHeader>
            <CardTitle>Request Return</CardTitle>
            <CardDescription>Submit a return request for your order</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleReturnSubmit} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="orderId">Order ID</Label>
                  <Input
                    id="orderId"
                    value={returnForm.orderId}
                    onChange={(e) => setReturnForm({ ...returnForm, orderId: e.target.value })}
                    placeholder="Enter order ID"
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="orderItemId">Order Item ID</Label>
                  <Input
                    id="orderItemId"
                    value={returnForm.orderItemId}
                    onChange={(e) => setReturnForm({ ...returnForm, orderItemId: e.target.value })}
                    placeholder="Enter item ID"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="reason">Reason for Return</Label>
                <Input
                  id="reason"
                  value={returnForm.reason}
                  onChange={(e) => setReturnForm({ ...returnForm, reason: e.target.value })}
                  placeholder="e.g., Damaged item, Wrong size, etc."
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="description">Description (Optional)</Label>
                <Textarea
                  id="description"
                  value={returnForm.description}
                  onChange={(e) => setReturnForm({ ...returnForm, description: e.target.value })}
                  placeholder="Provide additional details about the return..."
                  rows={3}
                />
              </div>

              <Button
                type="submit"
                className="w-full"
                disabled={createReturnMutation.isPending}
              >
                {createReturnMutation.isPending ? "Submitting..." : "Submit Return Request"}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Customer Returns History */}
      {customerId && customerReturns && (
        <Card>
          <CardHeader>
            <CardTitle>Your Returns</CardTitle>
            <CardDescription>Track your return requests</CardDescription>
          </CardHeader>
          <CardContent>
            {customerReturns.length === 0 ? (
              <div className="text-center py-8 text-gray-500">
                <Package className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                <p>No return requests found</p>
                <p className="text-sm">Your return requests will appear here</p>
              </div>
            ) : (
              <div className="space-y-4">
                {customerReturns.map((returnItem) => (
                  <div key={returnItem.id} className="p-4 border rounded-lg">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold">Return #{returnItem.id}</h3>
                        <Badge className={getStatusColor(returnItem.status)}>
                          <div className="flex items-center gap-1">
                            {getStatusIcon(returnItem.status)}
                            <span className="capitalize">{returnItem.status}</span>
                          </div>
                        </Badge>
                      </div>
                      <span className="text-sm text-gray-500">
                        {new Date(returnItem.createdAt).toLocaleDateString()}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="font-medium">Order ID:</span> #{returnItem.orderId}
                      </div>
                      <div>
                        <span className="font-medium">Reason:</span> {returnItem.reason}
                      </div>
                    </div>

                    {returnItem.description && (
                      <div className="mt-3 text-sm">
                        <span className="font-medium">Description:</span>
                        <p className="text-gray-600 mt-1">{returnItem.description}</p>
                      </div>
                    )}

                    {returnItem.refundAmount && (
                      <div className="mt-3 text-sm">
                        <span className="font-medium">Refund Amount:</span>
                        <span className="text-green-600 font-semibold ml-1">
                          ₹{returnItem.refundAmount}
                        </span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}