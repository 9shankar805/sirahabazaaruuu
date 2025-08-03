import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Form, FormControl, FormField, FormItem, FormLabel } from "@/components/ui/form";
import { Badge } from "@/components/ui/badge";
import { Zap, Clock, Percent, Edit, Trash2, Plus, ShieldAlert } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

interface FlashSale {
  id: number;
  title: string;
  description: string | null;
  discountPercentage: number;
  startsAt: string;
  endsAt: string;
  isActive: boolean;
  createdAt: string;
}

interface Product {
  id: number;
  name: string;
  price: string;
  imageUrl: string;
  isFastSell: boolean;
}

const flashSaleSchema = z.object({
  title: z.string().min(1, "Title is required"),
  description: z.string().optional(),
  discountPercentage: z.number().min(1).max(99),
  startsAt: z.string(),
  endsAt: z.string(),
  isActive: z.boolean().default(true),
});

type FlashSaleFormData = z.infer<typeof flashSaleSchema>;

export default function FlashSales() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [editingFlashSale, setEditingFlashSale] = useState<FlashSale | null>(null);
  const [selectedFlashSaleId, setSelectedFlashSaleId] = useState<number | null>(null);
  const [adminUser, setAdminUser] = useState<any>(null);
  const [isAdmin, setIsAdmin] = useState(false);

  // Check if user is admin
  useEffect(() => {
    const stored = localStorage.getItem("adminUser");
    if (stored && stored !== "undefined" && stored !== "null") {
      try {
        const adminData = JSON.parse(stored);
        setAdminUser(adminData);
        setIsAdmin(true);
      } catch (error) {
        console.error('Error parsing admin user data:', error);
        setIsAdmin(false);
      }
    } else {
      setIsAdmin(false);
    }
  }, []);

  const form = useForm<FlashSaleFormData>({
    resolver: zodResolver(flashSaleSchema),
    defaultValues: {
      title: "",
      description: "",
      discountPercentage: 10,
      startsAt: new Date().toISOString().slice(0, 16),
      endsAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 16),
      isActive: true,
    },
  });

  // Fetch all flash sales
  const { data: flashSales, isLoading: flashSalesLoading } = useQuery<FlashSale[]>({
    queryKey: ["/api/flash-sales"],
  });

  // Fetch active flash sales
  const { data: activeFlashSales } = useQuery<FlashSale[]>({
    queryKey: ["/api/flash-sales/active"],
  });

  // Fetch flash sale products
  const { data: flashSaleProducts } = useQuery<Product[]>({
    queryKey: ["/api/flash-sales", selectedFlashSaleId, "products"],
    enabled: !!selectedFlashSaleId,
  });

  // Create flash sale mutation
  const createFlashSaleMutation = useMutation({
    mutationFn: (data: FlashSaleFormData) =>
      apiRequest("/api/admin/flash-sales", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/flash-sales"] });
      setIsCreateDialogOpen(false);
      form.reset();
      toast({
        title: "Success",
        description: "Flash sale created successfully",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to create flash sale",
        variant: "destructive",
      });
    },
  });

  // Update flash sale mutation
  const updateFlashSaleMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<FlashSaleFormData> }) =>
      apiRequest(`/api/admin/flash-sales/${id}`, {
        method: "PUT",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/flash-sales"] });
      setEditingFlashSale(null);
      form.reset();
      toast({
        title: "Success",
        description: "Flash sale updated successfully",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to update flash sale",
        variant: "destructive",
      });
    },
  });

  // Delete flash sale mutation
  const deleteFlashSaleMutation = useMutation({
    mutationFn: (id: number) =>
      apiRequest(`/api/admin/flash-sales/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/flash-sales"] });
      toast({
        title: "Success",
        description: "Flash sale deleted successfully",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to delete flash sale",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: FlashSaleFormData) => {
    const formattedData = {
      ...data,
      startsAt: new Date(data.startsAt).toISOString(),
      endsAt: new Date(data.endsAt).toISOString(),
    };

    if (editingFlashSale) {
      updateFlashSaleMutation.mutate({ id: editingFlashSale.id, data: formattedData });
    } else {
      createFlashSaleMutation.mutate(formattedData);
    }
  };

  const handleEdit = (flashSale: FlashSale) => {
    setEditingFlashSale(flashSale);
    form.reset({
      title: flashSale.title,
      description: flashSale.description || "",
      discountPercentage: flashSale.discountPercentage,
      startsAt: new Date(flashSale.startsAt).toISOString().slice(0, 16),
      endsAt: new Date(flashSale.endsAt).toISOString().slice(0, 16),
      isActive: flashSale.isActive,
    });
    setIsCreateDialogOpen(true);
  };

  const handleDelete = (id: number) => {
    if (confirm("Are you sure you want to delete this flash sale?")) {
      deleteFlashSaleMutation.mutate(id);
    }
  };

  const isFlashSaleActive = (flashSale: FlashSale) => {
    const now = new Date();
    const startDate = new Date(flashSale.startsAt);
    const endDate = new Date(flashSale.endsAt);
    return flashSale.isActive && now >= startDate && now <= endDate;
  };

  const formatDateTime = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  if (flashSalesLoading) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="text-center">Loading flash sales...</div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Warning for non-admin users */}
      {!isAdmin && (
        <Card className="mb-6 border-orange-200 bg-orange-50">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <ShieldAlert className="h-5 w-5 text-orange-600" />
              <div>
                <p className="text-sm font-medium text-orange-800">
                  Read-Only Access
                </p>
                <p className="text-sm text-orange-600">
                  You can view flash sales but cannot create, edit, or delete them. Admin access required for management.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
      
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Zap className="h-8 w-8 text-yellow-500" />
            Flash Sales
          </h1>
          <p className="text-gray-600">
            {isAdmin ? "Manage time-limited promotional sales" : "Browse current flash sales and discounts"}
          </p>
        </div>
        {isAdmin && (
          <Button
            onClick={() => {
              setEditingFlashSale(null);
              form.reset();
              setIsCreateDialogOpen(true);
            }}
            className="flex items-center gap-2"
          >
            <Plus className="h-4 w-4" />
            Create Flash Sale
          </Button>
        )}
      </div>

      {/* Active Flash Sales Section */}
      {activeFlashSales && activeFlashSales.length > 0 && (
        <div className="mb-8">
          <h2 className="text-2xl font-semibold mb-4 flex items-center gap-2">
            <Clock className="h-6 w-6 text-green-500" />
            Currently Active
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {activeFlashSales.map((flashSale) => (
              <Card key={flashSale.id} className="border-green-200 bg-green-50">
                <CardHeader className="pb-3">
                  <div className="flex justify-between items-start">
                    <CardTitle className="text-lg">{flashSale.title}</CardTitle>
                    <Badge variant="default" className="bg-green-500">
                      <Percent className="h-3 w-3 mr-1" />
                      {flashSale.discountPercentage}% OFF
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  {flashSale.description && (
                    <p className="text-sm text-gray-600 mb-3">{flashSale.description}</p>
                  )}
                  <div className="space-y-2 text-sm">
                    <div>
                      <span className="font-medium">Ends:</span>{" "}
                      {formatDateTime(flashSale.endsAt)}
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-3 w-full"
                    onClick={() => setSelectedFlashSaleId(flashSale.id)}
                  >
                    View Products
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* All Flash Sales Section */}
      <div>
        <h2 className="text-2xl font-semibold mb-4">All Flash Sales</h2>
        {!flashSales || flashSales.length === 0 ? (
          <Card>
            <CardContent className="text-center py-8">
              <Zap className="h-12 w-12 text-gray-300 mx-auto mb-4" />
              <p className="text-gray-500">
                {isAdmin ? "No flash sales created yet" : "No flash sales available at the moment"}
              </p>
              {isAdmin && (
                <Button
                  onClick={() => setIsCreateDialogOpen(true)}
                  className="mt-4"
                >
                  Create Your First Flash Sale
                </Button>
              )}
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {flashSales.map((flashSale) => (
              <Card key={flashSale.id} className={isFlashSaleActive(flashSale) ? "border-yellow-200" : ""}>
                <CardHeader className="pb-3">
                  <div className="flex justify-between items-start">
                    <CardTitle className="text-lg">{flashSale.title}</CardTitle>
                    <div className="flex items-center gap-2">
                      <Badge variant={isFlashSaleActive(flashSale) ? "default" : "secondary"}>
                        <Percent className="h-3 w-3 mr-1" />
                        {flashSale.discountPercentage}% OFF
                      </Badge>
                      {isFlashSaleActive(flashSale) && (
                        <Badge variant="default" className="bg-green-500">Live</Badge>
                      )}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  {flashSale.description && (
                    <p className="text-sm text-gray-600 mb-3">{flashSale.description}</p>
                  )}
                  <div className="space-y-2 text-sm">
                    <div>
                      <span className="font-medium">Starts:</span>{" "}
                      {formatDateTime(flashSale.startsAt)}
                    </div>
                    <div>
                      <span className="font-medium">Ends:</span>{" "}
                      {formatDateTime(flashSale.endsAt)}
                    </div>
                    <div>
                      <span className="font-medium">Status:</span>{" "}
                      <Badge variant={flashSale.isActive ? "default" : "secondary"}>
                        {flashSale.isActive ? "Active" : "Inactive"}
                      </Badge>
                    </div>
                  </div>
                  {isAdmin && (
                    <div className="flex gap-2 mt-4">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleEdit(flashSale)}
                        className="flex-1"
                      >
                        <Edit className="h-4 w-4 mr-1" />
                        Edit
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleDelete(flashSale.id)}
                        className="text-red-600 hover:text-red-700"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* Create/Edit Flash Sale Dialog */}
      <Dialog
        open={isCreateDialogOpen}
        onOpenChange={(open) => {
          setIsCreateDialogOpen(open);
          if (!open) {
            setEditingFlashSale(null);
            form.reset();
          }
        }}
      >
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>
              {editingFlashSale ? "Edit Flash Sale" : "Create Flash Sale"}
            </DialogTitle>
          </DialogHeader>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="title"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Title</FormLabel>
                    <FormControl>
                      <Input placeholder="e.g., Weekend Flash Sale" {...field} />
                    </FormControl>
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="description"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Description (Optional)</FormLabel>
                    <FormControl>
                      <Textarea 
                        placeholder="Brief description of the flash sale..."
                        {...field}
                      />
                    </FormControl>
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="discountPercentage"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Discount Percentage</FormLabel>
                    <FormControl>
                      <Input
                        type="number"
                        min="1"
                        max="99"
                        {...field}
                        onChange={(e) => field.onChange(parseInt(e.target.value))}
                      />
                    </FormControl>
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="startsAt"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Start Date & Time</FormLabel>
                    <FormControl>
                      <Input type="datetime-local" {...field} />
                    </FormControl>
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="endsAt"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>End Date & Time</FormLabel>
                    <FormControl>
                      <Input type="datetime-local" {...field} />
                    </FormControl>
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="isActive"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                    <div className="space-y-0.5">
                      <FormLabel className="text-base">Active</FormLabel>
                      <div className="text-sm text-muted-foreground">
                        Enable this flash sale
                      </div>
                    </div>
                    <FormControl>
                      <input
                        type="checkbox"
                        checked={field.value}
                        onChange={field.onChange}
                        className="w-4 h-4"
                      />
                    </FormControl>
                  </FormItem>
                )}
              />

              <div className="flex gap-3 pt-4">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setIsCreateDialogOpen(false)}
                  className="flex-1"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={createFlashSaleMutation.isPending || updateFlashSaleMutation.isPending}
                  className="flex-1"
                >
                  {editingFlashSale ? "Update" : "Create"}
                </Button>
              </div>
            </form>
          </Form>
        </DialogContent>
      </Dialog>

      {/* Flash Sale Products Dialog */}
      {selectedFlashSaleId && (
        <Dialog
          open={!!selectedFlashSaleId}
          onOpenChange={() => setSelectedFlashSaleId(null)}
        >
          <DialogContent className="max-w-4xl">
            <DialogHeader>
              <DialogTitle>Flash Sale Products</DialogTitle>
            </DialogHeader>
            <div className="max-h-96 overflow-y-auto">
              {!flashSaleProducts || flashSaleProducts.length === 0 ? (
                <div className="text-center py-8">
                  <p className="text-gray-500">No fast-sell products available for this flash sale</p>
                  <p className="text-sm text-gray-400 mt-2">
                    Products marked as "Fast Sell" will appear here
                  </p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {flashSaleProducts.map((product) => (
                    <Card key={product.id}>
                      <CardContent className="p-4">
                        <img
                          src={product.imageUrl || "/placeholder-product.jpg"}
                          alt={product.name}
                          className="w-full h-32 object-cover rounded mb-3"
                        />
                        <h3 className="font-medium text-sm mb-1">{product.name}</h3>
                        <p className="text-lg font-bold text-primary">₹{product.price}</p>
                        <Badge variant="secondary" className="mt-2">
                          Fast Sell
                        </Badge>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}