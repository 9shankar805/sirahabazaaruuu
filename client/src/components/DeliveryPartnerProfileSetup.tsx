import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { useToast } from "@/hooks/use-toast";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Truck, FileText, CreditCard, Phone, MapPin, AlertCircle } from "lucide-react";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";

const deliveryPartnerProfileSchema = z.object({
  vehicleType: z.string().min(1, "Vehicle type is required"),
  vehicleNumber: z.string().min(1, "Vehicle number is required"),
  drivingLicense: z.string().min(1, "Driving license number is required"),
  idProofType: z.string().min(1, "ID proof type is required"),
  idProofNumber: z.string().min(1, "ID proof number is required"),
  deliveryAreas: z.string().min(1, "Delivery areas are required"),
  emergencyContact: z.string().min(10, "Emergency contact number is required"),
  bankAccountNumber: z.string().min(10, "Bank account number is required"),
  ifscCode: z.string().min(11, "IFSC code is required"),
  termsAccepted: z.boolean().refine(val => val === true, {
    message: "You must accept the terms and conditions"
  }),
});

type DeliveryPartnerProfileData = z.infer<typeof deliveryPartnerProfileSchema>;

interface DeliveryPartnerProfileSetupProps {
  userId: number;
}

export default function DeliveryPartnerProfileSetup({ userId }: DeliveryPartnerProfileSetupProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const form = useForm<DeliveryPartnerProfileData>({
    resolver: zodResolver(deliveryPartnerProfileSchema),
    defaultValues: {
      vehicleType: "",
      vehicleNumber: "",
      drivingLicense: "",
      idProofType: "",
      idProofNumber: "",
      deliveryAreas: "",
      emergencyContact: "",
      bankAccountNumber: "",
      ifscCode: "",
      termsAccepted: false,
    },
  });

  const createProfile = useMutation({
    mutationFn: async (data: DeliveryPartnerProfileData) => {
      const profileData = {
        userId,
        vehicleType: data.vehicleType,
        vehicleNumber: data.vehicleNumber,
        drivingLicense: data.drivingLicense,
        idProofType: data.idProofType,
        idProofNumber: data.idProofNumber,
        deliveryAreas: data.deliveryAreas.split(',').map(area => area.trim()).filter(area => area.length > 0),
        emergencyContact: data.emergencyContact,
        bankAccountNumber: data.bankAccountNumber,
        ifscCode: data.ifscCode,
      };

      const response = await fetch('/api/delivery-partners/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(profileData),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to create delivery partner profile');
      }

      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/delivery-partners/user'] });
      toast({
        title: "Profile Created Successfully!",
        description: "Your delivery partner profile has been created and is pending admin approval.",
      });
    },
    onError: (error) => {
      toast({
        title: "Profile Creation Failed",
        description: error instanceof Error ? error.message : "Failed to create profile",
        variant: "destructive",
      });
    },
  });

  const onSubmit = async (data: DeliveryPartnerProfileData) => {
    setIsSubmitting(true);
    try {
      await createProfile.mutateAsync(data);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-6">
      <div className="max-w-2xl mx-auto">
        <div className="text-center mb-8">
          <div className="p-4 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-full w-20 h-20 mx-auto mb-4 flex items-center justify-center">
            <Truck className="h-10 w-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-gray-800 mb-2">Complete Your Delivery Partner Profile</h1>
          <p className="text-gray-600">Please provide the required information to start accepting deliveries</p>
        </div>

        <Card className="shadow-xl border-0">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              Delivery Partner Information
            </CardTitle>
            <CardDescription>
              All fields are required for account verification and approval
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                {/* Vehicle Information */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-gray-800 flex items-center gap-2">
                    <Truck className="h-5 w-5" />
                    Vehicle Information
                  </h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <FormField
                      control={form.control}
                      name="vehicleType"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Vehicle Type</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger>
                                <SelectValue placeholder="Select vehicle type" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="bicycle">Bicycle</SelectItem>
                              <SelectItem value="motorcycle">Motorcycle</SelectItem>
                              <SelectItem value="scooter">Scooter</SelectItem>
                              <SelectItem value="car">Car</SelectItem>
                              <SelectItem value="van">Van</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="vehicleNumber"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Vehicle Number</FormLabel>
                          <FormControl>
                            <Input placeholder="e.g., BA-1-PA-1234" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>

                  <FormField
                    control={form.control}
                    name="drivingLicense"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Driving License Number</FormLabel>
                        <FormControl>
                          <Input placeholder="Enter your driving license number" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                {/* Identity Verification */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-gray-800 flex items-center gap-2">
                    <FileText className="h-5 w-5" />
                    Identity Verification
                  </h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <FormField
                      control={form.control}
                      name="idProofType"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>ID Proof Type</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger>
                                <SelectValue placeholder="Select ID proof type" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="aadhar">Aadhar Card</SelectItem>
                              <SelectItem value="pan">PAN Card</SelectItem>
                              <SelectItem value="passport">Passport</SelectItem>
                              <SelectItem value="voter_id">Voter ID</SelectItem>
                              <SelectItem value="driving_license">Driving License</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="idProofNumber"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>ID Proof Number</FormLabel>
                          <FormControl>
                            <Input placeholder="Enter your ID proof number" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>
                </div>

                {/* Service Areas */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-gray-800 flex items-center gap-2">
                    <MapPin className="h-5 w-5" />
                    Service Information
                  </h3>
                  
                  <FormField
                    control={form.control}
                    name="deliveryAreas"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Delivery Areas</FormLabel>
                        <FormControl>
                          <Textarea 
                            placeholder="Enter delivery areas separated by commas (e.g., Siraha, Lahan, Mirchaiya)" 
                            className="min-h-[100px]"
                            {...field} 
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                {/* Contact & Banking */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-gray-800 flex items-center gap-2">
                    <Phone className="h-5 w-5" />
                    Contact & Banking
                  </h3>
                  
                  <FormField
                    control={form.control}
                    name="emergencyContact"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Emergency Contact Number</FormLabel>
                        <FormControl>
                          <Input placeholder="Enter emergency contact number" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <FormField
                      control={form.control}
                      name="bankAccountNumber"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Bank Account Number</FormLabel>
                          <FormControl>
                            <Input placeholder="Enter bank account number" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="ifscCode"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>IFSC Code</FormLabel>
                          <FormControl>
                            <Input placeholder="Enter IFSC code" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>
                </div>

                {/* Terms & Conditions */}
                <div className="space-y-4">
                  <FormField
                    control={form.control}
                    name="termsAccepted"
                    render={({ field }) => (
                      <FormItem className="flex flex-row items-start space-x-3 space-y-0">
                        <FormControl>
                          <Checkbox
                            checked={field.value}
                            onCheckedChange={field.onChange}
                          />
                        </FormControl>
                        <div className="space-y-1 leading-none">
                          <FormLabel>
                            I accept the terms and conditions for delivery partners
                          </FormLabel>
                          <FormMessage />
                        </div>
                      </FormItem>
                    )}
                  />
                </div>

                {/* Important Note */}
                <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <AlertCircle className="h-5 w-5 text-amber-600 mt-0.5" />
                    <div>
                      <h4 className="font-medium text-amber-800">Important</h4>
                      <p className="text-sm text-amber-700 mt-1">
                        Your profile will be reviewed by our admin team. You'll receive a notification once your account is approved and you can start accepting deliveries.
                      </p>
                    </div>
                  </div>
                </div>

                <Button 
                  type="submit" 
                  className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700" 
                  disabled={isSubmitting || createProfile.isPending}
                >
                  {isSubmitting || createProfile.isPending ? "Creating Profile..." : "Create Delivery Partner Profile"}
                </Button>
              </form>
            </Form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}