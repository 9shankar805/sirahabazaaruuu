import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { useToast } from "@/hooks/use-toast";
import { useLocation } from "wouter";
import { Truck, CheckCircle, Upload, FileText } from "lucide-react";
import DocumentUpload from "@/components/DocumentUpload";

const deliveryPartnerSchema = z.object({
  fullName: z.string().min(2, "Full name must be at least 2 characters"),
  email: z.string().email("Please enter a valid email address"),
  phone: z.string().min(10, "Phone number must be at least 10 digits"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  confirmPassword: z.string(),
  address: z.string().min(5, "Address is required"),
  vehicleType: z.string().min(1, "Vehicle type is required"),
  vehicleNumber: z.string().min(1, "Vehicle number is required"),
  deliveryArea: z.string().min(1, "Delivery area is required"),
  idProofUrl: z.string().min(1, "ID proof is required"),
  drivingLicenseUrl: z.string().min(1, "Driving license is required"),
  vehicleRegistrationUrl: z.string().optional(),
  insuranceUrl: z.string().optional(),
  photoUrl: z.string().min(1, "Profile photo is required"),
  termsAccepted: z.boolean().refine(val => val === true, {
    message: "You must accept the terms and conditions"
  }),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

type DeliveryPartnerForm = z.infer<typeof deliveryPartnerSchema>;

export default function DeliveryPartnerQuickReg() {
  const [isLoading, setIsLoading] = useState(false);
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [documents, setDocuments] = useState<Record<string, string>>({});

  const handleDocumentChange = (field: string, value: string) => {
    setDocuments(prev => ({ ...prev, [field]: value }));
    form.setValue(field as keyof DeliveryPartnerForm, value);
  };

  const form = useForm<DeliveryPartnerForm>({
    resolver: zodResolver(deliveryPartnerSchema),
    defaultValues: {
      fullName: "",
      email: "",
      phone: "",
      password: "",
      confirmPassword: "",
      address: "",
      vehicleType: "",
      vehicleNumber: "",
      deliveryArea: "",
      idProofUrl: "",
      drivingLicenseUrl: "",
      vehicleRegistrationUrl: "",
      insuranceUrl: "",
      photoUrl: "",
      termsAccepted: false,
    },
  });

  const onSubmit = async (data: DeliveryPartnerForm) => {
    setIsLoading(true);
    try {
      // First create user account
      const userResponse = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fullName: data.fullName,
          email: data.email,
          phone: data.phone,
          password: data.password,
          address: data.address,
          role: 'delivery_partner',
        }),
      });

      if (!userResponse.ok) {
        const error = await userResponse.json();
        if (error.error?.includes('User already exists')) {
          if (error.error.includes('email')) {
            throw new Error('An account with this email already exists. Please use a different email address or login to your existing account.');
          } else if (error.error.includes('phone')) {
            throw new Error('An account with this phone number already exists. Please use a different phone number or login to your existing account.');
          } else {
            throw new Error('An account with these credentials already exists. Please use different information or login to your existing account.');
          }
        }
        throw new Error(error.error || 'Registration failed');
      }

      const userResult = await userResponse.json();

      // Create delivery partner profile with all document data
      const deliveryPartnerData = {
        userId: userResult.user.id,
        vehicleType: data.vehicleType,
        vehicleNumber: data.vehicleNumber,
        deliveryArea: data.deliveryArea,
        idProofUrl: data.idProofUrl,
        drivingLicenseUrl: data.drivingLicenseUrl,
        vehicleRegistrationUrl: data.vehicleRegistrationUrl,
        insuranceUrl: data.insuranceUrl,
        photoUrl: data.photoUrl,
      };

      const partnerResponse = await fetch('/api/delivery-partners/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(deliveryPartnerData),
      });

      if (!partnerResponse.ok) {
        throw new Error('Failed to create delivery partner profile');
      }

      toast({
        title: "Registration Successful!",
        description: "Your delivery partner application has been submitted. You'll be notified once approved.",
      });

      // Redirect to login or dashboard
      setLocation('/login');
    } catch (error) {
      console.error('Registration error:', error);
      const errorMessage = error instanceof Error ? error.message : "Something went wrong. Please try again.";
      
      toast({
        title: "Registration Failed",
        description: errorMessage,
        variant: "destructive",
      });
      
      // If it's a duplicate user error, suggest alternative actions
      if (errorMessage.includes('already exists')) {
        setTimeout(() => {
          toast({
            title: "Need Help?",
            description: "If you already have an account, try logging in instead. If you need to update your role to delivery partner, contact support.",
          });
        }, 3000);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 flex items-center justify-center p-4">
      <Card className="w-full max-w-2xl">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-blue-600">
            <Truck className="h-6 w-6 text-white" />
          </div>
          <CardTitle className="text-2xl font-bold">Join as Delivery Partner</CardTitle>
          <CardDescription>
            Complete your registration to start earning with flexible delivery work
          </CardDescription>
        </CardHeader>

        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              {/* Personal Information */}
              <div className="space-y-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Personal Information
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="fullName"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Full Name *</FormLabel>
                        <FormControl>
                          <Input placeholder="Enter your full name" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="phone"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Phone Number *</FormLabel>
                        <FormControl>
                          <Input placeholder="9876543210" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                <FormField
                  control={form.control}
                  name="email"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Email Address *</FormLabel>
                      <FormControl>
                        <Input placeholder="your.email@example.com" type="email" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="address"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Address *</FormLabel>
                      <FormControl>
                        <Textarea placeholder="Enter your complete address" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Password *</FormLabel>
                        <FormControl>
                          <Input placeholder="Create password" type="password" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="confirmPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Confirm Password *</FormLabel>
                        <FormControl>
                          <Input placeholder="Confirm password" type="password" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
              </div>

              {/* Delivery Information */}
              <div className="space-y-4 border-t pt-4">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Delivery Information
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="vehicleType"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Vehicle Type *</FormLabel>
                        <Select onValueChange={field.onChange} value={field.value}>
                          <FormControl>
                            <SelectTrigger>
                              <SelectValue placeholder="Select vehicle type" />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            <SelectItem value="motorcycle">Motorcycle</SelectItem>
                            <SelectItem value="bicycle">Bicycle</SelectItem>
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
                        <FormLabel>Vehicle Number *</FormLabel>
                        <FormControl>
                          <Input placeholder="BA 12 PA 1234" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                <FormField
                  control={form.control}
                  name="deliveryArea"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Preferred Delivery Areas *</FormLabel>
                      <FormControl>
                        <Input placeholder="Siraha, Lahan, Janakpur" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              {/* Document Upload */}
              <div className="space-y-4 border-t pt-4">
                <DocumentUpload 
                  onDocumentChange={handleDocumentChange}
                  initialDocuments={documents}
                  label="Required Documents"
                />
              </div>

              {/* Terms and Conditions */}
              <div className="border-t pt-4">
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
                        <FormLabel className="text-sm font-normal">
                          I agree to the delivery partner terms and conditions *
                        </FormLabel>
                        <p className="text-xs text-muted-foreground">
                          You agree to follow delivery guidelines and maintain professional conduct
                        </p>
                      </div>
                    </FormItem>
                  )}
                />
                <FormMessage />
              </div>

              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading ? "Creating Account..." : "Complete Registration"}
              </Button>
            </form>
          </Form>

          <div className="mt-6 p-4 bg-green-50 dark:bg-green-950 rounded-lg">
            <h4 className="font-semibold text-green-800 dark:text-green-200 mb-2">
              Delivery Partner Benefits:
            </h4>
            <ul className="text-sm text-green-700 dark:text-green-300 space-y-1">
              <li>• Flexible working hours - work when you want</li>
              <li>• Competitive delivery fees and bonuses</li>
              <li>• Weekly payments directly to your account</li>
              <li>• 24/7 support team assistance</li>
              <li>• Get started immediately after approval</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}