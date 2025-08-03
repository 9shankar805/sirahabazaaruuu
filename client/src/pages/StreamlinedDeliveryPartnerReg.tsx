import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { useToast } from '@/hooks/use-toast';
import { useLocation } from 'wouter';
import { Truck, User, Car, FileText, CreditCard, Phone } from 'lucide-react';
import DocumentUpload from '@/components/DocumentUpload';

const formSchema = z.object({
  // Personal Information
  fullName: z.string().min(2, 'Full name must be at least 2 characters'),
  email: z.string().email('Invalid email address'),
  phone: z.string().min(10, 'Phone number must be at least 10 digits'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  address: z.string().min(5, 'Address must be at least 5 characters'),
  
  // Vehicle Information
  vehicleType: z.string().min(1, 'Vehicle type is required'),
  vehicleNumber: z.string().min(1, 'Vehicle number is required'),
  drivingLicense: z.string().min(1, 'Driving license number is required'),
  
  // Banking Information
  bankAccountNumber: z.string().min(1, 'Bank account number is required'),
  ifscCode: z.string().min(1, 'IFSC code is required'),
  accountHolderName: z.string().min(1, 'Account holder name is required'),
  
  // Emergency Contact
  emergencyContactName: z.string().min(1, 'Emergency contact name is required'),
  emergencyContactPhone: z.string().min(10, 'Emergency contact phone is required'),
  
  // Delivery Information
  deliveryAreas: z.string().min(1, 'Delivery areas are required'),
  
  // Documents (will be handled by DocumentUpload component)
  idProofUrl: z.string().optional(),
  drivingLicenseUrl: z.string().optional(),
  vehicleRegistrationUrl: z.string().optional(),
  insuranceUrl: z.string().optional(),
  photoUrl: z.string().optional(),
  
  // Terms
  termsAccepted: z.boolean().refine(val => val === true, 'You must accept the terms and conditions'),
});

type FormData = z.infer<typeof formSchema>;

export default function StreamlinedDeliveryPartnerReg() {
  const [isLoading, setIsLoading] = useState(false);
  const [documents, setDocuments] = useState({
    idProofUrl: '',
    drivingLicenseUrl: '',
    vehicleRegistrationUrl: '',
    insuranceUrl: '',
    photoUrl: '',
  });
  const { toast } = useToast();
  const [, setLocation] = useLocation();

  const form = useForm<FormData>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      fullName: '',
      email: '',
      phone: '',
      password: '',
      address: '',
      vehicleType: '',
      vehicleNumber: '',
      drivingLicense: '',
      bankAccountNumber: '',
      ifscCode: '',
      accountHolderName: '',
      emergencyContactName: '',
      emergencyContactPhone: '',
      deliveryAreas: '',
      termsAccepted: false,
    },
  });

  const handleDocumentChange = (newDocuments: typeof documents) => {
    setDocuments(newDocuments);
    // Update form values
    form.setValue('idProofUrl', newDocuments.idProofUrl);
    form.setValue('drivingLicenseUrl', newDocuments.drivingLicenseUrl);
    form.setValue('vehicleRegistrationUrl', newDocuments.vehicleRegistrationUrl);
    form.setValue('insuranceUrl', newDocuments.insuranceUrl);
    form.setValue('photoUrl', newDocuments.photoUrl);
  };

  const onSubmit = async (data: FormData) => {
    setIsLoading(true);
    try {
      // Create user account
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
        throw new Error(error.error || 'Registration failed');
      }

      const userResult = await userResponse.json();

      // Create comprehensive delivery partner profile
      const deliveryPartnerData = {
        userId: userResult.user.id,
        vehicleType: data.vehicleType,
        vehicleNumber: data.vehicleNumber,
        drivingLicense: data.drivingLicense,
        bankAccountNumber: data.bankAccountNumber,
        ifscCode: data.ifscCode,
        accountHolderName: data.accountHolderName,
        emergencyContactName: data.emergencyContactName,
        emergencyContactPhone: data.emergencyContactPhone,
        deliveryAreas: data.deliveryAreas.split(',').map(area => area.trim()),
        idProofUrl: documents.idProofUrl,
        drivingLicenseUrl: documents.drivingLicenseUrl,
        vehicleRegistrationUrl: documents.vehicleRegistrationUrl,
        insuranceUrl: documents.insuranceUrl,
        photoUrl: documents.photoUrl,
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
        description: "Your delivery partner application has been submitted. You'll be approved shortly and can start earning immediately.",
      });

      setLocation('/login');
    } catch (error) {
      console.error('Registration error:', error);
      toast({
        title: "Registration Failed",
        description: error instanceof Error ? error.message : "Something went wrong. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 flex items-center justify-center p-4">
      <Card className="w-full max-w-4xl">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-r from-blue-600 to-indigo-600">
            <Truck className="h-8 w-8 text-white" />
          </div>
          <CardTitle className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
            Become a Delivery Partner
          </CardTitle>
          <CardDescription className="text-lg">
            Complete your profile in one simple form and start earning flexible income
          </CardDescription>
        </CardHeader>

        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
              
              {/* Personal Information */}
              <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-950 dark:to-indigo-950 p-6 rounded-lg space-y-4">
                <h3 className="flex items-center text-lg font-semibold text-blue-800 dark:text-blue-200">
                  <User className="h-5 w-5 mr-2" />
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
                    name="email"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Email *</FormLabel>
                        <FormControl>
                          <Input type="email" placeholder="your@email.com" {...field} />
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
                          <Input placeholder="9805916598" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Password *</FormLabel>
                        <FormControl>
                          <Input type="password" placeholder="Create a strong password" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
                <FormField
                  control={form.control}
                  name="address"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Address *</FormLabel>
                      <FormControl>
                        <Input placeholder="Your complete address" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              {/* Vehicle Information */}
              <div className="bg-gradient-to-r from-green-50 to-emerald-50 dark:from-green-950 dark:to-emerald-950 p-6 rounded-lg space-y-4">
                <h3 className="flex items-center text-lg font-semibold text-green-800 dark:text-green-200">
                  <Car className="h-5 w-5 mr-2" />
                  Vehicle Information
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <FormField
                    control={form.control}
                    name="vehicleType"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Vehicle Type *</FormLabel>
                        <Select onValueChange={field.onChange} value={field.value}>
                          <FormControl>
                            <SelectTrigger>
                              <SelectValue placeholder="Select vehicle" />
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
                          <Input placeholder="BA 01 PA 1234" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="drivingLicense"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Driving License *</FormLabel>
                        <FormControl>
                          <Input placeholder="DL1234567890" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
              </div>

              {/* Banking Information */}
              <div className="bg-gradient-to-r from-purple-50 to-pink-50 dark:from-purple-950 dark:to-pink-950 p-6 rounded-lg space-y-4">
                <h3 className="flex items-center text-lg font-semibold text-purple-800 dark:text-purple-200">
                  <CreditCard className="h-5 w-5 mr-2" />
                  Banking Information
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <FormField
                    control={form.control}
                    name="accountHolderName"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Account Holder Name *</FormLabel>
                        <FormControl>
                          <Input placeholder="Name as per bank account" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="bankAccountNumber"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Bank Account Number *</FormLabel>
                        <FormControl>
                          <Input placeholder="1234567890123456" {...field} />
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
                        <FormLabel>IFSC Code *</FormLabel>
                        <FormControl>
                          <Input placeholder="SBIN0000123" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
              </div>

              {/* Emergency Contact */}
              <div className="bg-gradient-to-r from-orange-50 to-red-50 dark:from-orange-950 dark:to-red-950 p-6 rounded-lg space-y-4">
                <h3 className="flex items-center text-lg font-semibold text-orange-800 dark:text-orange-200">
                  <Phone className="h-5 w-5 mr-2" />
                  Emergency Contact
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="emergencyContactName"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Emergency Contact Name *</FormLabel>
                        <FormControl>
                          <Input placeholder="Contact person name" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="emergencyContactPhone"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Emergency Contact Phone *</FormLabel>
                        <FormControl>
                          <Input placeholder="9876543210" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
              </div>

              {/* Delivery Areas */}
              <div className="bg-gradient-to-r from-teal-50 to-cyan-50 dark:from-teal-950 dark:to-cyan-950 p-6 rounded-lg space-y-4">
                <h3 className="flex items-center text-lg font-semibold text-teal-800 dark:text-teal-200">
                  <Truck className="h-5 w-5 mr-2" />
                  Delivery Areas
                </h3>
                <FormField
                  control={form.control}
                  name="deliveryAreas"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Preferred Delivery Areas *</FormLabel>
                      <FormControl>
                        <Input placeholder="Siraha, Lahan, Janakpur (comma separated)" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              {/* Document Upload */}
              <div className="bg-gradient-to-r from-gray-50 to-slate-50 dark:from-gray-950 dark:to-slate-950 p-6 rounded-lg space-y-4">
                <h3 className="flex items-center text-lg font-semibold text-gray-800 dark:text-gray-200">
                  <FileText className="h-5 w-5 mr-2" />
                  Required Documents
                </h3>
                <DocumentUpload 
                  onDocumentChange={handleDocumentChange}
                  initialDocuments={documents}
                  label="Upload Your Documents (All documents compressed to 200KB for fast processing)"
                />
              </div>

              {/* Terms and Conditions */}
              <div className="border-t pt-6">
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
                          You agree to follow delivery guidelines, maintain professional conduct, and provide timely service
                        </p>
                      </div>
                    </FormItem>
                  )}
                />
                <FormMessage />
              </div>

              <Button 
                type="submit" 
                className="w-full h-12 text-lg font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700" 
                disabled={isLoading}
              >
                {isLoading ? "Creating Your Account..." : "Complete Registration & Start Earning"}
              </Button>
            </form>
          </Form>

          <div className="mt-8 p-6 bg-gradient-to-r from-green-50 to-emerald-50 dark:from-green-950 dark:to-emerald-950 rounded-lg">
            <h4 className="font-semibold text-green-800 dark:text-green-200 mb-3 text-center">
              🎉 Why Choose Siraha Bazaar?
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-green-700 dark:text-green-300">
              <div className="space-y-2">
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-600 rounded-full mr-2"></div>
                  Flexible working hours - work when you want
                </div>
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-600 rounded-full mr-2"></div>
                  Competitive delivery fees starting from ₹30
                </div>
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-600 rounded-full mr-2"></div>
                  Weekly payments directly to your account
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-600 rounded-full mr-2"></div>
                  24/7 support team assistance
                </div>
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-600 rounded-full mr-2"></div>
                  Performance bonuses and incentives
                </div>
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-600 rounded-full mr-2"></div>
                  Get started immediately after approval
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}