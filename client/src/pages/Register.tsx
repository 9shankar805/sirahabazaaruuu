import { useState } from "react";
import { Link, useLocation } from "wouter";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Eye, EyeOff, Store, User, Truck, Upload, FileText, CheckCircle, DollarSign, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import ImageUpload from "@/components/ImageUpload";
// Removed Firebase dependencies - using backend authentication only

const registerSchema = z.object({
  fullName: z.string().min(2, "Full name must be at least 2 characters"),
  email: z.string().email("Please enter a valid email address"),
  phone: z.string().min(10, "Phone number must be at least 10 digits"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  confirmPassword: z.string(),
  role: z.enum(["customer", "shopkeeper", "delivery_partner"]),
  address: z.string().optional(),
  
  // Comprehensive Delivery partner verification fields
  vehicleType: z.string().optional(),
  vehicleNumber: z.string().optional(),
  vehicleBrand: z.string().optional(),
  vehicleModel: z.string().optional(),
  vehicleYear: z.string().optional(),
  vehicleColor: z.string().optional(),
  drivingLicense: z.string().optional(),
  licenseExpiryDate: z.string().optional(),
  idProofType: z.string().optional(),
  idProofNumber: z.string().optional(),
  bankAccountNumber: z.string().optional(),
  ifscCode: z.string().optional(),
  bankName: z.string().optional(),
  accountHolderName: z.string().optional(),
  emergencyContactName: z.string().optional(),
  emergencyContactPhone: z.string().optional(),
  emergencyContactRelation: z.string().optional(),
  deliveryAreas: z.array(z.string()).optional(),
  workingHours: z.string().optional(),
  experience: z.string().optional(),
  previousEmployment: z.string().optional(),
  references: z.string().optional(),
  medicalCertificate: z.string().optional(),
  policeClearance: z.string().optional(),
  idProofUrl: z.string().optional(),
  drivingLicenseUrl: z.string().optional(),
  vehicleRegistrationUrl: z.string().optional(),
  insuranceUrl: z.string().optional(),
  photoUrl: z.string().optional(),
  termsAccepted: z.boolean().optional(),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
}).refine((data) => {
  if (data.role === "delivery_partner") {
    return data.vehicleType && data.vehicleType.length > 0;
  }
  return true;
}, {
  message: "Vehicle type is required for delivery partners",
  path: ["vehicleType"],
}).refine((data) => {
  if (data.role === "delivery_partner") {
    return data.vehicleNumber && data.vehicleNumber.length > 0;
  }
  return true;
}, {
  message: "Vehicle number is required for delivery partners",
  path: ["vehicleNumber"],
}).refine((data) => {
  if (data.role === "delivery_partner" && data.vehicleType !== "bicycle") {
    return data.drivingLicense && data.drivingLicense.length > 0;
  }
  return true;
}, {
  message: "Driving license number is required for motorized vehicles",
  path: ["drivingLicense"],
}).refine((data) => {
  if (data.role === "delivery_partner") {
    return data.idProofType && data.idProofType.length > 0;
  }
  return true;
}, {
  message: "ID proof type is required for delivery partners",
  path: ["idProofType"],
}).refine((data) => {
  if (data.role === "delivery_partner") {
    return data.idProofNumber && data.idProofNumber.length > 0;
  }
  return true;
}, {
  message: "ID proof number is required for delivery partners",
  path: ["idProofNumber"],
}).refine((data) => {
  if (data.role === "delivery_partner") {
    return data.bankAccountNumber && data.bankAccountNumber.length > 0;
  }
  return true;
}, {
  message: "Bank account number is required for delivery partners",
  path: ["bankAccountNumber"],
}).refine((data) => {
  if (data.role === "delivery_partner") {
    return data.ifscCode && data.ifscCode.length > 0;
  }
  return true;
}, {
  message: "IFSC code is required for delivery partners",
  path: ["ifscCode"],
}).refine((data) => {
  if (data.role === "delivery_partner") {
    return data.emergencyContactName && data.emergencyContactName.length > 0;
  }
  return true;
}, {
  message: "Emergency contact name is required for delivery partners",
  path: ["emergencyContactName"],
}).refine((data) => {
  if (data.role === "delivery_partner") {
    return data.emergencyContactPhone && data.emergencyContactPhone.length > 0;
  }
  return true;
}, {
  message: "Emergency contact phone is required for delivery partners",
  path: ["emergencyContactPhone"],
}).refine((data) => {
  if (data.role === "delivery_partner") {
    return data.termsAccepted === true;
  }
  return true;
}, {
  message: "You must accept the terms and conditions",
  path: ["termsAccepted"],
});

type RegisterForm = z.infer<typeof registerSchema>;

export default function Register() {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const [, setLocation] = useLocation();
  const { register, user } = useAuth();
  const { toast } = useToast();
  
  // Check if current user is admin
  const isAdmin = user?.role === 'admin' || user?.email?.includes('admin') || localStorage.getItem('isAdmin') === 'true';

  const form = useForm<RegisterForm>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      fullName: "",
      email: "",
      phone: "",
      password: "",
      confirmPassword: "",
      role: "customer",
      address: "",
      vehicleType: "",
      vehicleNumber: "",
      vehicleBrand: "",
      vehicleModel: "",
      vehicleYear: "",
      vehicleColor: "",
      drivingLicense: "",
      licenseExpiryDate: "",
      idProofType: "",
      idProofNumber: "",
      bankAccountNumber: "",
      ifscCode: "",
      bankName: "",
      accountHolderName: "",
      emergencyContactName: "",
      emergencyContactPhone: "",
      emergencyContactRelation: "",
      deliveryAreas: [],
      workingHours: "",
      experience: "",
      previousEmployment: "",
      references: "",
      medicalCertificate: "",
      policeClearance: "",
      idProofUrl: "",
      drivingLicenseUrl: "",
      vehicleRegistrationUrl: "",
      insuranceUrl: "",
      photoUrl: "",
      termsAccepted: false,
    },
  });

  const selectedRole = form.watch("role");
  const selectedVehicleType = form.watch("vehicleType");

  // Direct backend registration without Firebase dependencies

  const onSubmit = async (data: RegisterForm) => {
    setIsLoading(true);
    try {
      const { confirmPassword, termsAccepted, ...registerData } = data;
      
      // Set shopkeeper and delivery partner accounts as pending for admin approval
      const userData = {
        ...registerData,
        status: (registerData.role === 'shopkeeper' || registerData.role === 'delivery_partner') ? 'pending' : 'active'
      };
      
      let user;
      
      if (registerData.role === 'customer') {
        // For customers, use the auth hook to properly set user state
        await register(userData);
      } else {
        // For shopkeepers and delivery partners, use direct API call since they need approval
        const response = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(userData),
        });

        if (!response.ok) {
          const error = await response.json();
          let errorMessage = error.error || 'Registration failed';
          
          // Handle common registration errors
          if (errorMessage.includes('duplicate key') || errorMessage.includes('already exists')) {
            if (errorMessage.includes('email')) {
              errorMessage = 'An account with this email already exists.';
            } else if (errorMessage.includes('phone')) {
              errorMessage = 'An account with this phone number already exists.';
            } else {
              errorMessage = 'An account with these credentials already exists.';
            }
          }
          
          throw new Error(errorMessage);
        }
        
        const result = await response.json();
        user = result.user || result;
      }
      
      if (registerData.role === 'delivery_partner' && user) {
        
        // Create delivery partner profile
        const deliveryPartnerData = {
          userId: user.id,
          vehicleType: data.vehicleType,
          vehicleNumber: data.vehicleNumber,
          vehicleBrand: data.vehicleBrand,
          vehicleModel: data.vehicleModel,
          vehicleYear: data.vehicleYear,
          vehicleColor: data.vehicleColor,
          drivingLicense: data.drivingLicense,
          licenseExpiryDate: data.licenseExpiryDate,
          idProofType: data.idProofType,
          idProofNumber: data.idProofNumber,
          bankAccountNumber: data.bankAccountNumber,
          ifscCode: data.ifscCode,
          bankName: data.bankName,
          accountHolderName: data.accountHolderName,
          emergencyContactName: data.emergencyContactName,
          emergencyContactPhone: data.emergencyContactPhone,
          emergencyContactRelation: data.emergencyContactRelation,
          deliveryAreas: data.deliveryAreas || [],
          workingHours: data.workingHours,
          experience: data.experience,
          previousEmployment: data.previousEmployment,
          references: data.references,
          idProofUrl: data.idProofUrl,
          drivingLicenseUrl: data.drivingLicenseUrl || '',
          vehicleRegistrationUrl: data.vehicleRegistrationUrl,
          insuranceUrl: data.insuranceUrl,
          photoUrl: data.photoUrl,
        };

        await fetch('/api/delivery-partners', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(deliveryPartnerData),
        });

        toast({
          title: "Application submitted!",
          description: "Your delivery partner application is pending admin approval. You'll be notified once approved.",
        });
        setLocation("/login");
      } else if (registerData.role === 'shopkeeper') {
        toast({
          title: "Application submitted!",
          description: "Your shopkeeper account is pending admin approval. You'll be notified once approved.",
        });
        setLocation("/login");
      } else {
        toast({
          title: "Account created successfully!",
          description: "Welcome to Siraha Bazaar. You are now logged in.",
        });
        setLocation("/");
      }
    } catch (error) {
      toast({
        title: "Registration failed",
        description: error instanceof Error ? error.message : "Failed to create account",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-muted flex items-center justify-center py-12">
      <div className="w-full max-w-md">
        <Card>
          <CardHeader className="text-center">
            <div className="flex items-center mb-4">
              <Store className="h-8 w-8 text-primary mr-2" />
              <span className="text-2xl font-bold text-foreground">Siraha Bazaar</span>
            </div>
            <CardTitle className="text-2xl">Create Account</CardTitle>
            <p className="text-muted-foreground">
              Join our local marketplace community
            </p>
          </CardHeader>
          <CardContent>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                <FormField
                  control={form.control}
                  name="fullName"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Full Name</FormLabel>
                      <FormControl>
                        <Input
                          placeholder="Enter your full name"
                          {...field}
                        />
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
                      <FormLabel>Email Address</FormLabel>
                      <FormControl>
                        <Input
                          type="email"
                          placeholder="Enter your email"
                          {...field}
                        />
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
                      <FormLabel>Phone Number</FormLabel>
                      <FormControl>
                        <Input
                          type="tel"
                          placeholder="Enter your phone number"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="role"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Account Type</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select account type" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="customer">
                            <div className="flex items-center">
                              <User className="h-4 w-4 mr-2" />
                              Customer - Shop from local stores
                            </div>
                          </SelectItem>
                          <SelectItem value="shopkeeper">
                            <div className="flex items-center">
                              <Store className="h-4 w-4 mr-2" />
                              Shopkeeper - Sell your products
                            </div>
                          </SelectItem>
                          <SelectItem value="delivery_partner">
                            <div className="flex items-center">
                              <Truck className="h-4 w-4 mr-2" />
                              Delivery Partner - Deliver orders
                            </div>
                          </SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="password"
                  render={({ field }) => {
                    const password = field.value || "";
                    
                    // Calculate password strength
                    let strength = 0;
                    let strengthText = "Very Weak";
                    let strengthColor = "bg-red-500";
                    
                    if (password.length >= 8) strength += 20;
                    if (password.match(/[a-z]/)) strength += 20;
                    if (password.match(/[A-Z]/)) strength += 20;
                    if (password.match(/[0-9]/)) strength += 20;
                    if (password.match(/[^a-zA-Z0-9]/)) strength += 20;
                    
                    if (strength >= 80) {
                      strengthText = "Very Strong";
                      strengthColor = "bg-green-500";
                    } else if (strength >= 60) {
                      strengthText = "Strong";
                      strengthColor = "bg-blue-500";
                    } else if (strength >= 40) {
                      strengthText = "Medium";
                      strengthColor = "bg-yellow-500";
                    } else if (strength >= 20) {
                      strengthText = "Weak";
                      strengthColor = "bg-orange-500";
                    }
                    
                    return (
                      <FormItem>
                        <FormLabel>Password</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Input
                              type={showPassword ? "text" : "password"}
                              placeholder="Create a password"
                              {...field}
                            />
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                              onClick={() => setShowPassword(!showPassword)}
                            >
                              {showPassword ? (
                                <EyeOff className="h-4 w-4" />
                              ) : (
                                <Eye className="h-4 w-4" />
                              )}
                            </Button>
                          </div>
                        </FormControl>
                        {password && (
                          <div className="mt-2 space-y-2">
                            <div className="flex items-center justify-between text-sm">
                              <span className="text-muted-foreground">Password Strength:</span>
                              <span className={`font-medium ${
                                strength >= 80 ? 'text-green-600' :
                                strength >= 60 ? 'text-blue-600' :
                                strength >= 40 ? 'text-yellow-600' :
                                strength >= 20 ? 'text-orange-600' :
                                'text-red-600'
                              }`}>
                                {strengthText}
                              </span>
                            </div>
                            <div className="w-full bg-gray-200 rounded-full h-2 overflow-hidden">
                              <div 
                                className={`h-full ${strengthColor} transition-all duration-500 ease-out rounded-full`}
                                style={{ width: `${strength}%` }}
                              ></div>
                            </div>
                            <div className="text-xs text-muted-foreground space-y-1">
                              <div className="flex items-center space-x-2">
                                <div className={`w-2 h-2 rounded-full ${password.length >= 8 ? 'bg-green-500' : 'bg-gray-300'} transition-colors duration-300`}></div>
                                <span>At least 8 characters</span>
                              </div>
                              <div className="flex items-center space-x-2">
                                <div className={`w-2 h-2 rounded-full ${password.match(/[a-z]/) ? 'bg-green-500' : 'bg-gray-300'} transition-colors duration-300`}></div>
                                <span>Lowercase letter</span>
                              </div>
                              <div className="flex items-center space-x-2">
                                <div className={`w-2 h-2 rounded-full ${password.match(/[A-Z]/) ? 'bg-green-500' : 'bg-gray-300'} transition-colors duration-300`}></div>
                                <span>Uppercase letter</span>
                              </div>
                              <div className="flex items-center space-x-2">
                                <div className={`w-2 h-2 rounded-full ${password.match(/[0-9]/) ? 'bg-green-500' : 'bg-gray-300'} transition-colors duration-300`}></div>
                                <span>Number</span>
                              </div>
                              <div className="flex items-center space-x-2">
                                <div className={`w-2 h-2 rounded-full ${password.match(/[^a-zA-Z0-9]/) ? 'bg-green-500' : 'bg-gray-300'} transition-colors duration-300`}></div>
                                <span>Special character</span>
                              </div>
                            </div>
                          </div>
                        )}
                        <FormMessage />
                      </FormItem>
                    );
                  }}
                />

                <FormField
                  control={form.control}
                  name="confirmPassword"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Confirm Password</FormLabel>
                      <FormControl>
                        <div className="relative">
                          <Input
                            type={showConfirmPassword ? "text" : "password"}
                            placeholder="Confirm your password"
                            {...field}
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                            onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                          >
                            {showConfirmPassword ? (
                              <EyeOff className="h-4 w-4" />
                            ) : (
                              <Eye className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* Address field for all roles */}
                <FormField
                  control={form.control}
                  name="address"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Address</FormLabel>
                      <FormControl>
                        <Textarea
                          placeholder="Enter your address"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* Comprehensive Delivery Partner Verification Fields */}
                {selectedRole === "delivery_partner" && (
                  <div className="space-y-6 border rounded-lg p-6 bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-950 dark:to-indigo-950">
                    <div className="text-center mb-6">
                      <div className="flex items-center justify-center mb-4">
                        <div className="p-3 bg-blue-600 rounded-full">
                          <Truck className="h-8 w-8 text-white" />
                        </div>
                      </div>
                      <h2 className="text-2xl font-bold text-blue-800 dark:text-blue-200">
                        Delivery Partner Verification
                      </h2>
                      <p className="text-blue-600 dark:text-blue-300 mt-2">
                        Complete all sections to join our delivery network
                      </p>
                    </div>

                    {/* Personal Information Section */}
                    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow-sm">
                      <h3 className="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-4 flex items-center">
                        <User className="h-5 w-5 mr-2" />
                        Personal Information
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <FormField
                          control={form.control}
                          name="emergencyContactName"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Emergency Contact Name *</FormLabel>
                              <FormControl>
                                <Input placeholder="Full name of emergency contact" {...field} />
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
                                <Input placeholder="Emergency contact phone number" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="emergencyContactRelation"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Relationship</FormLabel>
                              <Select onValueChange={field.onChange} defaultValue={field.value}>
                                <FormControl>
                                  <SelectTrigger>
                                    <SelectValue placeholder="Select relationship" />
                                  </SelectTrigger>
                                </FormControl>
                                <SelectContent>
                                  <SelectItem value="parent">Parent</SelectItem>
                                  <SelectItem value="spouse">Spouse</SelectItem>
                                  <SelectItem value="sibling">Sibling</SelectItem>
                                  <SelectItem value="friend">Friend</SelectItem>
                                  <SelectItem value="other">Other</SelectItem>
                                </SelectContent>
                              </Select>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="experience"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Delivery Experience</FormLabel>
                              <Select onValueChange={field.onChange} defaultValue={field.value}>
                                <FormControl>
                                  <SelectTrigger>
                                    <SelectValue placeholder="Select experience level" />
                                  </SelectTrigger>
                                </FormControl>
                                <SelectContent>
                                  <SelectItem value="0-6months">0-6 months</SelectItem>
                                  <SelectItem value="6months-1year">6 months - 1 year</SelectItem>
                                  <SelectItem value="1-2years">1-2 years</SelectItem>
                                  <SelectItem value="2-5years">2-5 years</SelectItem>
                                  <SelectItem value="5years+">5+ years</SelectItem>
                                </SelectContent>
                              </Select>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                    </div>

                    {/* Vehicle Information Section */}
                    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow-sm">
                      <h3 className="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-4 flex items-center">
                        <Truck className="h-5 w-5 mr-2" />
                        Vehicle Information
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <FormField
                          control={form.control}
                          name="vehicleType"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Vehicle Type *</FormLabel>
                              <Select onValueChange={field.onChange} defaultValue={field.value}>
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
                                <Input placeholder="e.g., BA 12 PA 1234" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="vehicleBrand"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Vehicle Brand</FormLabel>
                              <FormControl>
                                <Input placeholder="e.g., Honda, Yamaha, Hero" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="vehicleModel"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Vehicle Model</FormLabel>
                              <FormControl>
                                <Input placeholder="e.g., Splendor, FZ, Activa" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="vehicleYear"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Vehicle Year</FormLabel>
                              <FormControl>
                                <Input placeholder="e.g., 2020, 2021, 2022" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="vehicleColor"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Vehicle Color</FormLabel>
                              <FormControl>
                                <Input placeholder="e.g., Red, Blue, Black" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                    </div>

                    {/* License & Documents Section */}
                    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow-sm">
                      <h3 className="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-4 flex items-center">
                        <FileText className="h-5 w-5 mr-2" />
                        License & Documents
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
{selectedVehicleType !== "bicycle" && (
                          <>
                            <FormField
                              control={form.control}
                              name="drivingLicense"
                              render={({ field }) => (
                                <FormItem>
                                  <FormLabel>Driving License Number *</FormLabel>
                                  <FormControl>
                                    <Input placeholder="Enter license number" {...field} />
                                  </FormControl>
                                  <FormMessage />
                                </FormItem>
                              )}
                            />

                            <FormField
                              control={form.control}
                              name="licenseExpiryDate"
                              render={({ field }) => (
                                <FormItem>
                                  <FormLabel>License Expiry Date</FormLabel>
                                  <FormControl>
                                    <Input type="date" {...field} />
                                  </FormControl>
                                  <FormMessage />
                                </FormItem>
                              )}
                            />
                          </>
                        )}

                        {selectedVehicleType === "bicycle" && (
                          <div className="col-span-2 p-3 bg-green-50 dark:bg-green-950 rounded-lg border border-green-200 dark:border-green-800">
                            <p className="text-sm text-green-800 dark:text-green-200">
                              <strong>Note:</strong> Driving license is not required for bicycle delivery partners.
                            </p>
                          </div>
                        )}

                        <FormField
                          control={form.control}
                          name="idProofType"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>ID Proof Type *</FormLabel>
                              <Select onValueChange={field.onChange} defaultValue={field.value}>
                                <FormControl>
                                  <SelectTrigger>
                                    <SelectValue placeholder="Select ID type" />
                                  </SelectTrigger>
                                </FormControl>
                                <SelectContent>
                                  <SelectItem value="citizenship">Citizenship Certificate</SelectItem>
                                  <SelectItem value="passport">Passport</SelectItem>
                                  <SelectItem value="voter_id">Voter ID</SelectItem>
                                  <SelectItem value="national_id">National ID</SelectItem>
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
                              <FormLabel>ID Proof Number *</FormLabel>
                              <FormControl>
                                <Input placeholder="Enter ID number" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                    </div>

                    {/* Banking Information Section */}
                    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow-sm">
                      <h3 className="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-4 flex items-center">
                        <DollarSign className="h-5 w-5 mr-2" />
                        Banking Information
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <FormField
                          control={form.control}
                          name="bankAccountNumber"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Bank Account Number *</FormLabel>
                              <FormControl>
                                <Input placeholder="Enter account number" {...field} />
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
                                <Input placeholder="Enter IFSC code" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="bankName"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Bank Name</FormLabel>
                              <FormControl>
                                <Input placeholder="Enter bank name" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="accountHolderName"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Account Holder Name</FormLabel>
                              <FormControl>
                                <Input placeholder="Name as per bank account" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                    </div>

                    {/* Working Preferences Section */}
                    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow-sm">
                      <h3 className="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-4 flex items-center">
                        <Clock className="h-5 w-5 mr-2" />
                        Working Preferences
                      </h3>
                      <div className="space-y-4">
                        <FormField
                          control={form.control}
                          name="workingHours"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Preferred Working Hours</FormLabel>
                              <Select onValueChange={field.onChange} defaultValue={field.value}>
                                <FormControl>
                                  <SelectTrigger>
                                    <SelectValue placeholder="Select working hours" />
                                  </SelectTrigger>
                                </FormControl>
                                <SelectContent>
                                  <SelectItem value="morning">Morning (6AM - 12PM)</SelectItem>
                                  <SelectItem value="afternoon">Afternoon (12PM - 6PM)</SelectItem>
                                  <SelectItem value="evening">Evening (6PM - 12AM)</SelectItem>
                                  <SelectItem value="full-time">Full Time (6AM - 12AM)</SelectItem>
                                  <SelectItem value="flexible">Flexible Hours</SelectItem>
                                </SelectContent>
                              </Select>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="previousEmployment"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Previous Employment</FormLabel>
                              <FormControl>
                                <Textarea 
                                  placeholder="Describe your previous work experience (optional)"
                                  {...field}
                                />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="references"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>References</FormLabel>
                              <FormControl>
                                <Textarea 
                                  placeholder="Provide references if any (name, phone, relationship)"
                                  {...field}
                                />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                    </div>

                    {/* Document Upload Section */}
                    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow-sm">
                      <h3 className="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-4 flex items-center">
                        <Upload className="h-5 w-5 mr-2" />
                        Document Uploads
                      </h3>
                      <div className="space-y-4">
                        <FormField
                          control={form.control}
                          name="idProofUrl"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>ID Proof Document *</FormLabel>
                              <FormControl>
                                <div className="border-2 border-dashed border-gray-300 rounded-lg p-4">
                                  <div className="text-center">
                                    <Upload className="mx-auto h-12 w-12 text-gray-400" />
                                    <div className="mt-4">
                                      <Input
                                        type="file"
                                        accept="image/*,.pdf"
                                        onChange={(e) => {
                                          const file = e.target.files?.[0];
                                          if (file) {
                                            field.onChange(`/uploads/id_${Date.now()}.${file.name.split('.').pop()}`);
                                          }
                                        }}
                                        className="hidden"
                                        id="idProof"
                                      />
                                      <label
                                        htmlFor="idProof"
                                        className="cursor-pointer text-sm font-medium text-primary hover:text-primary/80"
                                      >
                                        Upload Citizenship or National ID
                                      </label>
                                      <p className="text-xs text-muted-foreground mt-1">
                                        PNG, JPG, PDF up to 10MB
                                      </p>
                                    </div>
                                  </div>
                                  {field.value && (
                                    <div className="mt-2 flex items-center text-sm text-green-600">
                                      <CheckCircle className="h-4 w-4 mr-1" />
                                      Document uploaded
                                    </div>
                                  )}
                                </div>
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

{selectedVehicleType !== "bicycle" && (
                          <FormField
                            control={form.control}
                            name="drivingLicenseUrl"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Driving License Document</FormLabel>
                                <FormControl>
                                  <div className="border-2 border-dashed border-gray-300 rounded-lg p-4">
                                    <div className="text-center">
                                      <Upload className="mx-auto h-12 w-12 text-gray-400" />
                                      <div className="mt-4">
                                        <Input
                                          type="file"
                                          accept="image/*,.pdf"
                                          onChange={(e) => {
                                            const file = e.target.files?.[0];
                                            if (file) {
                                              field.onChange(`/uploads/license_${Date.now()}.${file.name.split('.').pop()}`);
                                            }
                                          }}
                                          className="hidden"
                                          id="drivingLicense"
                                        />
                                        <label
                                          htmlFor="drivingLicense"
                                          className="cursor-pointer text-sm font-medium text-primary hover:text-primary/80"
                                        >
                                          Upload Driving License
                                        </label>
                                        <p className="text-xs text-muted-foreground mt-1">
                                          PNG, JPG, PDF up to 10MB
                                        </p>
                                      </div>
                                    </div>
                                    {field.value && (
                                      <div className="mt-2 flex items-center text-sm text-green-600">
                                        <CheckCircle className="h-4 w-4 mr-1" />
                                        Document uploaded
                                      </div>
                                    )}
                                  </div>
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                        )}

                        <FormField
                          control={form.control}
                          name="vehicleRegistrationUrl"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Vehicle Registration</FormLabel>
                              <FormControl>
                                <div className="border-2 border-dashed border-gray-300 rounded-lg p-4">
                                  <div className="text-center">
                                    <Upload className="mx-auto h-12 w-12 text-gray-400" />
                                    <div className="mt-4">
                                      <Input
                                        type="file"
                                        accept="image/*,.pdf"
                                        onChange={(e) => {
                                          const file = e.target.files?.[0];
                                          if (file) {
                                            field.onChange(`/uploads/registration_${Date.now()}.${file.name.split('.').pop()}`);
                                          }
                                        }}
                                        className="hidden"
                                        id="vehicleRegistration"
                                      />
                                      <label
                                        htmlFor="vehicleRegistration"
                                        className="cursor-pointer text-sm font-medium text-primary hover:text-primary/80"
                                      >
                                        Upload Vehicle Registration
                                      </label>
                                      <p className="text-xs text-muted-foreground mt-1">
                                        PNG, JPG, PDF up to 10MB
                                      </p>
                                    </div>
                                  </div>
                                  {field.value && (
                                    <div className="mt-2 flex items-center text-sm text-green-600">
                                      <CheckCircle className="h-4 w-4 mr-1" />
                                      Document uploaded
                                    </div>
                                  )}
                                </div>
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="insuranceUrl"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Vehicle Insurance</FormLabel>
                              <FormControl>
                                <div className="border-2 border-dashed border-gray-300 rounded-lg p-4">
                                  <div className="text-center">
                                    <Upload className="mx-auto h-12 w-12 text-gray-400" />
                                    <div className="mt-4">
                                      <Input
                                        type="file"
                                        accept="image/*,.pdf"
                                        onChange={(e) => {
                                          const file = e.target.files?.[0];
                                          if (file) {
                                            field.onChange(`/uploads/insurance_${Date.now()}.${file.name.split('.').pop()}`);
                                          }
                                        }}
                                        className="hidden"
                                        id="insurance"
                                      />
                                      <label
                                        htmlFor="insurance"
                                        className="cursor-pointer text-sm font-medium text-primary hover:text-primary/80"
                                      >
                                        Upload Insurance Document
                                      </label>
                                      <p className="text-xs text-muted-foreground mt-1">
                                        PNG, JPG, PDF up to 10MB
                                      </p>
                                    </div>
                                  </div>
                                  {field.value && (
                                    <div className="mt-2 flex items-center text-sm text-green-600">
                                      <CheckCircle className="h-4 w-4 mr-1" />
                                      Document uploaded
                                    </div>
                                  )}
                                </div>
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="photoUrl"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Profile Photo</FormLabel>
                              <FormControl>
                                <div className="border-2 border-dashed border-gray-300 rounded-lg p-4">
                                  <div className="text-center">
                                    <Upload className="mx-auto h-12 w-12 text-gray-400" />
                                    <div className="mt-4">
                                      <Input
                                        type="file"
                                        accept="image/*"
                                        onChange={(e) => {
                                          const file = e.target.files?.[0];
                                          if (file) {
                                            field.onChange(`/uploads/photo_${Date.now()}.${file.name.split('.').pop()}`);
                                          }
                                        }}
                                        className="hidden"
                                        id="photo"
                                      />
                                      <label
                                        htmlFor="photo"
                                        className="cursor-pointer text-sm font-medium text-primary hover:text-primary/80"
                                      >
                                        Upload Profile Photo
                                      </label>
                                      <p className="text-xs text-muted-foreground mt-1">
                                        PNG, JPG up to 5MB
                                      </p>
                                    </div>
                                  </div>
                                  {field.value && (
                                    <div className="mt-2 flex items-center text-sm text-green-600">
                                      <CheckCircle className="h-4 w-4 mr-1" />
                                      Photo uploaded
                                    </div>
                                  )}
                                </div>
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                    </div>

                    {/* Terms and Conditions */}
                    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow-sm">
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
                                I accept the terms and conditions *
                              </FormLabel>
                              <div className="text-sm text-muted-foreground">
                                I agree to provide delivery services according to platform guidelines,
                                maintain vehicle in good condition, and follow all safety protocols.
                                I understand that my application will be reviewed and I may be contacted
                                for additional verification.
                              </div>
                            </div>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>

                    <div className="bg-green-50 dark:bg-green-950 p-4 rounded-lg border border-green-200 dark:border-green-800">
                      <div className="flex items-start space-x-3">
                        <CheckCircle className="h-5 w-5 text-green-600 mt-0.5" />
                        <div className="text-sm text-green-800 dark:text-green-200">
                          <p className="font-medium mb-2">What happens next?</p>
                          <ul className="space-y-1 text-xs">
                            <li>• Your application will be reviewed within 24-48 hours</li>
                            <li>• You'll receive an email notification about your application status</li>
                            <li>• Upon approval, you can start accepting delivery orders immediately</li>
                            <li>• You'll have access to our delivery partner dashboard and training materials</li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                <Button type="submit" className="w-full btn-primary" disabled={isLoading}>
                  {isLoading ? "Creating account..." : "Create Account"}
                </Button>
              </form>
            </Form>



            <div className="mt-6">
              <div className="text-center">
                <span className="text-muted-foreground">Already have an account? </span>
                <Link href="/login" className="text-primary hover:underline font-medium">
                  Sign in
                </Link>
              </div>
            </div>

            {selectedRole === "shopkeeper" && (
              <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-950 rounded-lg">
                <p className="text-sm text-blue-800 dark:text-blue-200">
                  <strong>Shopkeeper Benefits:</strong>
                  <br />• Create and manage your online store
                  <br />• Reach customers in your local area
                  <br />• Track orders and inventory
                  <br />• No setup fees - start selling immediately
                </p>
              </div>
            )}

            {selectedRole === "delivery_partner" && (
              <div className="mt-6 p-4 bg-green-50 dark:bg-green-950 rounded-lg">
                <p className="text-sm text-green-800 dark:text-green-200">
                  <strong>Delivery Partner Benefits:</strong>
                  <br />• Flexible working hours - work when you want
                  <br />• Competitive delivery fees and bonuses
                  <br />• Weekly payments directly to your account
                  <br />• Support team available 24/7 for assistance
                  <br />• Get started immediately after approval
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
