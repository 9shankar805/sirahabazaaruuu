declare global {
  interface Window {
    recaptchaVerifier?: any;
  }
}

import { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "wouter";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Eye, EyeOff, Store, User as UserIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { playSound } from "@/lib/soundEffects";
import { FcGoogle } from "react-icons/fc"; // Add this for Google icon (install react-icons if needed)
import { auth } from "@/lib/firebaseAuth";
import { RecaptchaVerifier, signInWithPhoneNumber } from "firebase/auth";
import type { User } from "@shared/schema";

const loginSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

type LoginForm = z.infer<typeof loginSchema>;

export default function Login() {
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isGoogleLoading, setIsGoogleLoading] = useState(false); // Add loading state for Google
  const [showPhoneLogin, setShowPhoneLogin] = useState(false);
  const [phone, setPhone] = useState("");
  const [otp, setOtp] = useState("");
  const [isPhoneLoading, setIsPhoneLoading] = useState(false);
  const [confirmationResult, setConfirmationResult] = useState<any>(null);
  const [isFirebaseReady, setIsFirebaseReady] = useState(false);
  const recaptchaRef = useRef<HTMLDivElement>(null);

  const [, setLocation] = useLocation();
  const { login, loginWithGoogle, user, setUser } = useAuth();
  const { toast } = useToast();

  const form = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      email: "",
      password: "",
    },
  });

  const onSubmit = async (data: LoginForm) => {
    setIsLoading(true);
    try {
      await login(data.email, data.password);
      
      // Play success sound for successful login
      playSound.success();
      
      toast({
        title: "Welcome back!",
        description: "You have been successfully logged in.",
      });
      
      setLocation("/");
    } catch (error) {
      // Play error sound for failed login
      playSound.error();
      
      toast({
        title: "Login failed",
        description: error instanceof Error ? error.message : "Invalid credentials",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Add Google login handler
  const handleGoogleLogin = async () => {
    setIsGoogleLoading(true);
    try {
      if (!isFirebaseReady) {
        throw new Error("Firebase authentication is not ready. Please try again.");
      }
      await loginWithGoogle(); // <-- let context handle user state
      playSound.success();
      toast({
        title: "Welcome back!",
        description: "You have been successfully logged in with Google.",
      });
      setLocation("/");
    } catch (error) {
      playSound.error();
      toast({
        title: "Google Login failed",
        description: error instanceof Error ? error.message : "Google login error",
        variant: "destructive",
      });
    } finally {
      setIsGoogleLoading(false);
    }
  };

  // Phone login handler
  const handlePhoneLogin = async () => {
    setIsPhoneLoading(true);
    try {
      if (!isFirebaseReady) {
        throw new Error("Firebase authentication is not ready. Please try again.");
      }

      // Validate phone number format
      const phoneRegex = /^\+[1-9]\d{1,14}$/;
      if (!phoneRegex.test(phone)) {
        throw new Error("Please enter a valid phone number with country code (e.g., +977XXXXXXXXXX)");
      }

      // Initialize recaptcha if not already done
      if (!window.recaptchaVerifier) {
        try {
          if (auth && typeof auth.app !== 'undefined') {
            window.recaptchaVerifier = new RecaptchaVerifier(
              "recaptcha-container", // <-- ID string as first argument
              { 
                size: "invisible",
                callback: () => {
                  console.log("Recaptcha verified successfully");
                },
                'expired-callback': () => {
                  console.log("Recaptcha expired");
                  window.recaptchaVerifier = null;
                }
              },
              auth // <-- Firebase Auth instance as third argument
            );
          } else {
            throw new Error("Firebase auth not properly initialized");
          }
        } catch (recaptchaError) {
          console.error('Recaptcha initialization error:', recaptchaError);
          throw new Error("Phone verification failed to initialize. Please refresh the page and try again.");
        }
      }

      // Render recaptcha
      try {
        await window.recaptchaVerifier.render();
      } catch (renderError) {
        console.error('Recaptcha render error:', renderError);
        // Clear and recreate recaptcha
        window.recaptchaVerifier = null;
        if (auth && typeof auth.app !== 'undefined') {
          window.recaptchaVerifier = new RecaptchaVerifier(
            "recaptcha-container",
            { size: "invisible" }
          );
          await window.recaptchaVerifier.render();
        }
      }

      if (!auth) {
        throw new Error("Firebase authentication not available.");
      }

      console.log('Sending OTP to phone:', phone);
      const result = await signInWithPhoneNumber(auth, phone, window.recaptchaVerifier);
      setConfirmationResult(result);
      toast({ title: "OTP sent!", description: "Check your phone for the code." });
    } catch (error: any) {
      console.error('Phone login error:', error);
      let errorMessage = error.message || "Failed to send OTP. Please try again.";
      
      // Handle specific Firebase errors
      if (error.code === 'auth/internal-error') {
        errorMessage = "Phone verification failed. Please refresh the page and try again.";
      } else if (error.code === 'auth/invalid-phone-number') {
        errorMessage = "Please enter a valid phone number with country code (e.g., +977XXXXXXXXXX)";
      } else if (error.code === 'auth/too-many-requests') {
        errorMessage = "Too many attempts. Please try again later.";
      } else if (error.code === 'auth/quota-exceeded') {
        errorMessage = "SMS quota exceeded. Please try again later or use email login.";
      } else if (error.code === 'auth/operation-not-allowed') {
        errorMessage = "Phone authentication is not enabled. Please contact support.";
      } else if (error.code === 'auth/captcha-check-failed') {
        errorMessage = "Verification failed. Please refresh the page and try again.";
      }
      
      toast({ 
        title: "Phone Login failed", 
        description: errorMessage, 
        variant: "destructive" 
      });
    } finally {
      setIsPhoneLoading(false);
    }
  };

  // OTP verification handler
  const handleVerifyOtp = async () => {
    setIsPhoneLoading(true);
    try {
      const result = await confirmationResult.confirm(otp);
      playSound.success();
      toast({ title: "Welcome!", description: "You have been logged in with phone." });
      
      const firebaseUser = result.user;
      
      // Use the new Firebase login endpoint
      const response = await fetch("/api/auth/firebase-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          firebaseUid: firebaseUser.uid,
          email: firebaseUser.email,
          phone: firebaseUser.phoneNumber || phone,
          displayName: firebaseUser.displayName || "Phone User",
        }),
      });

      if (response.ok) {
        const responseData = await response.json();
        if (responseData.user) {
          setUser(responseData.user);
          localStorage.setItem("user", JSON.stringify(responseData.user));
          setLocation("/");
          return;
        }
      }

      // Fallback: handle missing backend user
      console.warn("Backend did not return user for phone login. Creating fallback user.");
      const userData: User = {
        id: -1,
        firebaseUid: firebaseUser.uid ?? null,
        email: firebaseUser.email ?? "",
        password: null,
        status: "pending",
        address: "",
        city: null,
        role: "customer",
        phone: firebaseUser.phoneNumber ?? phone,
        username: null,
        fullName: firebaseUser.displayName ?? "Phone User",
        createdAt: new Date(),
        updatedAt: new Date(),
        state: null,
        approvalDate: null,
        approvedBy: null,
        rejectionReason: null,
      };
      setUser(userData);
      localStorage.setItem("user", JSON.stringify(userData));
      setLocation("/");
    } catch (error: any) {
      playSound.error();
      toast({ title: "OTP Verification failed", description: error.message, variant: "destructive" });
    } finally {
      setIsPhoneLoading(false);
    }
  };

  // Check if Firebase auth is ready
  useEffect(() => {
    if (auth && typeof auth.app !== 'undefined') {
      setIsFirebaseReady(true);
    } else {
      console.warn('Firebase auth not properly initialized');
      setIsFirebaseReady(false);
    }
  }, [auth]);

  useEffect(() => {
    if (showPhoneLogin && !window.recaptchaVerifier && auth && isFirebaseReady) {
      try {
        if (auth && typeof auth.app !== 'undefined') {
          window.recaptchaVerifier = new RecaptchaVerifier(
            "recaptcha-container", // <-- ID string as first argument
            { 
              size: "invisible",
              callback: () => {
                console.log("Recaptcha verified successfully");
              },
              'expired-callback': () => {
                console.log("Recaptcha expired");
                window.recaptchaVerifier = null;
              }
            },
            auth // <-- Firebase Auth instance as third argument
          );
        } else {
          console.warn('Firebase auth not properly initialized');
        }
      } catch (error) {
        console.error('Error creating RecaptchaVerifier:', error);
        toast({
          title: "Phone login unavailable",
          description: "Firebase authentication is not properly configured. Please use email login instead.",
          variant: "destructive",
        });
      }
    }
  }, [showPhoneLogin, auth, isFirebaseReady, toast]);

  return (
    <div className="min-h-screen bg-muted flex items-center justify-center py-12">
      <div className="w-full max-w-md">
        <Card>
          <CardHeader className="text-center">
            <div className="flex items-center justify-center mb-4">
              <Store className="h-8 w-8 text-primary mr-2" />
              <span className="text-2xl font-bold text-foreground">Siraha Bazaar</span>
            </div>
            <CardTitle className="text-2xl">Welcome Back</CardTitle>
            <p className="text-muted-foreground">
              Sign in to your account to continue shopping
            </p>
          </CardHeader>
          <CardContent>
            {/* Google Login Button */}
            <Button
              type="button"
              className="w-full mb-4 flex items-center justify-center gap-2 border border-gray-300 bg-white text-black hover:bg-gray-100"
              onClick={handleGoogleLogin}
              disabled={isGoogleLoading || !isFirebaseReady}
            >
              <FcGoogle className="h-5 w-5" />
              {isGoogleLoading ? "Signing in with Google..." : !isFirebaseReady ? "Google login unavailable" : "Sign in with Google"}
            </Button>

            {/* Phone Login Button */}
            <Button
              type="button"
              className="w-full mb-4 flex items-center justify-center gap-2 border border-gray-300 bg-white text-black hover:bg-gray-100"
              onClick={() => setShowPhoneLogin((v) => !v)}
              disabled={isPhoneLoading || !isFirebaseReady}
            >
              📱 {isPhoneLoading ? "Processing..." : !isFirebaseReady ? "Phone login unavailable" : "Sign in with Phone"}
            </Button>

            {/* Phone Login Form */}
            {showPhoneLogin && (
              <div className="mb-4">
                <div id="recaptcha-container" ref={recaptchaRef} />
                <div className="mb-2 p-2 bg-blue-50 dark:bg-blue-950 rounded text-xs text-blue-700 dark:text-blue-300">
                  <p><strong>Note:</strong> Phone login requires a valid phone number with country code (e.g., +977XXXXXXXXXX)</p>
                  <p className="mt-1"><strong>Supported formats:</strong> +977XXXXXXXXXX, +1XXXXXXXXXX, +91XXXXXXXXXX</p>
                </div>
                <Input
                  type="tel"
                  placeholder="Enter phone number (+977XXXXXXXXXX)"
                  value={phone}
                  onChange={(e) => {
                    const value = e.target.value;
                    // Only allow digits, +, and spaces
                    const cleaned = value.replace(/[^\d\s+]/g, '');
                    setPhone(cleaned);
                  }}
                  className="mb-2"
                  pattern="^\+[1-9]\d{1,14}$"
                  title="Enter a valid phone number with country code"
                />
                {!confirmationResult ? (
                  <Button
                    type="button"
                    className="w-full"
                    onClick={handlePhoneLogin}
                    disabled={isPhoneLoading || !phone || phone.length < 10}
                  >
                    {isPhoneLoading ? "Sending OTP..." : "Send OTP"}
                  </Button>
                ) : (
                  <>
                    <Input
                      type="text"
                      placeholder="Enter OTP (6 digits)"
                      value={otp}
                      onChange={(e) => {
                        const value = e.target.value;
                        // Only allow digits
                        const cleaned = value.replace(/\D/g, '');
                        setOtp(cleaned);
                      }}
                      className="mb-2 mt-2"
                      maxLength={6}
                      pattern="\d{6}"
                    />
                    <Button
                      type="button"
                      className="w-full"
                      onClick={handleVerifyOtp}
                      disabled={isPhoneLoading || !otp || otp.length !== 6}
                    >
                      {isPhoneLoading ? "Verifying..." : "Verify OTP"}
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      className="w-full mt-2"
                      onClick={() => {
                        setConfirmationResult(null);
                        setOtp("");
                        if (window.recaptchaVerifier) {
                          window.recaptchaVerifier.clear();
                          window.recaptchaVerifier = null;
                        }
                      }}
                    >
                      Cancel & Try Again
                    </Button>
                  </>
                )}
              </div>
            )}

            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
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
                  name="password"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Password</FormLabel>
                      <FormControl>
                        <div className="relative">
                          <Input
                            type={showPassword ? "text" : "password"}
                            placeholder="Enter your password"
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
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="remember"
                      className="rounded border-gray-300"
                    />
                    <label htmlFor="remember" className="text-sm text-muted-foreground">
                      Remember me
                    </label>
                  </div>
                  <Link href="/forgot-password">
                    <Button
                      type="button"
                      variant="link"
                      className="text-sm text-primary hover:underline p-0 h-auto"
                    >
                      Forgot password?
                    </Button>
                  </Link>
                </div>

                <Button type="submit" className="w-full btn-primary" disabled={isLoading}>
                  {isLoading ? "Signing in..." : "Sign In"}
                </Button>
              </form>
            </Form>



            <div className="mt-6">
              <div className="text-center">
                <span className="text-muted-foreground">Don't have an account? </span>
                <Link href="/register" className="text-primary hover:underline font-medium">
                  Create Account
                </Link>
              </div>
            </div>

            {/* Password Reset Info */}
            <div className="mt-6 border-t pt-6">
              <div className="text-center mb-4">
                <div className="p-3 bg-blue-50 dark:bg-blue-950 rounded-lg border border-blue-200 dark:border-blue-800 mb-4">
                  <p className="text-sm text-blue-800 dark:text-blue-200 mb-2">
                    <strong>Password Reset:</strong>
                  </p>
                  <p className="text-xs text-blue-700 dark:text-blue-300">
                    Enter your email address and click "Forgot password?" to receive reset instructions.
                    Note: Firebase domain authorization may be required for email delivery.
                  </p>
                </div>
                
                <p className="text-sm text-muted-foreground mb-3">Demo Accounts:</p>
                <div className="space-y-2 text-sm">
                  <div className="flex items-center justify-center space-x-2 p-2 bg-muted rounded">
                    <UserIcon className="h-4 w-4" />
                    <span>Customer: customer@example.com</span>
                  </div>
                  <div className="flex items-center justify-center space-x-2 p-2 bg-muted rounded">
                    <Store className="h-4 w-4" />
                    <span>Shopkeeper: shopkeeper@example.com</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Password: password123</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
