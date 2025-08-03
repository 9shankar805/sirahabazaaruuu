import { initializeApp } from 'firebase/app';
import { 
  getAuth, 
  GoogleAuthProvider, 
  FacebookAuthProvider, 
  signInWithPopup, 
  signOut, 
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  RecaptchaVerifier,
  signInWithPhoneNumber,
  PhoneAuthProvider,
  signInWithCredential,
  User
} from 'firebase/auth';

// Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyBbHSV2EJZ9BPE1C1ZC4_ZNYwFYJIR9VSo",
  authDomain: "myweb-1c1f37b3.firebaseapp.com",
  projectId: "myweb-1c1f37b3",
  storageBucket: "myweb-1c1f37b3.appspot.com",
  messagingSenderId: "774950702828",
  appId: "1:774950702828:web:09c2dfc1198d45244a9fc9",
  measurementId: "G-XH9SP47FYT"
};

// Debug Firebase configuration
console.log('Firebase config loaded:', {
  apiKey: firebaseConfig.apiKey ? 'Present' : 'Missing',
  authDomain: firebaseConfig.authDomain,
  projectId: firebaseConfig.projectId,
  storageBucket: firebaseConfig.storageBucket,
  messagingSenderId: firebaseConfig.messagingSenderId,
  appId: firebaseConfig.appId ? 'Present' : 'Missing'
});

// Check current domain for Firebase authorization
const currentDomain = window.location.hostname;
console.log('Current domain:', currentDomain);
console.log('Full origin:', window.location.origin);

// Domain authorization check
if (currentDomain.includes('replit.app') || currentDomain.includes('replit.dev')) {
  console.warn('⚠️ DOMAIN AUTHORIZATION REQUIRED:');
  console.warn('You need to add this domain to Firebase Console:');
  console.warn('1. Go to https://console.firebase.google.com/');
  console.warn('2. Select your project: myweb-1c1f37b3');
  console.warn('3. Go to Authentication > Settings > Authorized domains');
  console.warn(`4. Add: ${window.location.hostname}`);
  console.warn(`5. Also add: *.replit.app and *.replit.dev`);
}

// Initialize Firebase
const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);

// Auth providers
export const googleProvider = new GoogleAuthProvider();
export const facebookProvider = new FacebookAuthProvider();

// Configure Google provider
googleProvider.addScope('email');
googleProvider.addScope('profile');
googleProvider.setCustomParameters({
  'prompt': 'select_account'
});

// Auth functions - Optimized for webview apps
export const signInWithGoogle = async () => {
  console.log('Starting Google sign-in for webview app...');
  
  // Check if we're in a webview/mobile app environment
  const isWebView = /webview|wv|android.*; wv|iphone.*mobile/i.test(navigator.userAgent) || 
                   (window.navigator as any).standalone === true ||
                   window.matchMedia('(display-mode: standalone)').matches;
  
  try {
    if (isWebView) {
      // For webview apps, use redirect method directly
      console.log('Webview detected, using redirect method...');
      const { signInWithRedirect, getRedirectResult } = await import('firebase/auth');
      
      // Check if we're returning from a redirect
      const redirectResult = await getRedirectResult(auth);
      if (redirectResult) {
        console.log('Redirect result found:', redirectResult.user?.email);
        return redirectResult;
      }
      
      // Start redirect flow
      console.log('Starting Google redirect flow...');
      await signInWithRedirect(auth, googleProvider);
      return null; // Redirect will handle the return
    } else {
      // For regular browsers, try popup first
      console.log('Regular browser detected, trying popup...');
      const result = await signInWithPopup(auth, googleProvider);
      return result;
    }
  } catch (error: any) {
    console.error('Google sign-in failed:', error);
    
    // Fallback to redirect for any popup failures
    if (error.code === 'auth/popup-blocked' || error.code === 'auth/popup-closed-by-user' || error.code === 'auth/internal-error') {
      console.log('Popup failed, falling back to redirect...');
      const { signInWithRedirect } = await import('firebase/auth');
      await signInWithRedirect(auth, googleProvider);
      return null;
    }
    
    throw error;
  }
};

export const signInWithFacebook = () => {
  console.log('Attempting Facebook sign-in with popup...');
  return signInWithPopup(auth, facebookProvider);
};
export const signOutUser = () => signOut(auth);

// Email/password auth
export const createUserWithEmail = (email: string, password: string) => 
  createUserWithEmailAndPassword(auth, email, password);

export const signInWithEmail = (email: string, password: string) =>
  signInWithEmailAndPassword(auth, email, password);

// Phone authentication functions
export const setupRecaptcha = (elementId: string) => {
  try {
    return new RecaptchaVerifier(auth, elementId, {
      size: 'invisible',
      callback: () => {
        console.log('reCAPTCHA verified successfully');
      },
      'expired-callback': () => {
        console.log('reCAPTCHA expired');
      }
    });
  } catch (error) {
    console.error('Failed to create RecaptchaVerifier:', error);
    throw new Error('Failed to initialize phone verification. Please refresh and try again.');
  }
};

export const sendPhoneOTP = (phoneNumber: string, recaptchaVerifier: RecaptchaVerifier) => {
  return signInWithPhoneNumber(auth, phoneNumber, recaptchaVerifier);
};

export const verifyPhoneOTP = (verificationId: string, code: string) => {
  const credential = PhoneAuthProvider.credential(verificationId, code);
  return signInWithCredential(auth, credential);
};

export type { User, RecaptchaVerifier };

