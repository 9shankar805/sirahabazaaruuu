import { initializeApp } from 'firebase/app';
import { 
  getAuth, 
  GoogleAuthProvider, 
  FacebookAuthProvider, 
  signInWithPopup, 
  signOut, 
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
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

// Auth functions
export const signInWithGoogle = async () => {
  console.log('Attempting Google sign-in with popup...');
  try {
    // First try popup method
    const result = await signInWithPopup(auth, googleProvider);
    return result;
  } catch (error: any) {
    console.error('Popup method failed:', error);
    
    // If popup fails due to internal error, try redirect method
    if (error.code === 'auth/internal-error' || error.code === 'auth/popup-blocked') {
      console.log('Trying redirect method as fallback...');
      const { signInWithRedirect, getRedirectResult } = await import('firebase/auth');
      
      // Check if we're returning from a redirect
      const redirectResult = await getRedirectResult(auth);
      if (redirectResult) {
        return redirectResult;
      }
      
      // Start redirect flow
      await signInWithRedirect(auth, googleProvider);
      return null; // Redirect will handle the return
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

export type { User };

