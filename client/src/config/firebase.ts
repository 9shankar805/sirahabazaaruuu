// Firebase configuration for the client-side application
export const getFirebaseConfig = () => {
  // For development, use hardcoded values since environment variables from .env
  // should match these values based on the .env file content
  const config = {
    apiKey: "AIzaSyBbHSV2EJZ9BPE1C1ZC4_ZNYwFYJIR9VSo",
    authDomain: "myweb-1c1f37b3.firebaseapp.com",
    projectId: "myweb-1c1f37b3",
    storageBucket: "myweb-1c1f37b3.firebasestorage.app",
    messagingSenderId: "774950702828",
    appId: "1:774950702828:web:09c2dfc1198d45244a9fc9",
    measurementId: "G-XH9SP47FYT"
  };

  return config;
};

export const getVapidKey = () => {
  // VAPID key for web push notifications - Updated with correct key
  return "BBeY7MuZB7850MAibtxV4fJxcKYAF3oQxNBB60l1FzHK63IjkTSI9ZFDPW1hmHnKSJPckGFM5gu7JlaCGavnwqA";
};

// Validate Firebase configuration
export const validateFirebaseConfig = (config: any) => {
  const requiredFields = [
    'apiKey',
    'authDomain', 
    'projectId',
    'storageBucket',
    'messagingSenderId',
    'appId'
  ];

  for (const field of requiredFields) {
    if (!config[field]) {
      console.error(`Firebase config missing required field: ${field}`);
      return false;
    }
  }

  return true;
};