import { createRoot } from "react-dom/client";
import App from "./App";
import TestApp from "./TestApp";
import ErrorBoundary from "./components/ErrorBoundary";
import "./index.css";
import "./utils/androidFCMHandler";
import { PWAService } from "./utils/pwa";

// Handle unhandled promise rejections at the global level
window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', event.reason);
  // Prevent the default error display
  event.preventDefault();
});

// Handle uncaught errors
window.addEventListener('error', (event) => {
  console.error('Uncaught error:', event.error);
});

try {
  console.log("Starting React app initialization...");
  
  const rootElement = document.getElementById("root");
  if (!rootElement) {
    throw new Error("Root element not found");
  }
  
  console.log("Root element found, creating React root...");
  
  // Show immediate loading indicator
  rootElement.innerHTML = '<div style="padding: 20px; text-align: center; font-family: Arial, sans-serif;">🚀 Loading Siraha Bazaar...</div>';
  
  const root = createRoot(rootElement);
  
  // Test if basic React rendering works
  const isTestMode = window.location.search.includes('test=true');
  
  console.log(`Rendering app in ${isTestMode ? 'test' : 'normal'} mode...`);
  
  root.render(
    <ErrorBoundary>
      {isTestMode ? <TestApp /> : <App />}
    </ErrorBoundary>
  );
  
  console.log("React app mounted successfully");
  
  // Initialize PWA features
  PWAService.initialize().then(() => {
    console.log("PWA features initialized");
  }).catch((error) => {
    console.error("PWA initialization failed:", error);
  });
} catch (error: any) {
  console.error("Failed to mount React app:", error);
  const errorMessage = error?.message || String(error);
  document.body.innerHTML = `<div style="padding: 20px; color: red; text-align: center;">Error mounting React app: ${errorMessage}</div>`;
}
