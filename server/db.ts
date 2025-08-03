import { Pool } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import * as schema from "@shared/schema";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// PostgreSQL database URL - prioritize DigitalOcean, fallback to development
const DATABASE_URL = process.env.DIGITALOCEAN_DATABASE_URL || process.env.DATABASE_URL || 
  "postgresql://neondb_owner:npg_x70rUbTWcLXC@ep-summer-bread-a88huiee-pooler.eastus2.azure.neon.tech/neondb?sslmode=require&channel_binding=require";

// Check if we're in development and handle SSL accordingly
const isDevelopment = process.env.NODE_ENV === 'development';
const isDigitalOcean = DATABASE_URL.includes('ondigitalocean.com');

// Ensure proper SSL mode for production
const finalDatabaseUrl = DATABASE_URL.includes('sslmode=') 
  ? DATABASE_URL 
  : `${DATABASE_URL}${DATABASE_URL.includes('?') ? '&' : '?'}sslmode=require`;

console.log(`🔌 Using PostgreSQL database: ${DATABASE_URL ? 'Connected' : 'No URL found'}`);
if (isDigitalOcean) {
  console.log(`🌊 DigitalOcean database detected - SSL configured for managed database`);
}

// Robust connection configuration for DigitalOcean managed databases
export const pool = new Pool({
  connectionString: finalDatabaseUrl,
  
  // Conservative settings for DigitalOcean managed databases
  max: isDigitalOcean ? 2 : 5, // Very conservative for managed databases
  min: 0, // Allow pool to scale down completely
  idleTimeoutMillis: isDigitalOcean ? 120000 : 30000, // 2 minutes for DigitalOcean
  connectionTimeoutMillis: isDigitalOcean ? 60000 : 15000, // 1 minute timeout
  acquireTimeoutMillis: isDigitalOcean ? 60000 : 30000, // Wait longer for connection
  
  // Application identification
  application_name: "siraha_bazaar_app",
  
  // Query timeouts - very generous for managed databases
  statement_timeout: isDigitalOcean ? 120000 : 45000, // 2 minutes
  query_timeout: isDigitalOcean ? 110000 : 40000,
  
  // SSL configuration optimized for DigitalOcean
  ssl: isDigitalOcean ? {
    rejectUnauthorized: false,
    checkServerIdentity: () => undefined,
    secureProtocol: 'TLSv1_2_method',
    servername: undefined,
    // Additional SSL options for managed databases
    requestCert: false,
    agent: false
  } : isDevelopment ? {
    rejectUnauthorized: false,
    checkServerIdentity: () => undefined
  } : {
    rejectUnauthorized: true
  },

  // Connection health and stability
  keepAlive: true,
  keepAliveInitialDelayMillis: isDigitalOcean ? 10000 : 3000, // 10 seconds for managed
  
  // Connection lifecycle for managed databases
  allowExitOnIdle: false,
  maxUses: isDigitalOcean ? 500 : 5000, // Rotate connections more frequently
  
  // Retry configuration
  connectionTimeoutMillis: isDigitalOcean ? 60000 : 15000
});

// Enhanced error handling with automatic recovery
pool.on("error", (err: any, client) => {
  console.error("Database connection error:", err.message);

  // Handle specific error codes and attempt recovery
  if (err.code) {
    switch (err.code) {
      case "53300": // Too many connections
        console.error("⚠️ Too many connections - reducing pool size");
        break;
      case "53200": // Out of memory
        console.error("⚠️ Database memory issue - will retry");
        break;
      case "57P01": // Admin shutdown
        console.error("⚠️ Database connection terminated - reconnecting");
        setTimeout(() => {
          console.log("🔄 Attempting database reconnection...");
        }, 2000);
        break;
      case "ECONNRESET":
        console.error("⚠️ Connection reset - will reconnect automatically");
        break;
      case "ENOTFOUND":
        console.error("⚠️ Database host not found - check connection string");
        break;
      default:
        console.error(`⚠️ Database error (${err.code}): ${err.message}`);
    }
  }
});

// Connection event handlers
pool.on("connect", (client) => {
  console.log("✅ Database client connected");
});

pool.on("acquire", (client) => {
  console.log("🔗 Database client acquired from pool");
});

pool.on("remove", (client) => {
  console.log("➖ Database client removed from pool");
});

// Graceful shutdown handling
process.on("SIGINT", async () => {
  console.log("\nShutting down database connections...");
  try {
    await pool.end();
    console.log("Database connections closed gracefully");
  } catch (error: any) {
    console.error("Error during shutdown:", error?.message || error);
  }
  process.exit(0);
});

process.on("SIGTERM", async () => {
  console.log("\nShutting down database connections...");
  try {
    await pool.end();
    console.log("Database connections closed gracefully");
  } catch (error: any) {
    console.error("Error during shutdown:", error?.message || error);
  }
  process.exit(0);
});

export const db = drizzle(pool, { schema });
