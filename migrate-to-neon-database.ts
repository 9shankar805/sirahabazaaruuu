import { Pool } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import * as schema from "./shared/schema";

// Old DigitalOcean Database Configuration
const oldDatabaseUrl = "postgresql://doadmin:AVNS_3UkZ6PqedWGFkdV6amW@db-postgresql-blr1-34567-do-user-23211066-0.d.db.ondigitalocean.com:25060/defaultdb?sslmode=require";

// New Neon Database Configuration
const newDatabaseUrl = "postgresql://neondb_owner:npg_B14cMjkFUhuw@ep-wispy-paper-a1eejnp5-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require";

// Create connection pools
const oldPool = new Pool({
  connectionString: oldDatabaseUrl,
  max: 2,
  ssl: { rejectUnauthorized: false }
});

const newPool = new Pool({
  connectionString: newDatabaseUrl,
  max: 2,
  ssl: { rejectUnauthorized: false }
});

const oldDb = drizzle(oldPool, { schema });
const newDb = drizzle(newPool, { schema });

interface MigrationResult {
  table: string;
  recordsFound: number;
  recordsMigrated: number;
  errors: string[];
}

async function migrateTable(
  tableName: string, 
  sourceDb: any, 
  targetDb: any, 
  sourceTable: any, 
  targetTable: any
): Promise<MigrationResult> {
  const result: MigrationResult = {
    table: tableName,
    recordsFound: 0,
    recordsMigrated: 0,
    errors: []
  };

  try {
    console.log(`\n📋 Migrating table: ${tableName}`);
    
    // Fetch all records from source
    const records = await sourceDb.select().from(sourceTable);
    result.recordsFound = records.length;
    
    console.log(`   Found ${records.length} records in ${tableName}`);
    
    if (records.length === 0) {
      console.log(`   ✅ ${tableName} is empty - nothing to migrate`);
      return result;
    }

    // Insert records into target database in batches
    const batchSize = 50;
    let migratedCount = 0;
    
    for (let i = 0; i < records.length; i += batchSize) {
      const batch = records.slice(i, i + batchSize);
      
      try {
        await targetDb.insert(targetTable).values(batch).onConflictDoNothing();
        migratedCount += batch.length;
        console.log(`   📦 Migrated batch ${Math.floor(i/batchSize) + 1}: ${batch.length} records`);
      } catch (error: any) {
        const errorMsg = `Batch ${Math.floor(i/batchSize) + 1} failed: ${error.message}`;
        result.errors.push(errorMsg);
        console.error(`   ❌ ${errorMsg}`);
      }
    }
    
    result.recordsMigrated = migratedCount;
    console.log(`   ✅ ${tableName} migration completed: ${migratedCount}/${records.length} records migrated`);
    
    return result;
  } catch (error: any) {
    const errorMsg = `Failed to migrate ${tableName}: ${error.message}`;
    result.errors.push(errorMsg);
    console.error(`   ❌ ${errorMsg}`);
    return result;
  }
}

async function migrateAllData() {
  console.log("🚀 Starting data migration from DigitalOcean to Neon database...\n");
  
  const startTime = Date.now();
  const results: MigrationResult[] = [];
  
  try {
    // Test connections
    console.log("🔌 Testing database connections...");
    await oldPool.query('SELECT 1');
    console.log("   ✅ Source database connected");
    
    await newPool.query('SELECT 1');
    console.log("   ✅ Target database connected");
    
    // Migration order based on foreign key dependencies
    const migrationTables = [
      { name: "admin_users", source: schema.adminUsers, target: schema.adminUsers },
      { name: "admins", source: schema.admins, target: schema.admins },
      { name: "users", source: schema.users, target: schema.users },
      { name: "password_reset_tokens", source: schema.passwordResetTokens, target: schema.passwordResetTokens },
      { name: "categories", source: schema.categories, target: schema.categories },
      { name: "stores", source: schema.stores, target: schema.stores },
      { name: "products", source: schema.products, target: schema.products },
      { name: "cart_items", source: schema.cartItems, target: schema.cartItems },
      { name: "wishlist_items", source: schema.wishlistItems, target: schema.wishlistItems },
      { name: "orders", source: schema.orders, target: schema.orders },
      { name: "order_items", source: schema.orderItems, target: schema.orderItems },
      { name: "delivery_partners", source: schema.deliveryPartners, target: schema.deliveryPartners },
      { name: "deliveries", source: schema.deliveries, target: schema.deliveries },
      { name: "delivery_zones", source: schema.deliveryZones, target: schema.deliveryZones },
      { name: "website_visits", source: schema.websiteVisits, target: schema.websiteVisits },
      { name: "notifications", source: schema.notifications, target: schema.notifications },
      { name: "order_tracking", source: schema.orderTracking, target: schema.orderTracking },
      { name: "delivery_location_tracking", source: schema.deliveryLocationTracking, target: schema.deliveryLocationTracking },
      { name: "delivery_routes", source: schema.deliveryRoutes, target: schema.deliveryRoutes },
    ];
    
    // Migrate each table
    for (const table of migrationTables) {
      const result = await migrateTable(
        table.name,
        oldDb,
        newDb,
        table.source,
        table.target
      );
      results.push(result);
    }
    
    // Migration summary
    const endTime = Date.now();
    const duration = ((endTime - startTime) / 1000).toFixed(2);
    
    console.log("\n" + "=".repeat(60));
    console.log("📊 MIGRATION SUMMARY");
    console.log("=".repeat(60));
    
    let totalFound = 0;
    let totalMigrated = 0;
    let totalErrors = 0;
    
    results.forEach(result => {
      totalFound += result.recordsFound;
      totalMigrated += result.recordsMigrated;
      totalErrors += result.errors.length;
      
      const status = result.errors.length === 0 ? "✅" : "⚠️";
      console.log(`${status} ${result.table.padEnd(25)} | Found: ${result.recordsFound.toString().padStart(4)} | Migrated: ${result.recordsMigrated.toString().padStart(4)}`);
      
      if (result.errors.length > 0) {
        result.errors.forEach(error => {
          console.log(`     ❌ ${error}`);
        });
      }
    });
    
    console.log("-".repeat(60));
    console.log(`📈 Total Records Found: ${totalFound}`);
    console.log(`📋 Total Records Migrated: ${totalMigrated}`);
    console.log(`❌ Total Errors: ${totalErrors}`);
    console.log(`⏱️  Migration Duration: ${duration} seconds`);
    
    if (totalErrors === 0) {
      console.log("\n🎉 Migration completed successfully!");
    } else {
      console.log("\n⚠️  Migration completed with some errors. Check logs above for details.");
    }
    
  } catch (error: any) {
    console.error("\n💥 Migration failed:", error.message);
    throw error;
  } finally {
    // Close connections
    console.log("\n🔌 Closing database connections...");
    try {
      await oldPool.end();
      await newPool.end();
      console.log("   ✅ Connections closed");
    } catch (error: any) {
      console.error("   ❌ Error closing connections:", error.message);
    }
  }
}

// Run migration
migrateAllData()
  .then(() => {
    console.log("\n✨ Migration process completed!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("\n💥 Migration failed:", error.message);
    process.exit(1);
  });