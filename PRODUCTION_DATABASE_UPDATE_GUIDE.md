# Production Database Update Guide - Preserve Your Data

## Your Scenario
✅ **Current**: Website working with your existing database data  
✅ **Future**: Website updates with new database schema changes  
✅ **Goal**: Apply updates without losing existing data, prevent development data from showing  

## Safe Update Strategy

### Method 1: Schema-Only Updates (Recommended)
Apply only structural changes without touching existing data.

```bash
# Step 1: Generate migration files (safe)
npx drizzle-kit generate

# Step 2: Review migrations (shows exactly what changes)
# Check files in ./migrations/ folder

# Step 3: Apply only schema changes
npx drizzle-kit migrate
```

**Benefits:**
- ✅ Preserves all existing data
- ✅ Adds new tables/columns only
- ✅ No data import/export needed

### Method 2: Selective Data Migration
When you need specific new data but not development data.

```bash
# Step 1: Backup your production database
pg_dump "$PRODUCTION_DATABASE_URL" > production-backup.sql

# Step 2: Export only specific new data from development
pg_dump "$DEVELOPMENT_DATABASE_URL" --data-only \
  --table=new_categories \
  --table=new_products \
  > new-data-only.sql

# Step 3: Apply schema changes
npx drizzle-kit migrate

# Step 4: Import only the new data you want
psql "$PRODUCTION_DATABASE_URL" < new-data-only.sql
```

## Complete Update Workflow

### Phase 1: Preparation (Before Updates)
```bash
# 1. Create production backup
./create-production-backup.sh

# 2. Test updates in development first
npm run db:push  # In development environment
npm run dev      # Test everything works

# 3. Generate production migration files
npx drizzle-kit generate
```

### Phase 2: Production Deployment (Safe Update)
```bash
# 1. Deploy code updates (without database changes)
# Deploy your updated website code

# 2. Apply only schema changes to production
npx drizzle-kit migrate --config=production.config.ts

# 3. Restart production application
# Your existing data remains intact
```

### Phase 3: Verification
```bash
# 1. Verify data integrity
./verify-production-data.sh

# 2. Test website functionality
# All existing data should be preserved
# New features should work with existing data
```

## Preventing Development Data Leakage

### Environment-Based Data Filtering
Add data environment flags to prevent development data from showing:

```sql
-- Add environment column to tables
ALTER TABLE products ADD COLUMN environment VARCHAR(20) DEFAULT 'production';
ALTER TABLE stores ADD COLUMN environment VARCHAR(20) DEFAULT 'production';

-- Mark development data
UPDATE products SET environment = 'development' WHERE created_at > '2025-08-01';
UPDATE stores SET environment = 'development' WHERE created_at > '2025-08-01';
```

### Application-Level Filtering
Update your queries to only show production data:

```typescript
// In your API routes
const products = await db.select()
  .from(productsTable)
  .where(eq(productsTable.environment, 'production'));
```

## Safe Migration Scripts

### 1. Production Backup Script
```bash
#!/bin/bash
# File: create-production-backup.sh

DATE=$(date +%Y-%m-%d_%H-%M-%S)
BACKUP_DIR="backups/production/$DATE"
mkdir -p "$BACKUP_DIR"

echo "🛡️ Creating production backup..."

# Full backup
pg_dump "$PRODUCTION_DATABASE_URL" > "$BACKUP_DIR/full-backup.sql"

# Schema only
pg_dump --schema-only "$PRODUCTION_DATABASE_URL" > "$BACKUP_DIR/schema.sql"

# Data only
pg_dump --data-only "$PRODUCTION_DATABASE_URL" > "$BACKUP_DIR/data.sql"

echo "✅ Backup completed: $BACKUP_DIR"
```

### 2. Schema Migration Script
```bash
#!/bin/bash
# File: migrate-production-schema.sh

echo "🔄 Applying schema changes to production..."

# Generate migration files
npx drizzle-kit generate --config=production.config.ts

# Show what will be changed
echo "📋 Review these changes before proceeding:"
ls -la migrations/

read -p "Continue with migration? (y/N): " confirm
if [[ $confirm == "y" ]]; then
  # Apply migrations
  npx drizzle-kit migrate --config=production.config.ts
  echo "✅ Schema migration completed"
else
  echo "❌ Migration cancelled"
fi
```

### 3. Data Verification Script
```bash
#!/bin/bash
# File: verify-production-data.sh

echo "🔍 Verifying production data integrity..."

# Count important tables
psql "$PRODUCTION_DATABASE_URL" -c "
SELECT 
  'users' as table_name, COUNT(*) as count FROM users
UNION ALL
SELECT 
  'products' as table_name, COUNT(*) as count FROM products
UNION ALL
SELECT 
  'orders' as table_name, COUNT(*) as count FROM orders;
"

echo "✅ Data verification completed"
```

## Configuration Files

### Production Drizzle Config
```typescript
// File: production.config.ts
import { defineConfig } from "drizzle-kit";

export default defineConfig({
  out: "./migrations",
  schema: "./shared/schema.ts",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.PRODUCTION_DATABASE_URL,
  },
});
```

### Environment Variables Setup
```bash
# .env.production
PRODUCTION_DATABASE_URL=postgresql://doadmin:AVNS_3UkZ6PqedWGFkdV6amW@db-postgresql-blr1-34567-do-user-23211066-0.d.db.ondigitalocean.com:25060/defaultdb?sslmode=require
NODE_ENV=production
DATA_ENVIRONMENT=production
```

## Best Practices

### ✅ Safe Practices
1. **Always backup** before any schema changes
2. **Test migrations** in development first
3. **Use migrations** instead of db:push for production
4. **Add environment flags** to distinguish data sources
5. **Verify data integrity** after updates

### ❌ Avoid These
1. Never use `npm run db:push` on production
2. Don't import development data to production
3. Avoid dropping tables or columns with data
4. Don't skip backup steps

## Emergency Recovery

### If Something Goes Wrong
```bash
# Stop the application
systemctl stop your-app

# Restore from backup
psql "$PRODUCTION_DATABASE_URL" < "backups/production/DATE/full-backup.sql"

# Restart application
systemctl start your-app
```

## Summary for Your Future Updates

1. **Website Code Updates**: Deploy normally, no database impact
2. **Schema Updates**: Use `npx drizzle-kit migrate` (preserves data)
3. **New Features**: Add new tables/columns safely
4. **Data Protection**: Environment flags prevent development data showing
5. **Rollback Ready**: Always have recent backups

Your existing data will always be preserved, and development data won't appear on the live website.