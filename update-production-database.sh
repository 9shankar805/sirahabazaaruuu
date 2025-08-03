#!/bin/bash

# Production Database Update Script
# Safe way to update your website with database changes

set -e  # Exit on any error

echo "🚀 Production Database Update Process"
echo "======================================"

# Check if production database URL is set
if [ -z "$PRODUCTION_DATABASE_URL" ]; then
    echo "❌ PRODUCTION_DATABASE_URL environment variable not set"
    echo "💡 Set it to your DigitalOcean database URL"
    exit 1
fi

echo "📊 Current database: $(echo $PRODUCTION_DATABASE_URL | cut -d'@' -f2 | cut -d'/' -f1)"

# Step 1: Create backup
echo ""
echo "Step 1: Creating backup..."
DATE=$(date +%Y-%m-%d_%H-%M-%S)
BACKUP_DIR="backups/production/$DATE"
mkdir -p "$BACKUP_DIR"

echo "🛡️ Backing up production database..."
pg_dump "$PRODUCTION_DATABASE_URL" > "$BACKUP_DIR/full-backup.sql"
echo "✅ Backup saved: $BACKUP_DIR/full-backup.sql"

# Step 2: Generate migrations
echo ""
echo "Step 2: Generating migration files..."
npx drizzle-kit generate
echo "✅ Migration files generated"

# Step 3: Show what will change
echo ""
echo "Step 3: Review changes..."
echo "📋 Migration files created:"
ls -la migrations/ | tail -5

echo ""
read -p "🤔 Do you want to apply these changes to production? (y/N): " confirm

if [[ $confirm != "y" && $confirm != "Y" ]]; then
    echo "❌ Update cancelled. Your database is unchanged."
    exit 0
fi

# Step 4: Apply migrations
echo ""
echo "Step 4: Applying migrations to production..."
npx drizzle-kit migrate
echo "✅ Migrations applied successfully"

# Step 5: Add environment flags to existing data
echo ""
echo "Step 5: Marking existing data as production..."
psql "$PRODUCTION_DATABASE_URL" << 'EOF'
-- Add environment columns if they don't exist
ALTER TABLE products ADD COLUMN IF NOT EXISTS environment VARCHAR(20) DEFAULT 'production';
ALTER TABLE stores ADD COLUMN IF NOT EXISTS environment VARCHAR(20) DEFAULT 'production';
ALTER TABLE users ADD COLUMN IF NOT EXISTS environment VARCHAR(20) DEFAULT 'production';

-- Mark all existing data as production
UPDATE products SET environment = 'production' WHERE environment IS NULL;
UPDATE stores SET environment = 'production' WHERE environment IS NULL;
UPDATE users SET environment = 'production' WHERE environment IS NULL;

-- Show updated counts
SELECT 'products' as table_name, COUNT(*) as total, 
       COUNT(*) FILTER (WHERE environment = 'production') as production_data
FROM products
UNION ALL
SELECT 'stores' as table_name, COUNT(*) as total,
       COUNT(*) FILTER (WHERE environment = 'production') as production_data
FROM stores
UNION ALL
SELECT 'users' as table_name, COUNT(*) as total,
       COUNT(*) FILTER (WHERE environment = 'production') as production_data
FROM users;
EOF

echo "✅ Environment flags added"

# Step 6: Verification
echo ""
echo "Step 6: Verifying update..."
echo "📊 Final data status:"
psql "$PRODUCTION_DATABASE_URL" -c "
SELECT 
  schemaname, tablename, 
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables 
WHERE schemaname = 'public' 
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC 
LIMIT 10;
"

echo ""
echo "🎉 Production database update completed successfully!"
echo ""
echo "📋 Summary:"
echo "   ✅ Backup created: $BACKUP_DIR"
echo "   ✅ Schema updated with new tables/columns"
echo "   ✅ Existing data preserved and marked as production"
echo "   ✅ Ready for deployment"
echo ""
echo "🚀 Next steps:"
echo "   1. Deploy your updated website code"
echo "   2. Test the website with updated database"
echo "   3. Your existing data will show, development data won't"