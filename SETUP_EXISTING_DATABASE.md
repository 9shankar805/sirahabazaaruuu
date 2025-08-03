# Setup Guide: Integrate Your Existing Database

## Overview
This guide helps you safely connect your existing database (with data) to the Siraha Bazaar project without losing any information.

## Quick Start (5 Minutes)

### Step 1: Set Your Database URL
Create or update your `.env` file:
```bash
DATABASE_URL=your_existing_database_connection_string
```

Example:
```bash
DATABASE_URL=postgresql://username:password@host:port/database_name
```

### Step 2: Test Connection
```bash
node check-database-connection.js
```

### Step 3: Analyze Your Database
```bash
node safe-database-migration.js
```

This will:
- ✅ Inspect your existing database structure
- ✅ Compare with project requirements  
- ✅ Create backup scripts
- ✅ Generate safe migration plan

## What Each Script Does

### `check-database-connection.js`
- Tests if your database is accessible
- Shows basic database information
- Counts existing tables
- Quick 30-second health check

### `safe-database-migration.js`
- **Analyzes** your database structure (read-only)
- **Compares** with project schema requirements
- **Creates** backup scripts automatically
- **Generates** step-by-step migration guide
- **No changes** made to your database

## Safety Features

### ✅ What's Safe
- Connection testing
- Database analysis
- Backup creation
- Migration file generation
- Manual table creation

### ❌ What to Avoid
- `npm run db:push` (can destroy data)
- Direct schema modifications
- Table drops or renames

## Expected Outcome

After running the analysis, you'll have:

1. **database-analysis.json** - Complete structure of your database
2. **create-backup.sh** - Automated backup script
3. **SAFE_MIGRATION_GUIDE.md** - Personalized migration steps
4. **Clear recommendations** - Exactly what needs to be done

## Common Scenarios

### Scenario A: Your database has all required tables
- ✅ Project works immediately
- ✅ No migration needed
- ✅ Just connect and run

### Scenario B: Missing some tables
- 🔧 Add only missing tables
- 🛡️ Preserve all existing data
- ✅ Use generated migration files

### Scenario C: Different table structure
- 🔄 Modify project schema to match your database
- 🛡️ Adapt project to your existing structure
- ✅ Keep your data exactly as-is

## Emergency Recovery

If anything goes wrong:
```bash
# Restore from backup (created by scripts)
psql "$DATABASE_URL" < "backups/DATE/full-backup-TIME.sql"
```

## Support

The scripts are designed to be:
- **Read-only** during analysis
- **Safe** for production databases  
- **Detailed** in their reporting
- **Reversible** in their recommendations

Ready to start? Run:
```bash
node check-database-connection.js
```