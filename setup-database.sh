#!/bin/bash

# Database Setup Script for Siraha Bazaar
# Sets up the new PostgreSQL database connection

echo "🔧 Setting up database configuration..."

# Set the DATABASE_URL environment variable
export DATABASE_URL="postgresql://mydreamv50:123456@139.59.19.202:5432/mydreamv50"

echo "📍 Database URL configured:"
echo "   Host: 139.59.19.202"
echo "   Port: 5432"
echo "   Database: mydreamv50"
echo "   User: mydreamv50"

# Test the connection
echo ""
echo "🔍 Testing database connection..."

node test-db-connection.js

echo ""
echo "💡 Next steps:"
echo "   1. If connection test passes, run: npm run db:push"
echo "   2. To migrate existing data, run: node migrate-to-new-database.js"
echo "   3. Start the application: npm run dev"
echo ""
echo "⚠️  Important: Keep your backup files safe in case rollback is needed"