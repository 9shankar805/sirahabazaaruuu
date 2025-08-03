# Siraha Bazaar - Multi-Vendor E-commerce Platform

A comprehensive multi-vendor e-commerce marketplace built with modern web technologies. The platform enables multiple vendors to sell products through a unified marketplace while providing customers with a seamless shopping experience, real-time order tracking, and delivery management.

## Features

### Core Functionality
- **Multi-vendor Support** - Separate dashboards for store owners and customers
- **Real-time Order Tracking** - GPS-based delivery tracking with WebSocket updates
- **Advanced Admin Panel** - Comprehensive platform management and analytics
- **Payment Integration** - Stripe and PayPal support for secure transactions
- **Notification System** - Real-time push notifications and email alerts
- **Responsive Design** - Mobile-first design with progressive web app features

### User Roles
- **Customers** - Browse, shop, track orders, manage wishlist
- **Store Owners** - Manage inventory, process orders, view analytics
- **Delivery Partners** - Accept deliveries, track routes, update status
- **Administrators** - Platform oversight, user management, system configuration

## Quick Start for VS Code

### Prerequisites

1. **Node.js** (version 18 or higher) - Download from [nodejs.org](https://nodejs.org/)
2. **PostgreSQL** - Download from [postgresql.org](https://www.postgresql.org/download/)
3. **VS Code** - Download from [code.visualstudio.com](https://code.visualstudio.com/)

### Setup Steps

1. **Clone or download** this project to your computer
2. **Open the project folder** in VS Code
3. **Install dependencies**:
   ```bash
   npm install
   ```

4. **Setup database**:
   - Create a new PostgreSQL database
   - Copy `.env.example` to `.env`
   - Update the DATABASE_URL in `.env` with your database connection string:
     ```
     DATABASE_URL=postgresql://username:password@localhost:5432/your_database_name
     ```

5. **Initialize database tables**:
   ```bash
   npm run db:push
   ```

6. **Start the application**:
   ```bash
   npm run dev
   ```

7. **Open your browser** and visit `http://localhost:5000`

## Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run start` - Start production server
- `npm run db:push` - Push database schema changes
- `npm run db:studio` - Open database management interface

## Project Structure

```
├── client/                 # React frontend
│   ├── src/
│   │   ├── components/     # Reusable UI components
│   │   ├── hooks/          # Custom React hooks
│   │   └── pages/          # Application pages
├── server/                 # Node.js backend
│   ├── routes.ts           # API endpoints
│   └── storage.ts          # Database operations
├── shared/                 # Shared types and schemas
│   └── schema.ts           # Database schema definitions
└── package.json            # Dependencies and scripts
```

## Technology Stack

- **Frontend**: React, TypeScript, Tailwind CSS, Wouter (routing)
- **Backend**: Node.js, Express, TypeScript
- **Database**: PostgreSQL with Drizzle ORM
- **UI Components**: Radix UI primitives
- **Maps**: Leaflet for store locations
- **Forms**: React Hook Form with Zod validation

## Default Login

For testing purposes, you can create an admin account or use the registration form to create a customer account.

## Troubleshooting

### Database Connection Issues
- Ensure PostgreSQL is running
- Check your DATABASE_URL in the `.env` file
- Verify database credentials and database name

### Port Already in Use
- The app runs on port 5000 by default
- If port 5000 is busy, you can change it in the server configuration

### Dependencies Issues
- Try deleting `node_modules` and running `npm install` again
- Ensure you're using Node.js version 18 or higher

## Production Deployment

### Deployment Readiness Check
Before deploying, run the verification script:
```bash
node deployment-check.js
```

### Environment Variables for Production
```env
# Required
DATABASE_URL=postgresql://user:pass@host:5432/database
NODE_ENV=production

# Optional Services (Enhance functionality)
HERE_API_KEY=your_here_maps_api_key
STRIPE_SECRET_KEY=sk_live_...
SENDGRID_API_KEY=SG.xxx
VAPID_PUBLIC_KEY=your_vapid_public_key
VAPID_PRIVATE_KEY=your_vapid_private_key
```

### Build and Deploy
1. **Build for production**:
   ```bash
   npm run build
   ```

2. **Start production server**:
   ```bash
   npm run start
   ```

### Default Admin Access
- **URL**: `/admin-login`
- **Email**: admin@sirabazaar.com
- **Password**: admin123
- **Important**: Change these credentials immediately in production

## Support

If you encounter any issues:
1. Run `node deployment-check.js` to verify system status
2. Check console logs for error messages
3. Verify database connectivity and environment variables
4. Ensure all required services are properly configured

## Documentation

- **Architecture**: See `replit.md` for comprehensive technical documentation
- **API Reference**: Endpoints documented in `server/routes.ts`
- **Database Schema**: Full schema in `shared/schema.ts`

---

Built with modern web technologies for scalable e-commerce solutions