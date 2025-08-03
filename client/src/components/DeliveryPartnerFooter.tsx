import { Link } from "wouter";
import { Truck, Phone, Mail, MapPin, Clock } from "lucide-react";

export default function DeliveryPartnerFooter() {
  return (
    <footer className="bg-blue-800 text-blue-100 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Delivery Partner Branding */}
          <div className="col-span-1 md:col-span-1">
            <div className="flex items-center space-x-2 mb-4">
              <Truck className="h-6 w-6" />
              <span className="text-lg font-bold text-white">Siraha Delivery</span>
            </div>
            <p className="text-sm">
              Professional delivery partner portal for Siraha Bazaar marketplace.
            </p>
          </div>

          {/* Quick Links */}
          <div>
            <h3 className="text-white font-semibold mb-4">Quick Links</h3>
            <ul className="space-y-2 text-sm">
              <li>
                <Link href="/delivery-partner/dashboard" className="hover:text-white">
                  Dashboard
                </Link>
              </li>
              <li>
                <Link href="/delivery-partner/notifications" className="hover:text-white">
                  Notifications
                </Link>
              </li>
              <li>
                <Link href="/delivery-partner/tracking" className="hover:text-white">
                  Live Tracking
                </Link>
              </li>
              <li>
                <Link href="/delivery-partner/earnings" className="hover:text-white">
                  Earnings
                </Link>
              </li>
            </ul>
          </div>

          {/* Support */}
          <div>
            <h3 className="text-white font-semibold mb-4">Support</h3>
            <ul className="space-y-2 text-sm">
              <li className="flex items-center space-x-2">
                <Phone className="h-4 w-4" />
                <span>+977-123-456-789</span>
              </li>
              <li className="flex items-center space-x-2">
                <Mail className="h-4 w-4" />
                <span>delivery@sirahazaar.com</span>
              </li>
              <li className="flex items-center space-x-2">
                <Clock className="h-4 w-4" />
                <span>24/7 Support</span>
              </li>
            </ul>
          </div>

          {/* Service Areas */}
          <div>
            <h3 className="text-white font-semibold mb-4">Service Areas</h3>
            <ul className="space-y-2 text-sm">
              <li className="flex items-center space-x-2">
                <MapPin className="h-4 w-4" />
                <span>Siraha District</span>
              </li>
              <li className="flex items-center space-x-2">
                <MapPin className="h-4 w-4" />
                <span>Lahan Municipality</span>
              </li>
              <li className="flex items-center space-x-2">
                <MapPin className="h-4 w-4" />
                <span>Janakpur Sub-Metro</span>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom Section */}
        <div className="border-t border-blue-700 mt-8 pt-8 flex flex-col md:flex-row justify-between items-center">
          <p className="text-sm">
            © 2024 Siraha Bazaar Delivery. All rights reserved.
          </p>
          <div className="flex space-x-6 mt-4 md:mt-0 text-sm">
            <Link href="/privacy" className="hover:text-white">
              Privacy Policy
            </Link>
            <Link href="/terms" className="hover:text-white">
              Terms of Service
            </Link>
            <Link href="/delivery-guidelines" className="hover:text-white">
              Delivery Guidelines
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
}