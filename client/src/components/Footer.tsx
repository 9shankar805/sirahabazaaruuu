import { Link } from "wouter";
import { Store, Facebook, Twitter, Instagram, Youtube, Mail, Phone, Download, Smartphone, ChevronUp, ChevronDown, Music } from "lucide-react";
import { useState } from "react";

export default function Footer() {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <footer className="bg-gray-800 text-white mt-8 mb-20">
      {/* Mobile-First Compact Footer */}
      <div className="max-w-7xl mx-auto px-3 py-3">
        {/* Main Mobile Row */}
        <div className="flex items-center justify-between">
          {/* Left: Brand */}
          <div className="flex items-center space-x-2">
            <img 
              src="/assets/icon2.png" 
              alt="Siraha Bazaar" 
              className="h-6 w-6 object-contain rounded-lg"
            />
          </div>

          {/* Right: Actions */}
          <div className="flex items-center space-x-3">
            {/* Download Button - Mobile Optimized */}
            <a 
              href="/SirahaBazaar.apk" 
              download="SirahaBazaar.apk"
              className="inline-flex items-center space-x-1 bg-blue-600 hover:bg-blue-700 text-white px-2 py-1 rounded text-xs font-medium transition-colors"
            >
              <Download className="h-3 w-3" />
              <span className="hidden xs:inline">App</span>
            </a>

            {/* Social Icons - Minimal */}
            <div className="flex space-x-2">
              <a href="https://www.facebook.com/profile.php?id=61578565817335" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-white transition-colors">
                <Facebook className="h-3.5 w-3.5" />
              </a>
              <a href="https://www.tiktok.com/@sirahabazaar.service?_t=ZS-8ySvLQ8IiG1&_r=1" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-white transition-colors">
                <Music className="h-3.5 w-3.5" />
              </a>
              <a href="https://www.instagram.com/sirahabazaar?igsh=MTJnZnh3cmR1MWkxeQ==" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-white transition-colors">
                <Instagram className="h-3.5 w-3.5" />
              </a>
            </div>
            
            {/* Expand Button */}
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="flex items-center text-gray-300 hover:text-white transition-colors"
            >
              {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>
          </div>
        </div>

        {/* Mobile Copyright */}
        <div className="mt-2 pt-2 border-t border-gray-700">
          <div className="flex flex-col xs:flex-row items-center justify-between space-y-1 xs:space-y-0 text-xs text-gray-400">
            <span>&copy; 2024 Siraha Bazaar</span>
            <div className="flex items-center space-x-1">
              <Mail className="h-3 w-3" />
              <span className="truncate">sirahabazzar@gmail.com</span>
            </div>
          </div>
        </div>
      </div>

      {/* Mobile Expanded Section */}
      {isExpanded && (
        <div className="border-t border-gray-700 bg-gray-900">
          <div className="max-w-7xl mx-auto px-3 py-4">
            {/* Mobile Grid - 2 columns max */}
            <div className="grid grid-cols-2 gap-4 text-xs">
              {/* Quick Links */}
              <div>
                <h4 className="font-semibold mb-2 text-white text-sm">Links</h4>
                <ul className="space-y-1 text-gray-300">
                  <li><Link href="/" className="hover:text-white transition-colors">Home</Link></li>
                  <li><Link href="/products" className="hover:text-white transition-colors">Products</Link></li>
                  <li><a href="#" className="hover:text-white transition-colors">About</a></li>
                  <li><a href="#" className="hover:text-white transition-colors">Contact</a></li>
                </ul>
              </div>

              {/* Categories */}
              <div>
                <h4 className="font-semibold mb-2 text-white text-sm">Shop</h4>
                <ul className="space-y-1 text-gray-300">
                  <li><Link href="/products?category=1" className="hover:text-white transition-colors">Groceries</Link></li>
                  <li><Link href="/products?category=2" className="hover:text-white transition-colors">Clothing</Link></li>
                  <li><Link href="/products?category=3" className="hover:text-white transition-colors">Electronics</Link></li>
                  <li><Link href="/products?category=4" className="hover:text-white transition-colors">Kitchen</Link></li>
                </ul>
              </div>
            </div>

            {/* Contact & Social Row */}
            <div className="mt-4 pt-3 border-t border-gray-700">
              <div className="flex flex-col space-y-2">
                {/* Contact */}
                <div className="flex items-center justify-between text-xs text-gray-300">
                  <div className="flex items-center space-x-2">
                    <Phone className="h-3 w-3" />
                    <span>+9779805916598</span>
                  </div>
                  <span>Siraha, Nepal</span>
                </div>
                
                {/* Social Links */}
                <div className="flex items-center justify-center space-x-4">
                  <a href="https://www.facebook.com/profile.php?id=61578565817335" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-white transition-colors">
                    <Facebook className="h-4 w-4" />
                  </a>
                  <a href="https://www.tiktok.com/@sirahabazaar.service?_t=ZS-8ySvLQ8IiG1&_r=1" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-white transition-colors">
                    <Music className="h-4 w-4" />
                  </a>
                  <a href="#" className="text-gray-300 hover:text-white transition-colors">
                    <Twitter className="h-4 w-4" />
                  </a>
                  <a href="https://www.instagram.com/sirahabazaar?igsh=MTJnZnh3cmR1MWkxeQ==" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-white transition-colors">
                    <Instagram className="h-4 w-4" />
                  </a>
                  <a href="#" className="text-gray-300 hover:text-white transition-colors">
                    <Youtube className="h-4 w-4" />
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </footer>
  );
}
