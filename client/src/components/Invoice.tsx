import React from 'react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Separator } from '@/components/ui/separator';
import type { CalculatorItem } from '@/types/calculator';

interface InvoiceProps {
  items: CalculatorItem[];
  currency: string;
  subTotal: number;
  totalDiscount: number;
  totalTax: number;
  grandTotal: number;
  storeName: string;
  notes?: string;
}

const calculateTotal = (item: CalculatorItem, currency: string) => {
  const total = item.quantity * item.rate * (1 - (item.discount / 100)) * (1 + (item.tax / 100));
  return `${currency}${total.toFixed(2)}`;
};

export const Invoice: React.FC<InvoiceProps> = React.forwardRef<HTMLDivElement, InvoiceProps>(({ 
  items, 
  currency, 
  subTotal, 
  totalDiscount, 
  totalTax, 
  grandTotal, 
  storeName,
  notes
}, ref) => {
  return (
    <div ref={ref} className="p-8 bg-white text-black font-sans">
      {/* Header */}
      <div className="flex justify-between items-center pb-4 border-b-2 border-gray-200">
        <div className="flex items-center">
          <img src="/assets/icon2.png" alt="SirahaBazaar Logo" className="w-16 h-16 mr-4" />
          <div>
            <h1 className="text-3xl font-bold text-gray-800">{storeName}</h1>
            <p className="text-gray-500">Invoice</p>
          </div>
        </div>
        <div className="text-right">
          <p className="text-xl font-semibold">Invoice</p>
          <p className="text-gray-500">Date: {new Date().toLocaleDateString()}</p>
        </div>
      </div>

      {/* Bill To */}
      <div className="my-8">
        <h2 className="text-lg font-semibold text-gray-700">Bill To:</h2>
        <p className="text-gray-600">Valued Customer</p>
      </div>

      {/* Items Table */}
      <Table className="my-8">
        <TableHeader>
          <TableRow className="bg-gray-100">
            <TableHead className="text-gray-700 font-semibold">Item</TableHead>
            <TableHead className="text-center text-gray-700 font-semibold">Quantity</TableHead>
            <TableHead className="text-center text-gray-700 font-semibold">Rate</TableHead>
            <TableHead className="text-right text-gray-700 font-semibold">Total</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map(item => (
            <TableRow key={item.id}>
              <TableCell className="font-medium">{item.name}</TableCell>
              <TableCell className="text-center">{item.quantity}</TableCell>
              <TableCell className="text-center">{currency}{item.rate.toFixed(2)}</TableCell>
              <TableCell className="text-right">{calculateTotal(item, currency)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      {/* Totals */}
      <div className="flex justify-end">
        <div className="w-full md:w-1/2 lg:w-1/3">
          <div className="flex justify-between py-2">
            <span className="text-gray-600">Subtotal</span>
            <span className="font-medium">{currency}{subTotal.toFixed(2)}</span>
          </div>
          <div className="flex justify-between py-2">
            <span className="text-gray-600">Discount</span>
            <span className="font-medium text-green-600">-{currency}{totalDiscount.toFixed(2)}</span>
          </div>
          <div className="flex justify-between py-2">
            <span className="text-gray-600">Tax</span>
            <span className="font-medium text-red-600">+{currency}{totalTax.toFixed(2)}</span>
          </div>
          <Separator className="my-2" />
          <div className="flex justify-between py-2 text-xl font-bold">
            <span className="text-gray-800">Grand Total</span>
            <span className="text-gray-800">{currency}{grandTotal.toFixed(2)}</span>
          </div>
        </div>
      </div>

      {/* Notes */}
      {notes && (
        <div className="mt-8">
          <h3 className="text-lg font-semibold text-gray-700">Notes:</h3>
          <p className="text-gray-600">{notes}</p>
        </div>
      )}

      {/* Footer */}
      <div className="mt-12 pt-4 text-center text-gray-500 border-t-2 border-gray-200">
        <p>Thank you for your business!</p>
        <p>{storeName} | Powered by SirahaBazaar</p>
      </div>
    </div>
  );
});
