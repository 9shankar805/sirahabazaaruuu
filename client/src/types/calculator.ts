export interface CalculatorProduct {
  id: number;
  name: string;
  price: number;
  description?: string;
  stock?: number;
  taxRate?: number;
  imageUrl?: string;
}

export interface CalculatorItem {
  id?: string;
  name: string;
  quantity: number;
  rate: number;
  discount: number;
  tax: number;
  total?: number;
}

export interface Calculation {
  id: string;
  items: CalculatorItem[];
  subtotal: number;
  grandTotal: number;
  timestamp: Date;
  currency: string;
  notes?: string;
}
