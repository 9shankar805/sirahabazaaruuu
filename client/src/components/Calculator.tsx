import { useState, useEffect, useRef, useMemo } from 'react';
import { Calculator as CalculatorIcon, History, Plus, Trash2, Edit, FileText, Printer, X, Moon, Sun, Download, Loader2, Save, Clipboard, Search, Package, Tag, Percent, Info } from 'lucide-react';
import type { CalculatorProduct, CalculatorItem, Calculation } from '@/types/calculator';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { format } from 'date-fns';
import { useToast } from '@/hooks/use-toast';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';

import { Check, ChevronsUpDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
} from '@/components/ui/command';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import { ScrollArea } from '@/components/ui/scroll-area';

interface CalculatorProps {
  isOpen: boolean;
  onClose: () => void;
  products: CalculatorProduct[];
}

const initialItem: Omit<CalculatorItem, 'id'> = { 
  name: '', 
  quantity: 1, 
  rate: 0, 
  discount: 0, 
  tax: 0 
};

export function Calculator({ isOpen, onClose, products }: CalculatorProps) {
  const { toast } = useToast();
  const [calculations, setCalculations] = useState<Calculation[]>([]);
  const [currentItem, setCurrentItem] = useState<Omit<CalculatorItem, 'id'>>(initialItem);
  const [selectedProduct, setSelectedProduct] = useState<CalculatorProduct | null>(null);

  // Log when products change
  useEffect(() => {
    console.log('Calculator received products:', {
      count: products?.length || 0,
      sample: products?.slice(0, 3) || []
    });
    
    // Reset selected product if it's no longer in the products list
    if (selectedProduct && products && products.length > 0) {
      const productExists = products.some(p => p && p.id === selectedProduct.id);
      if (!productExists) {
        console.log('Selected product no longer exists in products list, resetting selection');
        setSelectedProduct(null);
        setCurrentItem(prev => ({ ...prev, name: '' }));
      }
    } else if (selectedProduct && (!products || products.length === 0)) {
      console.log('No products available, resetting selection');
      setSelectedProduct(null);
      setCurrentItem(prev => ({ ...prev, name: '' }));
    }
  }, [products, selectedProduct]);
  const [openProductSelect, setOpenProductSelect] = useState(false);

  const handleProductSelect = (product: CalculatorProduct | null) => {
    if (product) {
      const price = typeof product.price === 'string' ? parseFloat(product.price) : (product.price || 0);
      setSelectedProduct(product);
      setCurrentItem(prev => ({
        ...prev,
        name: product.name,
        rate: price,
        tax: product.taxRate || 0
      }));
      
      toast({
        title: 'Product selected',
        description: `${product.name} added to the form`,
      });
    } else {
      setSelectedProduct(null);
      setCurrentItem(prev => ({ ...prev, name: '' }));
    }
  };
  const [items, setItems] = useState<CalculatorItem[]>([]);
  const [notes, setNotes] = useState('');
  const [currency, setCurrency] = useState('$');
  const [historySearchTerm, setHistorySearchTerm] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [editingItemId, setEditingItemId] = useState<string | null>(null);
  const invoiceRef = useRef<HTMLDivElement>(null);
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'light');
  const [currentInput, setCurrentInput] = useState('0');
  const [previousInput, setPreviousInput] = useState('');
  const [operation, setOperation] = useState('');
  const [subtotal, setSubtotal] = useState(0);
  const [totalDiscount, setTotalDiscount] = useState(0);
  const [totalTax, setTotalTax] = useState(0);
  const [grandTotal, setGrandTotal] = useState(0);
  const [activeTab, setActiveTab] = useState('invoice');

  // Load saved calculations
  useEffect(() => {
    const saved = localStorage.getItem('calculatorHistory');
    if (saved) setCalculations(JSON.parse(saved));
  }, []);

  // Save calculations
  useEffect(() => {
    if (calculations.length > 0) {
      localStorage.setItem('calculatorHistory', JSON.stringify(calculations));
    }
  }, [calculations]);

  const calculateTotal = (item: any) => {
    const totalBeforeDiscount = item.quantity * item.rate;
    const discountAmount = totalBeforeDiscount * (item.discount / 100);
    const totalAfterDiscount = totalBeforeDiscount - discountAmount;
    const taxAmount = totalAfterDiscount * (item.tax / 100);
    const totalWithTax = totalAfterDiscount + taxAmount;
    return { totalWithTax, discountAmount, taxAmount };
  };

  useEffect(() => {
    let sub = 0, discount = 0, tax = 0;
    items.forEach(item => {
      const { totalWithTax, discountAmount, taxAmount } = calculateTotal(item);
      sub += item.quantity * item.rate;
      discount += discountAmount;
      tax += taxAmount;
    });
    setSubtotal(sub);
    setTotalDiscount(discount);
    setTotalTax(tax);
    setGrandTotal(sub - discount + tax);
  }, [items]);

  // Calculator functions
  const inputNumber = (num: string) => {
    setCurrentInput(currentInput === '0' ? num : currentInput + num);
  };

  const handleOperation = (op: string) => {
    setPreviousInput(currentInput);
    setOperation(op);
    setCurrentInput('0');
  };

  const calculate = () => {
    const prev = parseFloat(previousInput);
    const current = parseFloat(currentInput);
    let result = 0;

    switch (operation) {
      case '+': result = prev + current; break;
      case '-': result = prev - current; break;
      case '×': result = prev * current; break;
      case '÷': result = prev / current; break;
    }

    setCurrentInput(result.toString());
    setPreviousInput('');
    setOperation('');
  };

  const addItem = () => {
    if (!currentItem.name || currentItem.quantity <= 0 || currentItem.rate <= 0) {
      toast({ 
        title: 'Invalid Item', 
        description: 'Please fill all item fields correctly.', 
        variant: 'destructive' 
      });
      return;
    }
    
    const newItem: CalculatorItem = { 
      ...currentItem, 
      id: Date.now().toString(),
      // Ensure we have all required fields
      name: currentItem.name || 'Custom Item',
      quantity: currentItem.quantity || 1,
      rate: currentItem.rate || 0,
      discount: currentItem.discount || 0,
      tax: currentItem.tax || 0
    };
    
    setItems([...items, newItem]);
    setCurrentItem(initialItem);
    setSelectedProduct(null);
    
    toast({
      title: 'Item added',
      description: `${newItem.name} added to the invoice`,
    });
  };

  const handleEditItem = (item: CalculatorItem & { total?: number }) => {
    setEditingItemId(item.id || null);
    setCurrentItem({
      name: item.name || '',
      quantity: item.quantity || 1,
      rate: item.rate || 0,
      discount: item.discount || 0,
      tax: item.tax || 0
    });
  };

  const handleUpdateItem = () => {
    if (!editingItemId) return;
    
    setItems(items.map(item => 
      item.id === editingItemId 
        ? { ...currentItem, id: editingItemId } 
        : item
    ));
    setCurrentItem(initialItem);
    setEditingItemId(null);
  };

  const handleRemoveItem = (id: string | undefined) => {
    if (!id) return;
    setItems(items.filter(item => item.id !== id));
  };

  const handleClearAll = () => {
    setItems([]);
    setCurrentItem(initialItem);
    setNotes('');
    setEditingItemId(null);
    toast({ title: 'Cleared', description: 'All items have been cleared.' });
  };

  const handleSaveToHistory = () => {
    if (items.length === 0) {
      toast({ title: 'Cannot Save', description: 'Add at least one item to save.', variant: 'destructive' });
      return;
    }
    setIsSaving(true);
    const newCalculation: Calculation = {
      id: Date.now().toString(),
      items: items.map(item => ({
        ...item,
        total: calculateTotal(item).totalWithTax,
        // Ensure all required properties are included
        name: item.name || 'Unnamed Item',
        quantity: item.quantity || 0,
        rate: item.rate || 0,
        discount: item.discount || 0,
        tax: item.tax || 0
      })),
      subtotal,
      grandTotal,
      timestamp: new Date(),
      currency,
      notes: notes || ''
    };
    setCalculations([newCalculation, ...calculations]);
    setTimeout(() => {
      setIsSaving(false);
      toast({ title: 'Saved!', description: 'Calculation saved to history.' });
    }, 1000);
  };

  const getInvoiceText = () => {
    const invoiceText = `
    Invoice
    Date: ${new Date().toLocaleDateString()}

    Items:
    ${items.map(item => {
      const itemTotal = calculateTotal(item).totalWithTax;
      return `${item.name || 'Unnamed Item'} (Qty: ${item.quantity || 0}, Rate: ${currency}${(item.rate || 0).toFixed(2)}) - ${currency}${itemTotal.toFixed(2)}`;
    }).join('\n    ')}

    Subtotal: ${currency}${subtotal.toFixed(2)}
    Discount: -${currency}${totalDiscount.toFixed(2)}
    Tax: +${currency}${totalTax.toFixed(2)}
    Grand Total: ${currency}${grandTotal.toFixed(2)}

    Notes:
    ${notes || 'No notes'}
  `;
    return invoiceText.trim();
  };

  const handleCopyToClipboard = () => {
    const textToCopy = getInvoiceText();
    navigator.clipboard.writeText(textToCopy).then(() => {
      toast({ title: 'Copied!', description: 'Invoice details copied to clipboard.' });
    }).catch(err => {
      toast({ title: 'Error', description: 'Could not copy to clipboard.', variant: 'destructive' });
      console.error('Failed to copy: ', err);
    });
  };

  const handlePrint = () => {
    // Print logic
  };
  const handleDownload = () => {
    // PDF download logic
  };

  // Load a calculation from history into the current form
  const handleLoadFromHistory = (calculation: Calculation) => {
    // Map the calculation items to match the expected CalculatorItem type
    const mappedItems = calculation.items.map(item => ({
      id: item.id || Date.now().toString(),
      name: item.name || 'Unnamed Item',
      quantity: item.quantity || 0,
      rate: item.rate || 0,
      discount: item.discount || 0,
      tax: item.tax || 0
    }));
    
    setItems(mappedItems);
    setNotes(calculation.notes || '');
    setCurrency(calculation.currency || '$');
    setActiveTab('invoice');
    toast({ 
      title: 'Loaded from History', 
      description: 'Invoice has been loaded for editing.' 
    });
  };

  const handleDeleteFromHistory = (id: string) => {
    setCalculations(calculations.filter(c => c.id !== id));
    toast({ title: 'Deleted', description: 'Calculation removed from history.', variant: 'destructive' });
  };

  const filteredCalculations = useMemo(() => {
    if (!historySearchTerm) return calculations;
    return calculations.filter(calc => {
      const searchTermLower = historySearchTerm.toLowerCase();
      const dateMatch = format(new Date(calc.timestamp), 'yyyy-MM-dd').includes(searchTermLower);
      const itemMatch = calc.items.some(item => item.name.toLowerCase().includes(searchTermLower));
      return dateMatch || itemMatch;
    });
  }, [calculations, historySearchTerm]);

  if (!isOpen) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-6xl w-full max-h-[95vh] flex flex-col p-0 overflow-hidden">
        <DialogHeader className="sr-only">
          <DialogTitle>Calculator</DialogTitle>
          <DialogDescription>Perform calculations and create invoices</DialogDescription>
        </DialogHeader>
        <Card className="w-full h-full flex flex-col shadow-2xl rounded-lg overflow-hidden border-0">
          <CardHeader className="flex flex-row items-center justify-between p-4 border-b">
            <div className="flex items-center gap-3">
              <CalculatorIcon className="h-7 w-7" aria-hidden="true" />
              <CardTitle className="text-2xl">Calculator</CardTitle>
            </div>
            <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close calculator">
              <X className="h-6 w-6" aria-hidden="true" />
              <span className="sr-only">Close</span>
            </Button>
          </CardHeader>
          <CardContent className="p-4 flex-grow overflow-y-auto">
            <Tabs value={activeTab} onValueChange={setActiveTab}>
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="invoice">Invoice</TabsTrigger>
                <TabsTrigger value="basic">Basic Calc</TabsTrigger>
                <TabsTrigger value="history">History</TabsTrigger>
              </TabsList>
              <TabsContent value="invoice" className="mt-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6" ref={invoiceRef}>
                  {/* Left side: Item entry and list */}
                  <div className="space-y-4">
                    <Card>
                      <CardHeader>
                        <CardTitle>Add/Edit Item</CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="space-y-4">
                            <div>
                              <Label>Select Product</Label>
                              <Popover open={openProductSelect} onOpenChange={setOpenProductSelect}>
                                <PopoverTrigger asChild>
                                  <Button
                                    variant="outline"
                                    role="combobox"
                                    className="w-full justify-between"
                                  >
                                    {selectedProduct ? (
                                      <span className="truncate">{selectedProduct.name}</span>
                                    ) : (
                                      <span className="text-muted-foreground">Select a product...</span>
                                    )}
                                    <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
                                  </Button>
                                </PopoverTrigger>
                                <PopoverContent className="w-[300px] p-0" align="start">
                                  <Command>
                                    <CommandInput placeholder="Search products..." />
                                    <CommandEmpty>No products found.</CommandEmpty>
                                    <CommandGroup className="max-h-[300px] overflow-y-auto">
                                      {products && products.length > 0 ? (
                                        products.filter(p => p && p.name).map((product) => (
                                          <CommandItem
                                            key={product.id}
                                            value={product.name}
                                            onSelect={() => {
                                              handleProductSelect(product);
                                              setOpenProductSelect(false);
                                            }}
                                            className="flex items-center justify-between w-full"
                                          >
                                            <div className="flex items-center">
                                              {product.imageUrl ? (
                                                <img
                                                  src={product.imageUrl}
                                                  alt={product.name}
                                                  className="w-8 h-8 object-cover rounded-md mr-3"
                                                />
                                              ) : (
                                                <div className="w-8 h-8 bg-gray-200 rounded-md mr-3 flex items-center justify-center">
                                                  <Package className="w-4 h-4 text-gray-500" />
                                                </div>
                                              )}
                                              <span className="flex-grow">{product.name}</span>
                                            </div>
                                            <Check
                                              className={cn(
                                                'ml-2 h-4 w-4',
                                                selectedProduct?.id === product.id
                                                  ? 'opacity-100'
                                                  : 'opacity-0'
                                              )}
                                            />
                                          </CommandItem>
                                        ))
                                      ) : (
                                        <div className="py-6 text-center text-sm text-muted-foreground">
                                          No products available.
                                        </div>
                                      )}
                                    </CommandGroup>
                                  </Command>
                                </PopoverContent>
                              </Popover>
                            </div>

                            {selectedProduct ? (
                              <Card className="p-3 text-sm bg-muted">
                                <div className="flex items-center gap-3">
                                  {selectedProduct.imageUrl ? (
                                    <img src={selectedProduct.imageUrl} alt={selectedProduct.name} className="w-12 h-12 object-cover rounded-md" />
                                  ) : (
                                    <div className="w-12 h-12 bg-gray-200 rounded-md flex items-center justify-center">
                                      <Package className="w-6 h-6 text-gray-500" />
                                    </div>
                                  )}
                                  <div className="font-semibold text-lg">{selectedProduct.name}</div>
                                </div>
                              </Card>
                            ) : (
                              <div>
                                <Label htmlFor="product-name">Custom Item Name</Label>
                                <Input
                                  id="product-name"
                                  placeholder="e.g., Custom T-Shirt"
                                  value={currentItem.name}
                                  onChange={(e) => setCurrentItem({ ...currentItem, name: e.target.value })}
                                />
                              </div>
                            )}

                            <div className="grid grid-cols-2 gap-4">
                              <div>
                                <Label htmlFor="quantity">Quantity</Label>
                                <Input
                                  id="quantity"
                                  type="number"
                                  placeholder="1"
                                  value={currentItem.quantity}
                                  onChange={(e) => setCurrentItem({ ...currentItem, quantity: parseFloat(e.target.value) || 1 })}
                                />
                              </div>
                              <div>
                                <Label htmlFor="rate">Price</Label>
                                <Input
                                  id="rate"
                                  type="number"
                                  placeholder="0.00"
                                  value={currentItem.rate}
                                  onChange={(e) => setCurrentItem({ ...currentItem, rate: parseFloat(e.target.value) || 0 })}
                                  disabled={!!selectedProduct} // Disable price input if a product is selected
                                />
                              </div>
                              <div className="space-y-1">
                                <div className="flex items-center justify-between">
                                  <Label htmlFor="tax">Tax</Label>
                                  <span className="text-xs text-muted-foreground">%</span>
                                </div>
                                <div className="relative">
                                  <Input 
                                    id="tax" 
                                    type="number" 
                                    placeholder="0" 
                                    min="0"
                                    max="100"
                                    value={currentItem.tax || ''} 
                                    onChange={(e) => setCurrentItem(prev => ({
                                      ...prev, 
                                      tax: Math.min(100, Math.max(0, Number(e.target.value)))
                                    }))}
                                    className="pr-8 [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
                                  />
                                  <Percent className="absolute right-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                                </div>
                              </div>
                            </div>
                            
                            {/* Item total preview */}
                            <div className="mt-3 p-3 bg-muted/30 rounded-md text-sm">
                              <div className="flex justify-between">
                                <span className="text-muted-foreground">Line Total:</span>
                                <span className="font-medium">
                                  {currency}
                                  {(
                                    (currentItem.quantity || 0) * 
                                    (currentItem.rate || 0) * 
                                    (1 - (currentItem.discount || 0) / 100) * 
                                    (1 + (currentItem.tax || 0) / 100)
                                  ).toFixed(2)}
                                </span>
                              </div>
                            </div>
                          </div>
                        </div>
                        <Button onClick={editingItemId ? handleUpdateItem : addItem} className="w-full">
                          {editingItemId ? 'Update Item' : 'Add Item'}
                        </Button>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardHeader>
                        <CardTitle>Items</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Name</TableHead>
                              <TableHead>Qty</TableHead>
                              <TableHead>Rate</TableHead>
                              <TableHead>Total</TableHead>
                              <TableHead>Actions</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {items.map(item => (
                              <TableRow key={item.id}>
                                <TableCell>{item.name}</TableCell>
                                <TableCell>{item.quantity}</TableCell>
                                <TableCell>{currency}{item.rate.toFixed(2)}</TableCell>
                                <TableCell>{currency}{calculateTotal(item).totalWithTax.toFixed(2)}</TableCell>
                                <TableCell className="flex gap-2">
                                  <Button size="icon" variant="ghost" onClick={() => handleEditItem(item)}><Edit className="h-4 w-4" /></Button>
                                  <Button size="icon" variant="ghost" onClick={() => handleRemoveItem(item.id)}><Trash2 className="h-4 w-4" /></Button>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </CardContent>
                    </Card>
                  </div>

                  {/* Right side: Summary and actions */}
                  <div className="space-y-4">
                    <Card>
                      <CardHeader>
                        <CardTitle>Summary</CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-2">
                        <div className="flex justify-between">
                          <span>Subtotal</span>
                          <span>{currency}{subtotal.toFixed(2)}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Discount</span>
                          <span>-{currency}{totalDiscount.toFixed(2)}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Tax</span>
                          <span>+{currency}{totalTax.toFixed(2)}</span>
                        </div>
                        <hr />
                        <div className="flex justify-between font-bold text-lg">
                          <span>Grand Total</span>
                          <span>{currency}{grandTotal.toFixed(2)}</span>
                        </div>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardHeader>
                        <CardTitle>Notes</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <textarea
                          value={notes}
                          onChange={(e) => setNotes(e.target.value)}
                          className="w-full p-2 border rounded"
                          rows={3}
                          placeholder="Add any notes here..."
                        ></textarea>
                      </CardContent>
                    </Card>
                    <Card>
                      {selectedProduct && (
                        <div className="col-span-4 flex items-center gap-4 p-2 bg-muted rounded-lg">
                          {selectedProduct.imageUrl ? (
                            <img src={selectedProduct.imageUrl} alt={selectedProduct.name} className="w-12 h-12 object-cover rounded-md" />
                          ) : (
                            <div className="w-12 h-12 bg-gray-200 rounded-md flex items-center justify-center">
                              <Package className="w-6 h-6 text-gray-500" />
                            </div>
                          )}
                          <div className="font-semibold text-lg">{selectedProduct.name}</div>
                        </div>
                      )}
                      <CardHeader>
                        <CardTitle>Actions</CardTitle>
                      </CardHeader>
                      <CardContent className="grid grid-cols-2 gap-2">
                        <Button onClick={handleSaveToHistory} disabled={isSaving}>
                          {isSaving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />} Save
                        </Button>
                        <Button onClick={handleCopyToClipboard}><Clipboard className="mr-2 h-4 w-4" /> Copy</Button>
                        <Button onClick={handlePrint}><Printer className="mr-2 h-4 w-4" /> Print</Button>
                        <Button onClick={handleDownload}><Download className="mr-2 h-4 w-4" /> Download</Button>
                        <Button onClick={handleClearAll} variant="destructive" className="col-span-2"><Trash2 className="mr-2 h-4 w-4" /> Clear All</Button>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              </TabsContent>
              <TabsContent value="basic" className="mt-4">
                <div className="space-y-2">
                  <div className="p-2 bg-muted rounded text-right">
                    {previousInput} {operation}
                  </div>
                  <div className="p-4 bg-muted rounded text-right text-4xl font-bold">
                    {currentInput}
                  </div>
                </div>
                <div className="grid grid-cols-4 gap-2 mt-4">
                  <Button onClick={() => setCurrentInput('0')} className="col-span-2">C</Button>
                  <Button onClick={() => handleOperation('÷')}>÷</Button>
                  <Button onClick={() => handleOperation('×')}>×</Button>
                  <Button onClick={() => inputNumber('7')}>7</Button>
                  <Button onClick={() => inputNumber('8')}>8</Button>
                  <Button onClick={() => inputNumber('9')}>9</Button>
                  <Button onClick={() => handleOperation('-')}>-</Button>
                  <Button onClick={() => inputNumber('4')}>4</Button>
                  <Button onClick={() => inputNumber('5')}>5</Button>
                  <Button onClick={() => inputNumber('6')}>6</Button>
                  <Button onClick={() => handleOperation('+')}>+</Button>
                  <Button onClick={() => inputNumber('1')}>1</Button>
                  <Button onClick={() => inputNumber('2')}>2</Button>
                  <Button onClick={() => inputNumber('3')}>3</Button>
                  <Button onClick={calculate} className="row-span-2">=</Button>
                  <Button onClick={() => inputNumber('0')} className="col-span-2">0</Button>
                  <Button onClick={() => inputNumber('.')}>.</Button>
                </div>
              </TabsContent>
              <TabsContent value="history" className="mt-4">
                <div className="relative mb-4">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
                  <Input
                    placeholder="Search by item name or date (YYYY-MM-DD)..."
                    value={historySearchTerm}
                    onChange={(e) => setHistorySearchTerm(e.target.value)}
                    className="pl-10 w-full"
                  />
                </div>
                <div className="space-y-4 max-h-[60vh] overflow-y-auto">
                  {filteredCalculations.length > 0 ? (
                    filteredCalculations.map((calc: Calculation) => (
                      <Card key={calc.id}>
                        <CardHeader className="flex flex-row justify-between items-start">
                          <div>
                            <CardTitle className="text-lg">{format(new Date(calc.timestamp), 'PPP p')}</CardTitle>
                            <p className="text-2xl font-bold">{calc.currency}{calc.grandTotal.toFixed(2)}</p>
                          </div>
                          <div className="flex gap-2">
                            <Button size="sm" variant="outline" onClick={() => handleLoadFromHistory(calc)}>Load</Button>
                            <Button size="sm" variant="destructive" onClick={() => handleDeleteFromHistory(calc.id)}>Delete</Button>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <p className="font-medium mb-2">Items:</p>
                          <ul className="list-disc pl-5 text-sm">
                            {calc.items.map((item, index) => {
                              const total = item.quantity * item.rate * (1 - (item.discount / 100)) * (1 + (item.tax / 100));
                              return (
                                <li key={index}>
                                  {item.name} (x{item.quantity}) - {calc.currency}{total.toFixed(2)}
                                </li>
                              );
                            })}
                          </ul>
                        </CardContent>
                      </Card>
                    ))
                  ) : (
                    <p className="text-center text-muted-foreground">No history found.</p>
                  )}
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </DialogContent>
    </Dialog>
  );
}
