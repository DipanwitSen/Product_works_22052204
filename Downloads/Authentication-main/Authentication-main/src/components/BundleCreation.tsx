import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { X } from "lucide-react";

interface Product {
  product_id: string;
  title: string;
  base_price: number;
  description: string | null;
  image_urls?: string[];
}

interface BundleCreationProps {
  open: boolean;
  onClose: () => void;
}

export function BundleCreation({ open, onClose }: BundleCreationProps) {
  const [products, setProducts] = useState<Product[]>([]);
  const [selectedProducts, setSelectedProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(true);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [discountPercentage, setDiscountPercentage] = useState<number>(0);
  const { toast } = useToast();

  useEffect(() => {
    loadProducts();
  }, []);

  const loadProducts = async () => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return;

      const { data, error } = await supabase
        .from("products")
        .select("*")
        .eq("seller_id", user.id)
        .eq("status", "active");

      if (error) throw error;
      setProducts(data || []);
    } catch (error) {
      console.error("Error loading products:", error);
      toast({
        title: "Error",
        description: "Failed to load products",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleProductSelect = (productId: string) => {
    const product = products.find(p => p.product_id === productId);
    if (product && !selectedProducts.some(p => p.product_id === productId)) {
      setSelectedProducts([...selectedProducts, product]);
    }
  };

  const removeProduct = (productId: string) => {
    setSelectedProducts(selectedProducts.filter(p => p.product_id !== productId));
  };

  const calculateTotalPrice = () => {
    const originalPrice = selectedProducts.reduce((sum, product) => sum + product.base_price, 0);
    const discountAmount = (originalPrice * discountPercentage) / 100;
    return originalPrice - discountAmount;
  };

  const handleSubmit = async () => {
    if (selectedProducts.length < 2) {
      toast({
        title: "Error",
        description: "Please select at least 2 products for the bundle",
        variant: "destructive",
      });
      return;
    }

    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error("User not authenticated");

      const originalPrice = selectedProducts.reduce((sum, p) => sum + p.base_price, 0);
      const finalPrice = calculateTotalPrice();

      // Create bundle
      const { data: bundle, error: bundleError } = await supabase
        .from("bundles")
        .insert({
          seller_id: user.id,
          title,
          description,
          original_price: originalPrice,
          discount_percentage: discountPercentage,
          final_price: finalPrice,
          thumbnail_url: selectedProducts[0]?.image_urls?.[0] || null
        })
        .select("bundle_id")
        .single();

      if (bundleError) throw bundleError;

      // Add products to bundle
      const bundleProducts = selectedProducts.map(product => ({
        bundle_id: bundle.bundle_id,
        product_id: product.product_id
      }));

      const { error: productsError } = await supabase
        .from("bundle_products")
        .insert(bundleProducts);

      if (productsError) throw productsError;

      toast({
        title: "Success",
        description: "Bundle created successfully",
      });

      onClose();
    } catch (error) {
      console.error("Error creating bundle:", error);
      toast({
        title: "Error",
        description: "Failed to create bundle",
        variant: "destructive",
      });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Create Product Bundle</DialogTitle>
          <DialogDescription>
            Select products to create a discounted bundle
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4 py-4">
          <div className="grid gap-2">
            <Label htmlFor="title">Bundle Title</Label>
            <Input
              id="title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Enter bundle title"
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="description">Description</Label>
            <Textarea
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Describe your bundle"
            />
          </div>

          <div className="grid gap-2">
            <Label>Add Products</Label>
            <Select onValueChange={handleProductSelect}>
              <SelectTrigger>
                <SelectValue placeholder="Select a product" />
              </SelectTrigger>
              <SelectContent>
                {products.map((product) => (
                  <SelectItem
                    key={product.product_id}
                    value={product.product_id}
                    disabled={selectedProducts.some(p => p.product_id === product.product_id)}
                  >
                    {product.title} - ₹{product.base_price}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {selectedProducts.length > 0 && (
            <div className="grid gap-2">
              <Label>Selected Products</Label>
              <div className="flex flex-wrap gap-2">
                {selectedProducts.map((product) => (
                  <Badge
                    key={product.product_id}
                    variant="secondary"
                    className="flex items-center gap-2"
                  >
                    {product.title} - ₹{product.base_price}
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-4 w-4 p-0 hover:bg-transparent"
                      onClick={() => removeProduct(product.product_id)}
                    >
                      <X className="h-3 w-3" />
                    </Button>
                  </Badge>
                ))}
              </div>
            </div>
          )}

          <div className="grid gap-2">
            <Label htmlFor="discount">Discount Percentage</Label>
            <Input
              id="discount"
              type="number"
              min="0"
              max="100"
              value={discountPercentage}
              onChange={(e) => setDiscountPercentage(Number(e.target.value))}
            />
          </div>

          {selectedProducts.length > 0 && (
            <Card>
              <CardContent className="p-4">
                <div className="flex justify-between items-center">
                  <span>Original Price:</span>
                  <span>₹{selectedProducts.reduce((sum, p) => sum + p.base_price, 0)}</span>
                </div>
                <div className="flex justify-between items-center text-green-600 font-semibold">
                  <span>Final Price:</span>
                  <span>₹{calculateTotalPrice()}</span>
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSubmit} disabled={selectedProducts.length < 2}>
            Create Bundle
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}