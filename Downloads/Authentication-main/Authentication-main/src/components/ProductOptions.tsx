import { useState, useEffect } from "react";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { X, Plus } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";

interface Allergen {
  allergen_id: string;
  name: string;
  description: string | null;
}

interface ProductVariant {
  variant_id: string;
  sku: string | null;
  price: number;
}

interface VariantForm {
  sku: string;
  price: number;
  stock_quantity: number;
}

interface ProductVariantSectionProps {
  onVariantsChange: (variants: ProductVariant[]) => void;
  initialVariants?: ProductVariant[];
}

interface AllergenSectionProps {
  onAllergensChange: (allergens: string[]) => void;
  initialAllergens?: string[];
}

export function ProductVariantSection({ onVariantsChange, initialVariants = [] }: ProductVariantSectionProps) {
  const [variants, setVariants] = useState<ProductVariant[]>(initialVariants);
  const [variantForm, setVariantForm] = useState<VariantForm>({
    sku: "",
    price: 0,
    stock_quantity: 0,
  });

  const handleAddVariant = () => {
    if (!variantForm.sku || variantForm.price <= 0) return;

    const newVariant: ProductVariant = {
      variant_id: crypto.randomUUID(),
      sku: variantForm.sku,
      price: variantForm.price,
    };

    const updatedVariants = [...variants, newVariant];
    setVariants(updatedVariants);
    onVariantsChange(updatedVariants);

    // Reset form
    setVariantForm({ sku: "", price: 0, stock_quantity: 0 });
  };

  const removeVariant = (variantId: string) => {
    const updatedVariants = variants.filter((v) => v.variant_id !== variantId);
    setVariants(updatedVariants);
    onVariantsChange(updatedVariants);
  };

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold">Product Variants</h3>
      
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div>
          <Label htmlFor="sku">SKU</Label>
          <Input
            id="sku"
            value={variantForm.sku}
            onChange={(e) => setVariantForm({ ...variantForm, sku: e.target.value })}
            placeholder="Enter SKU"
          />
        </div>
        <div>
          <Label htmlFor="variant-price">Price (₹)</Label>
          <Input
            id="variant-price"
            type="number"
            min="0"
            step="0.01"
            value={variantForm.price}
            onChange={(e) => setVariantForm({ ...variantForm, price: parseFloat(e.target.value) })}
          />
        </div>
        <div className="flex items-end">
          <Button onClick={handleAddVariant} className="w-full">
            <Plus className="mr-2 h-4 w-4" />
            Add Variant
          </Button>
        </div>
      </div>

      {variants.length > 0 && (
        <div className="space-y-2">
          <Label>Added Variants</Label>
          <div className="flex flex-wrap gap-2">
            {variants.map((variant) => (
              <Badge
                key={variant.variant_id}
                variant="secondary"
                className="flex items-center gap-2"
              >
                {variant.sku} - ₹{variant.price}
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-4 w-4 p-0 hover:bg-transparent"
                  onClick={() => removeVariant(variant.variant_id)}
                >
                  <X className="h-3 w-3" />
                </Button>
              </Badge>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function AllergenSection({ onAllergensChange, initialAllergens = [] }: AllergenSectionProps) {
  const [allergens, setAllergens] = useState<Allergen[]>([]);
  const [selectedAllergens, setSelectedAllergens] = useState<string[]>(initialAllergens);

  useEffect(() => {
    loadAllergens();
  }, []);

  const loadAllergens = async () => {
    try {
      const { data, error } = await supabase
        .from("allergens")
        .select("*")
        .order("name");

      if (error) throw error;
      setAllergens(data || []);
    } catch (error) {
      console.error("Error loading allergens:", error);
    }
  };

  const handleAllergenToggle = (allergenId: string) => {
    const updatedAllergens = selectedAllergens.includes(allergenId)
      ? selectedAllergens.filter(id => id !== allergenId)
      : [...selectedAllergens, allergenId];
    
    setSelectedAllergens(updatedAllergens);
    onAllergensChange(updatedAllergens);
  };

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold">Allergens</h3>
      <div className="flex flex-wrap gap-2">
        {allergens.map((allergen) => (
          <Badge
            key={allergen.allergen_id}
            variant={selectedAllergens.includes(allergen.allergen_id) ? "default" : "outline"}
            className="cursor-pointer"
            onClick={() => handleAllergenToggle(allergen.allergen_id)}
          >
            {allergen.name}
          </Badge>
        ))}
      </div>
    </div>
  );
}