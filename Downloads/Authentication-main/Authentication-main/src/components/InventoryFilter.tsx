import React from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useFilterOptions } from '@/hooks/useFilterOptions';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { FilterIcon } from 'lucide-react';

interface FilterProps {
  isAdmin?: boolean;
  onFilterChange: (filters: FilterValues) => void;
  allergens: string[];
  variants: string[];
}

export interface FilterValues {
  minPrice?: number;
  maxPrice?: number;
  minStock?: number;
  maxStock?: number;
  selectedAllergen?: string;
  selectedVariant?: string;
  sku?: string;
  sellerInfo?: string; // seller name or phone for admin
  productName?: string;
}

export function InventoryFilter({ isAdmin = false, onFilterChange }: Omit<FilterProps, 'allergens' | 'variants'>) {
  const [filters, setFilters] = React.useState<FilterValues>({});
  const { options, loading } = useFilterOptions();

  const handleFilterChange = (key: keyof FilterValues, value: any) => {
    const newFilters = { ...filters, [key]: value };
    setFilters(newFilters);
    onFilterChange(newFilters);
  };

  const clearFilters = () => {
    setFilters({});
    onFilterChange({});
  };

  return (
    <Sheet>
      <SheetTrigger asChild>
        <Button variant="outline" className="w-full sm:w-auto">
          <FilterIcon className="mr-2 h-4 w-4" />
          Filter
        </Button>
      </SheetTrigger>
      <SheetContent>
        <SheetHeader>
          <SheetTitle>Filter Products</SheetTitle>
          <SheetDescription>
            Apply filters to find specific products
          </SheetDescription>
        </SheetHeader>

        <div className="grid gap-4 py-4">
          {/* Product Name */}
          <div className="grid gap-2">
            <Label htmlFor="productName">Product Name</Label>
            <Input
              id="productName"
              placeholder="Search by product name"
              value={filters.productName || ''}
              onChange={(e) => handleFilterChange('productName', e.target.value)}
            />
          </div>

          {/* Price Range */}
          <div className="grid gap-2">
            <Label>Price Range (₹)</Label>
            <div className="flex gap-2">
              <Input
                type="number"
                placeholder="Min"
                value={filters.minPrice || ''}
                onChange={(e) => handleFilterChange('minPrice', e.target.value ? Number(e.target.value) : undefined)}
              />
              <Input
                type="number"
                placeholder="Max"
                value={filters.maxPrice || ''}
                onChange={(e) => handleFilterChange('maxPrice', e.target.value ? Number(e.target.value) : undefined)}
              />
            </div>
          </div>

          {/* Stock Range */}
          <div className="grid gap-2">
            <Label>Stock Quantity</Label>
            <div className="flex gap-2">
              <Input
                type="number"
                placeholder="Min"
                value={filters.minStock || ''}
                onChange={(e) => handleFilterChange('minStock', e.target.value ? Number(e.target.value) : undefined)}
              />
              <Input
                type="number"
                placeholder="Max"
                value={filters.maxStock || ''}
                onChange={(e) => handleFilterChange('maxStock', e.target.value ? Number(e.target.value) : undefined)}
              />
            </div>
          </div>

          {/* Allergen Filter */}
          <div className="grid gap-2">
            <Label>Allergen</Label>
            <Select
              value={filters.selectedAllergen}
              onValueChange={(value) => handleFilterChange('selectedAllergen', value)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select allergen" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">All Allergens</SelectItem>
                {options.allergens.map((allergen) => (
                  <SelectItem key={allergen} value={allergen}>
                    {allergen}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Variant Filter */}
          <div className="grid gap-2">
            <Label>Variant</Label>
            <Select
              value={filters.selectedVariant}
              onValueChange={(value) => handleFilterChange('selectedVariant', value)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select variant" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">All Variants</SelectItem>
                {options.variants.map((variant) => (
                  <SelectItem key={variant} value={variant}>
                    {variant}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* SKU Filter */}
          <div className="grid gap-2">
            <Label htmlFor="sku">SKU Number</Label>
            <Input
              id="sku"
              placeholder="Search by SKU"
              value={filters.sku || ''}
              onChange={(e) => handleFilterChange('sku', e.target.value)}
            />
          </div>

          {/* Admin-only Seller Search */}
          {isAdmin && (
            <div className="grid gap-2">
              <Label htmlFor="sellerInfo">Seller Name / Phone</Label>
              <Input
                id="sellerInfo"
                placeholder="Search by seller name or phone"
                value={filters.sellerInfo || ''}
                onChange={(e) => handleFilterChange('sellerInfo', e.target.value)}
              />
            </div>
          )}

          {/* Clear Filters Button */}
          <Button variant="outline" onClick={clearFilters} className="mt-2">
            Clear Filters
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}