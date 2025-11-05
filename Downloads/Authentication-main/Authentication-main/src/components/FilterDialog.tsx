import { useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { FilterIcon } from 'lucide-react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export interface FilterValues {
  minPrice?: number;
  maxPrice?: number;
  minStock?: number;
  maxStock?: number;
  selectedAllergen?: string;
  selectedVariant?: string;
  sku?: string;
  sellerInfo?: string;
  productName?: string;
}

interface FilterDialogProps {
  isAdmin?: boolean;
  onFilterChange: (filters: FilterValues) => void;
  initialFilters: FilterValues;
  options: {
    allergens: string[];
    variants: string[];
  };
}

export function FilterDialog({
  isAdmin = false,
  onFilterChange,
  initialFilters,
  options
}: FilterDialogProps) {
  const [filters, setFilters] = useState<FilterValues>(initialFilters);
  const [open, setOpen] = useState(false);

  const handleFilterChange = (key: keyof FilterValues, value: any) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const handleApply = () => {
    onFilterChange(filters);
    setOpen(false);
  };

  const clearFilters = () => {
    const newFilters = {};
    setFilters(newFilters);
    onFilterChange(newFilters);
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" className="w-full sm:w-auto">
          <FilterIcon className="mr-2 h-4 w-4" />
          Filter
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Filter Products</DialogTitle>
          <DialogDescription>
            Apply filters to find specific products
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-4">
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
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={clearFilters}>
            Clear Filters
          </Button>
          <Button onClick={handleApply}>Apply Filters</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}