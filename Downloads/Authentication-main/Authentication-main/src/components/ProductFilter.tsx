import { useState } from "react";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Slider } from "@/components/ui/slider";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Check, Filter } from "lucide-react";

interface FilterOptions {
  minPrice: number;
  maxPrice: number;
  category: string;
  allergens: string[];
}

interface ProductFilterProps {
  onFilterChange: (filters: FilterOptions) => void;
  categories: { category_id: string; name: string }[];
  allergens: { allergen_id: string; name: string }[];
  maxAvailablePrice: number;
}

export function ProductFilter({
  onFilterChange,
  categories,
  allergens,
  maxAvailablePrice,
}: ProductFilterProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [filters, setFilters] = useState<FilterOptions>({
    minPrice: 0,
    maxPrice: maxAvailablePrice,
    category: "",
    allergens: [],
  });

  const handleAllergenToggle = (allergenId: string) => {
    const newAllergens = filters.allergens.includes(allergenId)
      ? filters.allergens.filter(id => id !== allergenId)
      : [...filters.allergens, allergenId];
    
    const newFilters = { ...filters, allergens: newAllergens };
    setFilters(newFilters);
    onFilterChange(newFilters);
  };

  const handlePriceChange = (value: number[]) => {
    const newFilters = { ...filters, minPrice: value[0], maxPrice: value[1] };
    setFilters(newFilters);
    onFilterChange(newFilters);
  };

  const handleCategoryChange = (value: string) => {
    const newFilters = { ...filters, category: value };
    setFilters(newFilters);
    onFilterChange(newFilters);
  };

  const clearFilters = () => {
    const defaultFilters = {
      minPrice: 0,
      maxPrice: maxAvailablePrice,
      category: "",
      allergens: [],
    };
    setFilters(defaultFilters);
    onFilterChange(defaultFilters);
  };

  return (
    <Sheet open={isOpen} onOpenChange={setIsOpen}>
      <SheetTrigger asChild>
        <Button variant="outline" size="sm" className="w-[150px]">
          <Filter className="mr-2 h-4 w-4" />
          Filter Products
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
          <div className="space-y-2">
            <Label>Price Range</Label>
            <div className="pt-2">
              <Slider
                defaultValue={[filters.minPrice, filters.maxPrice]}
                max={maxAvailablePrice}
                step={1}
                value={[filters.minPrice, filters.maxPrice]}
                onValueChange={handlePriceChange}
              />
            </div>
            <div className="flex items-center justify-between">
              <div className="grid gap-2">
                <Label htmlFor="minPrice">Min Price</Label>
                <Input
                  id="minPrice"
                  type="number"
                  value={filters.minPrice}
                  onChange={(e) =>
                    handlePriceChange([parseInt(e.target.value), filters.maxPrice])
                  }
                  className="w-[100px]"
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="maxPrice">Max Price</Label>
                <Input
                  id="maxPrice"
                  type="number"
                  value={filters.maxPrice}
                  onChange={(e) =>
                    handlePriceChange([filters.minPrice, parseInt(e.target.value)])
                  }
                  className="w-[100px]"
                />
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <Label>Category</Label>
            <Select
              value={filters.category}
              onValueChange={handleCategoryChange}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="">All Categories</SelectItem>
                {categories.map((category) => (
                  <SelectItem
                    key={category.category_id}
                    value={category.category_id}
                  >
                    {category.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>Allergens (Free From)</Label>
            <div className="flex flex-wrap gap-2">
              {allergens.map((allergen) => {
                const isSelected = filters.allergens.includes(allergen.allergen_id);
                return (
                  <Badge
                    key={allergen.allergen_id}
                    variant={isSelected ? "default" : "outline"}
                    className="cursor-pointer"
                    onClick={() => handleAllergenToggle(allergen.allergen_id)}
                  >
                    {isSelected && <Check className="mr-1 h-3 w-3" />}
                    {allergen.name}
                  </Badge>
                );
              })}
            </div>
          </div>

          <Button
            variant="outline"
            className="mt-4"
            onClick={clearFilters}
          >
            Clear Filters
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}