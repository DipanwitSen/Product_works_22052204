import { useEffect, useState } from 'react';
import { supabase } from '@/integrations/supabase/client';

interface FilterOptions {
  allergens: string[];
  variants: string[];
  priceRange: {
    min: number;
    max: number;
  };
  stockRange: {
    min: number;
    max: number;
  };
}

export function useFilterOptions() {
  const [options, setOptions] = useState<FilterOptions>({
    allergens: [],
    variants: [],
    priceRange: { min: 0, max: 0 },
    stockRange: { min: 0, max: 0 }
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadFilterOptions() {
      try {
        // Fetch all unique allergens from all products
        const { data: products } = await supabase
          .from('products')
          .select('allergens, variants, base_price, stock_quantity');

        const allAllergens = new Set<string>();
        const allVariants = new Set<string>();
        let minPrice = Infinity;
        let maxPrice = -Infinity;
        let minStock = Infinity;
        let maxStock = -Infinity;

        products?.forEach((product) => {
          // Process allergens
          if (product.allergens && Array.isArray(product.allergens)) {
            product.allergens.forEach((allergen: string) => allAllergens.add(allergen));
          }

          // Process variants
          if (product.variants && Array.isArray(product.variants)) {
            product.variants.forEach((variant: any) => {
              if (variant.name) allVariants.add(variant.name);
            });
          }

          // Track price range
          if (product.base_price) {
            minPrice = Math.min(minPrice, product.base_price);
            maxPrice = Math.max(maxPrice, product.base_price);
          }

          // Track stock range
          if (product.stock_quantity) {
            minStock = Math.min(minStock, product.stock_quantity);
            maxStock = Math.max(maxStock, product.stock_quantity);
          }
        });

        setOptions({
          allergens: Array.from(allAllergens).sort(),
          variants: Array.from(allVariants).sort(),
          priceRange: {
            min: minPrice === Infinity ? 0 : minPrice,
            max: maxPrice === -Infinity ? 0 : maxPrice
          },
          stockRange: {
            min: minStock === Infinity ? 0 : minStock,
            max: maxStock === -Infinity ? 0 : maxStock
          }
        });
      } catch (err) {
        console.error('Error loading filter options:', err);
        setError(err instanceof Error ? err.message : 'Failed to load filter options');
      } finally {
        setLoading(false);
      }
    }

    loadFilterOptions();
  }, []);

  return { options, loading, error };
}