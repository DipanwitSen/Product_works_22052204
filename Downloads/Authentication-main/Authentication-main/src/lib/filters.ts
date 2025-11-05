import { FilterValues } from '@/components/InventoryFilter';
import { SupabaseClient } from '@supabase/supabase-js';

export async function applyProductFilters(
  supabase: SupabaseClient,
  filters: FilterValues,
  isAdmin: boolean,
  userId: string
) {
  let query = supabase
    .from('products')
    .select(`
      *,
      seller:seller_id(
        full_name,
        phone_number
      )
    `);

  // Apply seller filter for admin or restrict to current seller
  if (isAdmin) {
    if (filters.sellerInfo) {
      query = query.or(`seller.full_name.ilike.%${filters.sellerInfo}%,seller.phone_number.ilike.%${filters.sellerInfo}%`);
    }
  } else {
    query = query.eq('seller_id', userId);
  }

  // Apply filters
  if (filters.productName) {
    query = query.or(`title.ilike.%${filters.productName}%,name.ilike.%${filters.productName}%`);
  }

  if (filters.minPrice) {
    query = query.gte('base_price', filters.minPrice);
  }

  if (filters.maxPrice) {
    query = query.lte('base_price', filters.maxPrice);
  }

  if (filters.minStock) {
    query = query.gte('stock_quantity', filters.minStock);
  }

  if (filters.maxStock) {
    query = query.lte('stock_quantity', filters.maxStock);
  }

  if (filters.sku) {
    query = query.contains('variants', [{ sku: filters.sku }]);
  }

  if (filters.selectedAllergen) {
    query = query.contains('allergens', [filters.selectedAllergen]);
  }

  if (filters.selectedVariant) {
    query = query.contains('variants', [{ name: filters.selectedVariant }]);
  }

  return query;
}