import { Tables } from "@/integrations/supabase/database.types";

export interface Bundle extends Tables<"bundles"> {
  id: string;
  name: string;
  description: string | null;
  discount_percentage: number;
  seller_id: string;
  total_price: number;
  discounted_price: number;
  created_at: string;
  status: "active" | "inactive" | "archived";
}

export interface BundleProduct extends Tables<"bundle_products"> {
  bundle_id: string;
  product_id: string;
  quantity: number;
}

export interface BundleWithProducts extends Bundle {
  products: Tables<"products">[];
}