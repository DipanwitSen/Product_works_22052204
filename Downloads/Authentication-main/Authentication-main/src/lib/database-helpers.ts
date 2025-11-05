/**
 * Database Helper Functions for the new ProtiMart schema
 * These functions provide common database operations using the new sellers, products, and inventory tables
 */

import { supabase } from "@/integrations/supabase/client";
import type { Database } from "@/integrations/supabase/database.types";

type Sellers = Database["public"]["Tables"]["sellers"]["Row"];
type Products = Database["public"]["Tables"]["products"]["Row"];
type ProductVariants = Database["public"]["Tables"]["product_variants"]["Row"];
type Inventory = Database["public"]["Tables"]["inventory"]["Row"];

/**
 * Get seller information by user ID
 */
export async function getSellerByUserId(userId: string) {
  const { data, error } = await supabase
    .from("sellers")
    .select("*")
    .eq("user_id", userId)
    .single();

  if (error) {
    console.error("Error fetching seller:", error);
    return null;
  }
  return data as Sellers;
}

/**
 * Get all products for a seller with their variants and inventory
 */
export async function getSellerProducts(sellerId: string) {
  const { data, error } = await supabase
    .from("products")
    .select(
      `
      *,
      product_variants(
        *,
        inventory(*)
      ),
      product_images(*)
      `
    )
    .eq("seller_id", sellerId)
    .eq("status", "active");

  if (error) {
    console.error("Error fetching seller products:", error);
    return [];
  }
  return data || [];
}

/**
 * Get product with all its variants and inventory
 */
export async function getProductWithVariants(productId: string) {
  const { data, error } = await supabase
    .from("products")
    .select(
      `
      *,
      product_variants(
        *,
        inventory(*)
      ),
      product_images(*)
      `
    )
    .eq("product_id", productId)
    .single();

  if (error) {
    console.error("Error fetching product:", error);
    return null;
  }
  return data;
}

/**
 * Create a new product
 */
export async function createProduct(
  sellerId: string,
  product: Omit<Database["public"]["Tables"]["products"]["Insert"], "product_id" | "created_at" | "updated_at">
) {
  const { data, error } = await supabase
    .from("products")
    .insert({
      ...product,
      seller_id: sellerId,
      status: "active",
    })
    .select()
    .single();

  if (error) {
    console.error("Error creating product:", error);
    return null;
  }
  return data as Products;
}

/**
 * Create product variants with inventory
 */
export async function createProductVariant(
  productId: string,
  variant: Omit<Database["public"]["Tables"]["product_variants"]["Insert"], "variant_id" | "created_at">
) {
  const { data: variantData, error: variantError } = await supabase
    .from("product_variants")
    .insert({
      ...variant,
      product_id: productId,
      status: "active",
    })
    .select()
    .single();

  if (variantError) {
    console.error("Error creating variant:", variantError);
    return null;
  }

  // Create inventory record
  const { data: inventoryData, error: inventoryError } = await supabase
    .from("inventory")
    .insert({
      variant_id: variantData.variant_id,
      quantity: 0,
      reserved: 0,
    })
    .select()
    .single();

  if (inventoryError) {
    console.error("Error creating inventory:", inventoryError);
    return null;
  }

  return {
    variant: variantData as ProductVariants,
    inventory: inventoryData as Inventory,
  };
}

/**
 * Update product inventory
 */
export async function updateInventory(variantId: string, quantity: number) {
  const { data, error } = await supabase
    .from("inventory")
    .update({ quantity, updated_at: new Date().toISOString() })
    .eq("variant_id", variantId)
    .select()
    .single();

  if (error) {
    console.error("Error updating inventory:", error);
    return null;
  }
  return data as Inventory;
}

/**
 * Get seller bank accounts
 */
export async function getSellerBankAccounts(sellerId: string) {
  const { data, error } = await supabase
    .from("seller_bank_accounts")
    .select("*")
    .eq("seller_id", sellerId);

  if (error) {
    console.error("Error fetching bank accounts:", error);
    return [];
  }
  return data || [];
}

/**
 * Get seller documents
 */
export async function getSellerDocuments(sellerId: string) {
  const { data, error } = await supabase
    .from("seller_documents")
    .select("*")
    .eq("seller_id", sellerId);

  if (error) {
    console.error("Error fetching seller documents:", error);
    return [];
  }
  return data || [];
}

/**
 * Get seller KYC status
 */
export async function getSellerKYCStatus(userId: string) {
  const { data, error } = await supabase
    .from("sellers")
    .select("verification_status, onboarding_status")
    .eq("user_id", userId)
    .single();

  if (error) {
    console.error("Error fetching KYC status:", error);
    return null;
  }
  return data;
}

/**
 * Update seller information
 */
export async function updateSeller(
  userId: string,
  updates: Database["public"]["Tables"]["sellers"]["Update"]
) {
  const { data, error } = await supabase
    .from("sellers")
    .update(updates)
    .eq("user_id", userId)
    .select()
    .single();

  if (error) {
    console.error("Error updating seller:", error);
    return null;
  }
  return data as Sellers;
}
