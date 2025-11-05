import { supabase } from "@/integrations/supabase/client";
import { BundleWithProducts } from "@/types/bundle.types";
import { Tables } from "@/integrations/supabase/database.types";

export type CreateBundleInput = {
  name: string;
  description?: string;
  discount_percentage: number;
  seller_id: string;
  products: {
    product_id: string;
    quantity: number;
  }[];
};

export type UpdateBundleInput = {
  name?: string;
  description?: string;
  discount_percentage?: number;
  products?: {
    product_id: string;
    quantity: number;
  }[];
};

export async function createBundle(input: CreateBundleInput): Promise<BundleWithProducts | null> {
  try {
    // Start a transaction
    const { data: bundle, error: bundleError } = await supabase
      .from("bundles")
      .insert({
        name: input.name,
        description: input.description,
        discount_percentage: input.discount_percentage,
        seller_id: input.seller_id,
        // These will be calculated by the trigger
        total_price: 0,
        discounted_price: 0,
      })
      .select()
      .single();

    if (bundleError) throw bundleError;

    // Insert bundle products
    const bundleProducts = input.products.map(product => ({
      bundle_id: bundle.id,
      product_id: product.product_id,
      quantity: product.quantity
    }));

    const { error: productsError } = await supabase
      .from("bundle_products")
      .insert(bundleProducts);

    if (productsError) throw productsError;

    // Fetch the complete bundle with products
    return getBundleById(bundle.id);

  } catch (error) {
    console.error("Error creating bundle:", error);
    return null;
  }
}

export async function getBundleById(bundleId: string): Promise<BundleWithProducts | null> {
  try {
    // Get the bundle
    const { data: bundle, error: bundleError } = await supabase
      .from("bundles")
      .select("*")
      .eq("id", bundleId)
      .single();

    if (bundleError) throw bundleError;

    // Get all products in the bundle
    const { data: bundleProducts, error: productsError } = await supabase
      .from("bundle_products")
      .select(`
        product:products (*)
      `)
      .eq("bundle_id", bundleId);

    if (productsError) throw productsError;

    const products = bundleProducts.map(bp => bp.product);

    return {
      ...bundle,
      products
    };

  } catch (error) {
    console.error("Error fetching bundle:", error);
    return null;
  }
}

export async function updateBundle(bundleId: string, input: UpdateBundleInput): Promise<BundleWithProducts | null> {
  try {
    // Start with updating the bundle details
    const { error: bundleError } = await supabase
      .from("bundles")
      .update({
        name: input.name,
        description: input.description,
        discount_percentage: input.discount_percentage,
      })
      .eq("id", bundleId);

    if (bundleError) throw bundleError;

    // If products are being updated
    if (input.products) {
      // First delete all existing bundle products
      const { error: deleteError } = await supabase
        .from("bundle_products")
        .delete()
        .eq("bundle_id", bundleId);

      if (deleteError) throw deleteError;

      // Then insert new bundle products
      const bundleProducts = input.products.map(product => ({
        bundle_id: bundleId,
        product_id: product.product_id,
        quantity: product.quantity
      }));

      const { error: productsError } = await supabase
        .from("bundle_products")
        .insert(bundleProducts);

      if (productsError) throw productsError;
    }

    // Return the updated bundle
    return getBundleById(bundleId);

  } catch (error) {
    console.error("Error updating bundle:", error);
    return null;
  }
}

export async function deleteBundle(bundleId: string): Promise<boolean> {
  try {
    const { error } = await supabase
      .from("bundles")
      .delete()
      .eq("id", bundleId);

    return !error;
  } catch (error) {
    console.error("Error deleting bundle:", error);
    return false;
  }
}

export async function listBundles(sellerId?: string): Promise<BundleWithProducts[]> {
  try {
    let query = supabase
      .from("bundles")
      .select(`
        *,
        products:bundle_products (
          product:products (*)
        )
      `);

    if (sellerId) {
      query = query.eq("seller_id", sellerId);
    }

    const { data, error } = await query;

    if (error) throw error;

    return data.map(bundle => ({
      ...bundle,
      products: bundle.products.map((bp: any) => bp.product)
    }));

  } catch (error) {
    console.error("Error listing bundles:", error);
    return [];
  }
}