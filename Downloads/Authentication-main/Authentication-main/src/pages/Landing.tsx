import { useEffect, useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { Navbar } from "@/components/Navbar";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Search, Filter, Star, Image as ImageIcon, TrendingUp } from "lucide-react";
import heroImage from "@/assets/hero-protimart.jpg";

interface Product {
  product_id: string;
  title: string | null;
  description: string | null;
  base_price: number | null;
  image_url: string | null;
  brand_id: string | null;
  created_at: string | null;
}

interface Brand {
  brand_id: string;
  name: string;
}

export default function Landing() {
  const navigate = useNavigate();
  const [products, setProducts] = useState<Product[]>([]);
  const [brands, setBrands] = useState<Brand[]>([]);
  const [loading, setLoading] = useState(true);

  // 🔹 Filters
  const [search, setSearch] = useState("");
  const [filterBrand, setFilterBrand] = useState<string>("");
  const [minPrice, setMinPrice] = useState<number | "">("");
  const [maxPrice, setMaxPrice] = useState<number | "">("");

  useEffect(() => {
    loadData();
  }, []);

  // 🔹 Fetch all products & brands (public)
  async function loadData() {
    setLoading(true);
    try {
      const [{ data: productsData, error: pErr }, { data: brandsData, error: bErr }] = await Promise.all([
        supabase.from("products").select("*").order("created_at", { ascending: false }),
        supabase.from("brands").select("*").order("name", { ascending: true }),
      ]);

      if (pErr) console.error("Product fetch error:", pErr);
      if (bErr) console.error("Brand fetch error:", bErr);

      setProducts(productsData || []);
      setBrands(brandsData || []);
    } catch (err) {
      console.error("Load error:", err);
    } finally {
      setLoading(false);
    }
  }

  // 🔹 Filter + search logic
  const filteredProducts = useMemo(() => {
    return products.filter((p) => {
      const titleMatch = p.title?.toLowerCase().includes(search.toLowerCase()) ?? false;

      const brandMatch = filterBrand
        ? brands.find((b) => b.brand_id === p.brand_id)?.name?.toLowerCase() === filterBrand.toLowerCase()
        : true;

      const price = p.base_price ?? 0;
      const minOk = minPrice === "" || price >= Number(minPrice);
      const maxOk = maxPrice === "" || price <= Number(maxPrice);

      return titleMatch && brandMatch && minOk && maxOk;
    });
  }, [products, search, filterBrand, minPrice, maxPrice, brands]);

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      {/* 🏞 Hero Section */}
      <div className="relative h-[500px] mt-16">
        <img src={heroImage} alt="ProtiMart Hero" className="w-full h-full object-cover" />
        <div className="absolute inset-0 bg-gradient-to-r from-black/60 to-transparent flex items-center">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <h1 className="text-5xl font-bold text-white mb-4">
              Discover <span className="gradient-text">Quality Products</span>
            </h1>
            <p className="text-xl text-white/90 max-w-2xl">
              Browse top products from trusted sellers and verified brands
            </p>
          </div>
        </div>
      </div>

      {/* 🔍 Filters */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-4">
        <Card>
          <CardContent className="p-4 space-y-4">
            <div className="flex flex-wrap gap-3 items-center">
              <Search className="h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by product name..."
                className="w-60"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />

              <Filter className="h-4 w-4 text-muted-foreground" />
              <select
                className="border rounded-md p-2 text-sm"
                value={filterBrand}
                onChange={(e) => setFilterBrand(e.target.value)}
              >
                <option value="">All Brands</option>
                {brands.map((b) => (
                  <option key={b.brand_id} value={b.name || ""}>
                    {b.name}
                  </option>
                ))}
              </select>

              <div className="flex gap-2 items-center">
                <Label className="text-sm">Price ₹</Label>
                <Input
                  type="number"
                  placeholder="Min"
                  className="w-20"
                  value={minPrice as any}
                  onChange={(e) => setMinPrice(e.target.value === "" ? "" : Number(e.target.value))}
                />
                <span className="text-muted-foreground">-</span>
                <Input
                  type="number"
                  placeholder="Max"
                  className="w-20"
                  value={maxPrice as any}
                  onChange={(e) => setMaxPrice(e.target.value === "" ? "" : Number(e.target.value))}
                />
              </div>

              <Button
                variant="outline"
                onClick={() => {
                  setSearch("");
                  setFilterBrand("");
                  setMinPrice("");
                  setMaxPrice("");
                }}
              >
                Clear
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* 🛍 Product Grid */}
        <div className="flex items-center gap-2 mt-4">
          <TrendingUp className="w-6 h-6 text-primary" />
          <h2 className="text-2xl font-bold gradient-text">All Products</h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6 py-6">
          {loading ? (
            [...Array(8)].map((_, i) => (
              <Card key={i} className="animate-pulse">
                <div className="h-48 bg-muted rounded-t-lg" />
                <CardContent className="p-4 space-y-3">
                  <div className="h-4 bg-muted rounded" />
                  <div className="h-4 bg-muted rounded w-3/4" />
                </CardContent>
              </Card>
            ))
          ) : filteredProducts.length === 0 ? (
            <div className="text-muted-foreground text-center col-span-full py-8">
              No products found
            </div>
          ) : (
            filteredProducts.map((p) => (
              <Card
                key={p.product_id}
                className="group hover:shadow-lg transition cursor-pointer"
                onClick={() => navigate(`/product/${p.product_id}`)}
              >
                <div className="h-48 bg-muted flex items-center justify-center overflow-hidden rounded-t-lg">
                  {p.image_url ? (
                    <img
                      src={p.image_url}
                      alt={p.title || "Product image"}
                      className="object-cover w-full h-full transition-transform group-hover:scale-105"
                    />
                  ) : (
                    <ImageIcon className="w-12 h-12 text-muted-foreground" />
                  )}
                </div>
                <CardContent className="p-4 space-y-2">
                  <h3 className="font-semibold text-lg line-clamp-1">{p.title}</h3>
                  <p className="text-sm text-muted-foreground line-clamp-2">{p.description}</p>
                  <div className="flex items-center justify-between mt-2">
                    <span className="text-xl font-bold text-primary">₹{p.base_price ?? 0}</span>
                    <div className="flex items-center gap-1 text-sm text-muted-foreground">
                      <Star className="w-4 h-4 fill-yellow-400 text-yellow-400" />
                      <span>4.5</span>
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {brands.find((b) => b.brand_id === p.brand_id)?.name || "Unknown Brand"}
                  </p>
                </CardContent>
              </Card>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
