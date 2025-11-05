// src/pages/Inventory.tsx
import React, { useEffect, useState, useMemo } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Tables } from "@/integrations/supabase/database.type";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Edit, Trash2, Plus, Filter, Image as ImageIcon } from "lucide-react";

type ProductRow = Tables<"products">;
type ProductImage = Tables<"product_images">;

export default function Inventory() {
  const { toast } = useToast();
  const [products, setProducts] = useState<ProductRow[]>([]);
  const [images, setImages] = useState<Record<string, ProductImage[]>>({});
  const [loading, setLoading] = useState(true);
  const [sellerId, setSellerId] = useState<string | null>(null);

  // Dialog/form state
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingProduct, setEditingProduct] = useState<ProductRow | null>(null);
  const [formName, setFormName] = useState("");
  const [formPrice, setFormPrice] = useState<number | "">("");
  const [formStock, setFormStock] = useState<number | "">("");
  const [formDescription, setFormDescription] = useState("");
  const [formImage, setFormImage] = useState("");
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);

  // Filters
  const [filterKey, setFilterKey] = useState("name");
  const [search, setSearch] = useState("");

  // Load products on mount
  useEffect(() => {
    (async () => {
      setLoading(true);
      const { data: auth } = await supabase.auth.getUser();
      const user = auth?.user;
      if (!user) {
        toast({ title: "Not signed in", variant: "destructive" });
        setLoading(false);
        return;
      }
      setSellerId(user.id);
      await loadProducts(user.id);
      setLoading(false);
    })();
  }, []);

  async function loadProducts(seller_id: string) {
    const { data: prods, error } = await supabase
      .from("products")
      .select("*")
      .eq("seller_id", seller_id)
      .order("created_at", { ascending: false });

    if (error) {
      console.error(error);
      toast({ title: "Error loading products", variant: "destructive" });
      return;
    }

    setProducts(prods || []);

    const { data: imgs } = await supabase
      .from("product_images")
      .select("*")
      .eq("seller_id", seller_id);

    const grouped: Record<string, ProductImage[]> = {};
    imgs?.forEach((img) => {
      if (!grouped[img.product_id]) grouped[img.product_id] = [];
      grouped[img.product_id].push(img);
    });
    setImages(grouped);
  }

  function openDialog(product?: ProductRow) {
    if (product) {
      setEditingProduct(product);
      setFormName(product.title || "");
      setFormPrice(product.base_price || 0);
      setFormStock((product as any).stock_quantity || 0);
      setFormDescription(product.description || "");
      setFormImage(product.image_url || "");
    } else {
      setEditingProduct(null);
      setFormName("");
      setFormPrice("");
      setFormStock("");
      setFormDescription("");
      setFormImage("");
    }
    setDialogOpen(true);
  }

  async function handleSave() {
    if (!sellerId) return;
    if (!formName.trim()) {
      toast({ title: "Enter product name", variant: "destructive" });
      return;
    }

    const payload: any = {
      seller_id: sellerId,
      title: formName.trim(),
      base_price: formPrice || 0,
      stock_quantity: formStock || 0,
      description: formDescription,
      image_url: formImage.trim() || null,
      status: "active",
    };

    try {
      setLoading(true);
      let productId: string;
      if (editingProduct) {
        const { data, error } = await supabase
          .from("products")
          .update(payload)
          .eq("product_id", editingProduct.product_id)
          .select()
          .single();
        if (error) throw error;
        productId = data.product_id;
        toast({ title: "Product updated" });
      } else {
        const { data, error } = await supabase
          .from("products")
          .insert([payload])
          .select()
          .single();
        if (error) throw error;
        productId = data.product_id;
        toast({ title: "Product added" });
      }

      // Upload new files to storage
      for (const file of selectedFiles) {
        const filePath = `${sellerId}/${productId}/${Date.now()}-${file.name}`;
        const { error: uploadError } = await supabase.storage
          .from("product-images")
          .upload(filePath, file);

        if (!uploadError) {
          const { data: urlData } = supabase.storage
            .from("product-images")
            .getPublicUrl(filePath);
          await supabase.from("product_images").insert([
            {
              product_id: productId,
              seller_id: sellerId,
              image_url: urlData.publicUrl,
            },
          ]);
        } else {
          console.error(uploadError);
        }
      }

      setDialogOpen(false);
      setSelectedFiles([]);
      await loadProducts(sellerId);
    } catch (err: any) {
      toast({
        title: "Error saving product",
        description: err.message,
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  }

  async function handleDelete(id: string) {
    if (!window.confirm("Delete this product?")) return;
    try {
      setLoading(true);
      await supabase.from("products").delete().eq("product_id", id);
      toast({ title: "Deleted", description: "Product removed" });
      if (sellerId) await loadProducts(sellerId);
    } catch (err: any) {
      toast({ title: "Error deleting product", description: err.message, variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }

  const filtered = useMemo(() => {
    if (!search.trim()) return products;
    const s = search.trim().toLowerCase();
    return products.filter((p) => {
      if (filterKey === "name") return (p.title || "").toLowerCase().includes(s);
      if (filterKey === "price") return (p.base_price ?? 0).toString().includes(s);
      return true;
    });
  }, [search, filterKey, products]);

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">My Inventory</h1>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button><Plus className="h-4 w-4 mr-2" /> Add Product</Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>{editingProduct ? "Edit Product" : "Add Product"}</DialogTitle>
            </DialogHeader>
            <div className="space-y-3 py-2">
              <Label>Product Name</Label>
              <Input value={formName} onChange={(e) => setFormName(e.target.value)} />

              <Label>Price (₹)</Label>
              <Input type="number" value={formPrice as any} onChange={(e) => setFormPrice(e.target.value === "" ? "" : Number(e.target.value))} />

              <Label>Stock</Label>
              <Input type="number" value={formStock as any} onChange={(e) => setFormStock(e.target.value === "" ? "" : Number(e.target.value))} />

              <Label>Description</Label>
              <Input value={formDescription} onChange={(e) => setFormDescription(e.target.value)} />

              <Label>Image URL (optional)</Label>
              <Input placeholder="https://example.com/image.jpg" value={formImage} onChange={(e) => setFormImage(e.target.value)} />

              <Label>Upload Images</Label>
              <Input type="file" multiple onChange={(e) => setSelectedFiles(Array.from(e.target.files || []))} />

              <div className="flex justify-end gap-2 mt-4">
                <Button variant="ghost" onClick={() => setDialogOpen(false)}>Cancel</Button>
                <Button onClick={handleSave}>{editingProduct ? "Save" : "Add"}</Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center gap-3">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <select className="border rounded p-2 text-sm" value={filterKey} onChange={(e) => setFilterKey(e.target.value)}>
              <option value="name">Product Name</option>
              <option value="price">Price</option>
            </select>
            <Input className="w-60" placeholder={`Search by ${filterKey}`} value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
        </CardHeader>
      </Card>

      {/* Product Grid */}
      <Card>
        <CardContent className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 p-4">
          {loading ? (
            <div className="text-center w-full">Loading...</div>
          ) : filtered.length === 0 ? (
            <div className="text-sm text-muted-foreground">No products found</div>
          ) : (
            filtered.map((p) => (
              <div key={p.product_id} className="border rounded p-3 flex flex-col justify-between">
                <div>
                  <div className="aspect-square bg-muted mb-2 overflow-hidden rounded">
                    {images[p.product_id]?.[0]?.image_url || p.image_url ? (
                      <img
                        src={images[p.product_id]?.[0]?.image_url || p.image_url}
                        alt={p.title}
                        className="object-cover w-full h-full"
                      />
                    ) : (
                      <div className="flex items-center justify-center h-full text-muted-foreground">
                        <ImageIcon className="h-10 w-10" />
                      </div>
                    )}
                  </div>
                  <div className="font-semibold text-lg">{p.title}</div>
                  <div className="text-sm text-muted-foreground mt-1">₹{p.base_price ?? 0}</div>
                  <div className="text-xs mt-1">Stock: {(p as any).stock_quantity ?? 0}</div>
                </div>
                <div className="mt-3 flex gap-2 justify-end">
                  <Button size="sm" variant="ghost" onClick={() => openDialog(p)}>
                    <Edit className="h-4 w-4" />
                  </Button>
                  <Button size="sm" variant="destructive" onClick={() => handleDelete(p.product_id)}>
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
