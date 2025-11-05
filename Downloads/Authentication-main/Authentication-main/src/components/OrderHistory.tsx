import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { supabase } from "@/integrations/supabase/client";

interface OrderRow {
  id: string;
  created_at: string;
  customer_name: string | null;
  customer_email: string | null;
  product_id: string | null;
  bundle_id: string | null;
  quantity: number;
  total_amount: number;
  status: string;
  product?: { name?: string; title?: string };
  bundle?: { title?: string };
}

export function OrderHistory({ sellerId }: { sellerId: string | null }) {
  const [orders, setOrders] = useState<OrderRow[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!sellerId) return;
    loadOrders();
  }, [sellerId]);

  const loadOrders = async () => {
    setLoading(true);
    try {
      const { data, error } = await (supabase as any)
        .from("orders")
        .select(`*, product:products (name,title), bundle:bundles (title)`)
        .eq("seller_id", sellerId)
        .order("created_at", { ascending: false })
        .limit(20);

      if (error) throw error;
      setOrders(data || []);
    } catch (err) {
      console.error("Error loading orders:", err);
      setOrders([]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Orders</CardTitle>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="p-4 text-center">Loading orders...</div>
        ) : orders.length === 0 ? (
          <div className="p-4 text-sm text-muted-foreground">No recent orders</div>
        ) : (
          <div className="space-y-3">
            {orders.map((o) => (
              <div key={o.id} className="p-3 border rounded">
                <div className="flex justify-between items-start">
                  <div>
                    <div className="text-sm font-semibold">{o.customer_name || o.customer_email || 'Customer'}</div>
                    <div className="text-xs text-muted-foreground">{new Date(o.created_at).toLocaleString()}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-sm">₹{o.total_amount.toFixed(2)}</div>
                    <div className="text-xs text-muted-foreground">Qty: {o.quantity}</div>
                  </div>
                </div>
                <div className="mt-2 text-sm text-muted-foreground">
                  Bought: {o.product?.name || o.product?.title || o.bundle?.title || '—'}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
