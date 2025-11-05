import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
// Navbar is rendered by ProtectedRoute; do not render it here to avoid duplication
import { SellerGraph } from "@/components/SellerGraph";
import { OrderHistory } from "@/components/OrderHistory";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DollarSign, Package, ShoppingCart, TrendingUp, AlertCircle, Clock } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { LowStockNotifications } from "@/components/LowStockNotifications";

interface Stats {
  totalRevenue: number;
  totalOrders: number;
  totalProducts: number;
  pendingOrders: number;
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats>({
    totalRevenue: 0,
    totalOrders: 0,
    totalProducts: 0,
    pendingOrders: 0,
  });
  const [loading, setLoading] = useState(true);
  const [kycStatus, setKycStatus] = useState<string | null>(null);
  const [sellerId, setSellerId] = useState<string | null>(null);
  const [revenueChange, setRevenueChange] = useState<number | null>(null);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    setLoading(true);
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return;

    try {
      // Get seller record to check KYC status
      const { data: seller } = await supabase
        .from("sellers")
        .select("id, verification_status")
        .eq("user_id", user.id)
        .single();

      if (!seller) {
        setLoading(false);
        return;
      }

      // Set KYC status for banner
      setKycStatus(seller.verification_status);
  setSellerId(seller.id);

      // Load products
      const { count: productsCount } = await supabase
        .from("products")
        .select("product_id", { count: "exact" })
        .eq("seller_id", user.id)
        .eq("status", "active");

      // Calculate total revenue from orders for the seller
      const { data: revenueNow, error: revErr } = await (supabase as any)
        .from("orders")
        .select("total_amount", { count: "exact", head: false })
        .eq("seller_id", user.id)
        .gte("created_at", new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString());

      let totalRevenue = 0;
      if (revenueNow && Array.isArray(revenueNow)) {
        totalRevenue = revenueNow.reduce((s: number, r: any) => s + (r.total_amount || 0), 0);
      }

      // Compute previous period revenue for change percentage (previous 30 days)
      const now = new Date();
      const startCurrent = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      const startPrev = new Date(startCurrent.getTime() - 30 * 24 * 60 * 60 * 1000);

      const { data: prevPeriod } = await (supabase as any)
        .from("orders")
        .select("total_amount")
        .eq("seller_id", user.id)
        .gte("created_at", startPrev.toISOString())
        .lt("created_at", startCurrent.toISOString());

      const prevRevenue = (prevPeriod || []).reduce((s: number, r: any) => s + (r.total_amount || 0), 0);
      const change = prevRevenue === 0 ? (totalRevenue === 0 ? 0 : 100) : ((totalRevenue - prevRevenue) / prevRevenue) * 100;
      setRevenueChange(Number(change.toFixed(1)));

      setStats({
        totalRevenue: totalRevenue,
        totalOrders: 0,
        totalProducts: productsCount || 0,
        pendingOrders: 0,
      });
    } catch (error) {
      console.error("Error loading dashboard data:", error);
    } finally {
      setLoading(false);
    }
  };

  const statCards = [
    {
      title: "Total Revenue",
      value: `₹${stats.totalRevenue.toFixed(2)}`,
      icon: DollarSign,
      description: "Total earnings",
      gradient: "from-green-500 to-emerald-600",
    },
    {
      title: "Total Orders",
      value: stats.totalOrders.toString(),
      icon: ShoppingCart,
      description: "All time orders",
      gradient: "from-blue-500 to-cyan-600",
    },
    {
      title: "Products",
      value: stats.totalProducts.toString(),
      icon: Package,
      description: "Active products",
      gradient: "from-purple-500 to-pink-600",
    },
    {
      title: "Pending Orders",
      value: stats.pendingOrders.toString(),
      icon: TrendingUp,
      description: "Awaiting action",
      gradient: "from-orange-500 to-red-600",
    },
  ];

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-4xl font-bold gradient-text mb-2">Dashboard</h1>
          <p className="text-muted-foreground">Overview of your ProtiMart seller account</p>
        </div>

        {/* KYC Pending Banner */}
        {kycStatus === "pending" && (
          <Alert className="mb-6 border-amber-500/50 bg-amber-500/10">
            <Clock className="h-5 w-5 text-amber-500" />
            <AlertTitle className="text-amber-500 font-semibold">KYC Verification Pending</AlertTitle>
            <AlertDescription className="text-amber-600">
              Your documents are currently under review. You can continue using the platform with limited features. We'll notify you once your account is fully verified.
            </AlertDescription>
          </Alert>
        )}

        {/* KYC Rejected Banner */}
        {kycStatus === "rejected" && (
          <Alert className="mb-6 border-red-500/50 bg-red-500/10">
            <AlertCircle className="h-5 w-5 text-red-500" />
            <AlertTitle className="text-red-500 font-semibold">KYC Verification Rejected</AlertTitle>
            <AlertDescription className="text-red-600">
              Your KYC verification was rejected. Please resubmit your documents with correct information.
            </AlertDescription>
          </Alert>
        )}

        {stats.pendingOrders > 0 && (
          <Alert className="mb-6 border-primary/20 bg-primary/5">
            <AlertCircle className="h-4 w-4 text-primary" />
            <AlertDescription className="text-primary">
              You have {stats.pendingOrders} pending order(s) requiring attention
            </AlertDescription>
          </Alert>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
          {statCards.map((stat, index) => (
            <Card 
              key={index} 
              className="relative overflow-hidden group hover:shadow-pink transition-smooth"
            >
              <div className={`absolute top-0 right-0 w-32 h-32 bg-gradient-to-br ${stat.gradient} opacity-10 rounded-full -mr-16 -mt-16 group-hover:scale-110 transition-smooth`} />
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-medium text-muted-foreground">
                    {stat.title}
                  </CardTitle>
                  <stat.icon className="w-5 h-5 text-primary" />
                </div>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <div className="h-10 bg-muted rounded animate-pulse" />
                ) : (
                  <>
                    <div className="flex items-center gap-3 mb-1">
                      <div className="text-3xl font-bold gradient-text">{stat.value}</div>
                      {stat.title === 'Total Revenue' && revenueChange !== null && (
                        <div className={`px-2 py-1 rounded text-sm ${revenueChange >= 0 ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                          {revenueChange >= 0 ? `+${revenueChange}%` : `${revenueChange}%`}
                        </div>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground">{stat.description}</p>
                  </>
                )}
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <SellerGraph sellerId={sellerId ?? ''} />
          <LowStockNotifications />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <OrderHistory sellerId={sellerId} />
          {/* Additional dashboard widgets can be added here */}
        </div>
      </div>
    </div>
  );
}
