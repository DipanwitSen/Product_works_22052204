// src/components/ProtectedRoute.tsx
import { useEffect, useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { User, Session } from "@supabase/supabase-js";
import { Loader2 } from "lucide-react";
import { Navbar } from "@/components/Navbar";

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiresKYC?: boolean;
}

export function ProtectedRoute({ children, requiresKYC = false }: ProtectedRouteProps) {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [kycStatus, setKycStatus] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const location = useLocation();

  useEffect(() => {
    // Listen to auth state changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      setUser(session?.user ?? null);
    });

    // Initial session check
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);
    });

    return () => subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (user && requiresKYC) {
      supabase
        .from("sellers")
        .select("verification_status")
        .eq("user_id", user.id)
        .maybeSingle()
        .then(({ data }) => {
          setKycStatus(data?.verification_status || null);
        });
    }
  }, [user, requiresKYC]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  // Redirect unauthenticated users to sign in
  if (!user) {
    return <Navigate to="/auth/signin" state={{ from: location }} replace />;
  }

  // If KYC is required, enforce status-based routing
  if (requiresKYC) {
    if (!kycStatus) {
      // No KYC record yet → must start KYC
      return <Navigate to="/kyc" state={{ from: location }} replace />;
    } else if (kycStatus === "rejected") {
      // Rejected → must redo KYC
      return <Navigate to="/kyc" state={{ from: location }} replace />;
    } else if (kycStatus === "pending") {
      // Pending → can only access SellerVerification page
      const current = location.pathname.toLowerCase();
      if (!current.includes("seller-verification") && !current.includes("kyc")) {
        return <Navigate to="/seller-verification" state={{ from: location }} replace />;
      }
    }
  }

  // Approved or general access
  return (
    <>
      <Navbar />
      <main className="pt-16">{children}</main>
    </>
  );
}
