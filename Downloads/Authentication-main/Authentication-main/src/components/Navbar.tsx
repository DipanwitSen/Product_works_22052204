import { NavLink, useNavigate } from "react-router-dom";
import { 
  Home, BarChart2, Boxes, ClipboardList, 
  Megaphone, Wallet, UserCircle, LogOut, 
  Heart, Bell, Shield, AlertCircle 
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { useEffect, useState } from "react";

interface NavItem {
  title: string;
  path: string;
  icon: React.ElementType;
  badge?: number;
}

export function Navbar() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [profilePhoto, setProfilePhoto] = useState<string>("");
  const [username, setUsername] = useState<string>("");
  const [isAdmin, setIsAdmin] = useState(false);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const [pendingVerifications, setPendingVerifications] = useState(0);

  const sellerNavItems: NavItem[] = [
    { title: "Home", path: "/landing", icon: Home },
    { title: "Dashboard", path: "/dashboard", icon: BarChart2 },
    { title: "Inventory", path: "/inventory", icon: Boxes },
    { title: "Orders", path: "/orders", icon: ClipboardList },
    { title: "Ads & Banners", path: "/ads", icon: Megaphone },
    { title: "Redeem", path: "/redeem", icon: Wallet },
  ];

  const adminNavItems: NavItem[] = [
    { title: "Dashboard", path: "/admin", icon: BarChart2 },
    { title: "Sellers", path: "/admin/sellers", icon: UserCircle },
    { title: "Verifications", path: "/admin/verifications", icon: Shield, badge: pendingVerifications },
  ];

  useEffect(() => {
    loadProfile();
    checkAdminStatus();
    if (isAdmin) {
      checkPendingVerifications();
    }
    checkNotifications();
  }, [isAdmin]);

  const loadProfile = async () => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (user) {
        const { data } = await supabase
          .from("sellers")
          .select("id,name")
          .eq("user_id", user.id)
          .single();

        if (data) {
          setUsername(data.name || "Seller");
          // try to load profile photo from seller_documents
          const { data: docs } = await supabase
            .from('seller_documents')
            .select('storage_path')
            .eq('seller_id', data.id)
            .eq('doc_type', 'profile')
            .limit(1);
          if (docs && docs.length > 0) setProfilePhoto(docs[0].storage_path);
        }
      }
    } catch (error) {
      console.error("Error loading profile:", error);
    }
  };

  const checkAdminStatus = async () => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (user) {
        const { data } = await supabase
          .from("user_roles")
          .select("role_id")
          .eq("user_id", user.id)
          .single();

        setIsAdmin(data?.role_id === "admin");
      }
    } catch (error) {
      console.error("Error checking admin status:", error);
    }
  };

  const checkPendingVerifications = async () => {
    try {
      const { count } = await supabase
        .from("seller_edit_requests")
        .select("*", { count: "exact", head: true })
        .eq("status", "pending");

      setPendingVerifications(count || 0);
    } catch (error) {
      console.error("Error checking pending verifications:", error);
    }
  };

  const checkNotifications = async () => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (user) {
        const { count } = await supabase
          .from("seller_edit_notifications")
          .select("*", { count: "exact", head: true })
          .eq("seller_id", user.id)
          .eq("status", "unread");

        setUnreadNotifications(count || 0);
      }
    } catch (error) {
      console.error("Error checking notifications:", error);
    }
  };

  const handleLogout = async () => {
    const { error } = await supabase.auth.signOut();
    if (error) {
      toast({
        title: "Error",
        description: "Failed to log out. Please try again.",
        variant: "destructive",
      });
    } else {
      toast({
        title: "Success",
        description: "Logged out successfully",
      });
      navigate("/auth/signin");
    }
  };

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 glass-navbar transition-smooth">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center gap-2">
            <Heart className="w-6 h-6 text-primary fill-primary" />
            <span className="text-xl font-bold gradient-text">ProtiMart</span>
          </div>

          {/* Center Navigation */}
          <div className="hidden md:flex items-center gap-1">
            {(isAdmin ? adminNavItems : sellerNavItems).map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-2 px-4 py-2 rounded-lg transition-smooth ${
                    isActive
                      ? "bg-primary/10 text-primary font-medium"
                      : "text-foreground hover:bg-muted"
                  }`
                }
              >
                <div className="flex items-center gap-2">
                  <item.icon className="w-4 h-4" />
                  <span className="text-sm">{item.title}</span>
                  {item.badge ? (
                    <span className="px-1.5 py-0.5 text-xs font-medium bg-red-500 text-white rounded-full">
                      {item.badge}
                    </span>
                  ) : null}
                </div>
              </NavLink>
            ))}
          </div>

          {/* Right Side */}
          <div className="flex items-center gap-3">
            {/* Notifications */}
            <Button variant="ghost" size="icon" asChild>
              <NavLink to={isAdmin ? "/admin/verifications" : "/notifications"} className="relative">
                <Bell className="w-4 h-4" />
                {unreadNotifications > 0 && (
                  <span className="absolute -top-1 -right-1 w-4 h-4 text-xs flex items-center justify-center bg-red-500 text-white rounded-full">
                    {unreadNotifications}
                  </span>
                )}
              </NavLink>
            </Button>

            {/* Profile Menu */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Avatar className="w-9 h-9 border-2 border-primary/20 transition-smooth hover:border-primary cursor-pointer">
                  <AvatarImage src={profilePhoto} alt={username} />
                  <AvatarFallback className="bg-primary/10 text-primary">
                    {username.charAt(0).toUpperCase()}
                  </AvatarFallback>
                </Avatar>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56">
                <DropdownMenuLabel className="font-normal">
                  <div className="flex flex-col space-y-1">
                    <p className="text-sm font-medium leading-none">{username}</p>
                    <p className="text-xs leading-none text-muted-foreground">
                      {isAdmin ? 'Administrator' : 'Seller'}
                    </p>
                  </div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => navigate('/profile')}>
                  <UserCircle className="w-4 h-4 mr-2" />
                  Profile Settings
                </DropdownMenuItem>
                {!isAdmin && (
                <DropdownMenuItem onClick={() => navigate('/seller-verification')}>
                  <AlertCircle className="w-4 h-4 mr-2" />
                  Verification Status
                </DropdownMenuItem>
                )}
                <DropdownMenuSeparator />
                <DropdownMenuItem className="text-destructive" onClick={handleLogout}>
                  <LogOut className="w-4 h-4 mr-2" />
                  Log Out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </div>
    </nav>
  );
}

