import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import Index from "./pages/Index";
import SignIn from "./pages/auth/SignIn";
import SignUp from "./pages/auth/SignUp";
import ForgotPassword from "./pages/auth/ForgotPassword";
import KYC from "./pages/KYC";
import Landing from "./pages/Landing";
import Dashboard from "./pages/Dashboard";
import NotFound from "./pages/NotFound";
import Inventory from "./pages/Inventory";
import SellerProfile from "./pages/SellerProfile";
import Notifications from "./pages/Notifications";
import SellerVerification from "./pages/SellerVerification";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/auth/signin" element={<SignIn />} />
          <Route path="/auth/signup" element={<SignUp />} />
          <Route path="/auth/forgot-password" element={<ForgotPassword />} />
          <Route path="/kyc" element={<ProtectedRoute><KYC /></ProtectedRoute>} />
          <Route path="/landing" element={<ProtectedRoute requiresKYC><Landing /></ProtectedRoute>} />
          <Route path="/dashboard" element={<ProtectedRoute requiresKYC><Dashboard /></ProtectedRoute>} />
          <Route path="/inventory" element={<ProtectedRoute requiresKYC><Inventory /></ProtectedRoute>} />
            <Route path="/profile" element={<ProtectedRoute requiresKYC><SellerProfile /></ProtectedRoute>} />
            <Route path="/notifications" element={<ProtectedRoute requiresKYC><Notifications /></ProtectedRoute>} />
            <Route path="/seller-verification" element={<ProtectedRoute requiresKYC><SellerVerification /></ProtectedRoute>} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
