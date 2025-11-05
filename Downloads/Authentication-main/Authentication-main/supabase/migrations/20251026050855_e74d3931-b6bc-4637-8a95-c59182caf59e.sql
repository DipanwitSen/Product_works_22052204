-- Create enum for app roles
CREATE TYPE public.app_role AS ENUM ('admin', 'seller', 'customer');

-- Create enum for KYC status
CREATE TYPE public.kyc_status AS ENUM ('pending', 'approved', 'rejected');

-- Create enum for order status
CREATE TYPE public.order_status AS ENUM ('pending', 'accepted', 'rejected', 'shipped', 'delivered');

-- Create enum for ad status
CREATE TYPE public.ad_status AS ENUM ('pending', 'approved', 'rejected');

-- Create profiles table
CREATE TABLE public.profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    business_name TEXT,
    business_type TEXT,
    phone TEXT,
    address TEXT,
    profile_photo_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL
);

-- Create user_roles table
CREATE TABLE public.user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    role app_role NOT NULL DEFAULT 'seller',
    UNIQUE(user_id, role)
);

-- Create security definer function to check roles
CREATE OR REPLACE FUNCTION public.has_role(_user_id UUID, _role app_role)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_roles
    WHERE user_id = _user_id AND role = _role
  )
$$;

-- Create KYC documents table
CREATE TABLE public.kyc_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL UNIQUE,
    aadhaar_number TEXT,
    pan_number TEXT,
    gstin TEXT,
    aadhaar_document_url TEXT,
    pan_document_url TEXT,
    gstin_document_url TEXT,
    selfie_url TEXT,
    bank_account_number TEXT,
    bank_ifsc_code TEXT,
    bank_account_holder_name TEXT,
    verification_status kyc_status DEFAULT 'pending' NOT NULL,
    rejection_reason TEXT,
    verified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL
);

-- Create products table
CREATE TABLE public.products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seller_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    barcode TEXT,
    name TEXT NOT NULL,
    description TEXT,
    ingredients TEXT,
    allergens TEXT,
    price DECIMAL(10, 2) NOT NULL CHECK (price >= 0),
    variants JSONB DEFAULT '[]'::jsonb,
    stock_quantity INTEGER DEFAULT 0 NOT NULL CHECK (stock_quantity >= 0),
    health_score INTEGER CHECK (health_score >= 0 AND health_score <= 100),
    manufacturing_date DATE,
    expiry_date DATE,
    return_policy TEXT,
    image_urls TEXT[] DEFAULT ARRAY[]::TEXT[],
    video_urls TEXT[] DEFAULT ARRAY[]::TEXT[],
    certificate_urls TEXT[] DEFAULT ARRAY[]::TEXT[],
    is_draft BOOLEAN DEFAULT false NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL
);

-- Create bundles table
CREATE TABLE public.bundles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seller_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    product_ids UUID[] NOT NULL,
    discount_percentage DECIMAL(5, 2) DEFAULT 0 CHECK (discount_percentage >= 0 AND discount_percentage <= 100),
    total_price DECIMAL(10, 2) NOT NULL CHECK (total_price >= 0),
    image_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL
);

-- Create orders table
CREATE TABLE public.orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seller_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    customer_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    product_id UUID REFERENCES public.products(id) ON DELETE CASCADE,
    bundle_id UUID REFERENCES public.bundles(id) ON DELETE CASCADE,
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    total_amount DECIMAL(10, 2) NOT NULL CHECK (total_amount >= 0),
    status order_status DEFAULT 'pending' NOT NULL,
    customer_name TEXT,
    customer_email TEXT,
    customer_phone TEXT,
    shipping_address TEXT,
    estimated_delivery_date DATE,
    feedback_rating INTEGER CHECK (feedback_rating >= 1 AND feedback_rating <= 5),
    feedback_text TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL
);

-- Create ads table
CREATE TABLE public.ads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seller_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    ad_type TEXT NOT NULL,
    media_url TEXT,
    target_audience TEXT,
    duration_days INTEGER DEFAULT 7 CHECK (duration_days > 0),
    status ad_status DEFAULT 'pending' NOT NULL,
    admin_comments TEXT,
    views INTEGER DEFAULT 0 NOT NULL,
    clicks INTEGER DEFAULT 0 NOT NULL,
    approved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL
);

-- Create earnings table
CREATE TABLE public.earnings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seller_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL UNIQUE,
    total_earned DECIMAL(10, 2) DEFAULT 0 NOT NULL CHECK (total_earned >= 0),
    redeemed_amount DECIMAL(10, 2) DEFAULT 0 NOT NULL CHECK (redeemed_amount >= 0),
    ad_credits DECIMAL(10, 2) DEFAULT 0 NOT NULL CHECK (ad_credits >= 0),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL
);

-- Create media library table
CREATE TABLE public.media (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seller_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    media_type TEXT NOT NULL,
    url TEXT NOT NULL,
    linked_product_id UUID REFERENCES public.products(id) ON DELETE SET NULL,
    linked_bundle_id UUID REFERENCES public.bundles(id) ON DELETE SET NULL,
    is_profile_photo BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL
);

-- Create chat logs table
CREATE TABLE public.chat_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seller_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    message TEXT NOT NULL,
    response TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL
);

-- Create function to handle new user registration
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Insert profile
  INSERT INTO public.profiles (user_id, username, email)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'username', SPLIT_PART(NEW.email, '@', 1)),
    NEW.email
  );
  
  -- Assign seller role by default
  INSERT INTO public.user_roles (user_id, role)
  VALUES (NEW.id, 'seller');
  
  -- Initialize earnings
  INSERT INTO public.earnings (seller_id, total_earned, redeemed_amount, ad_credits)
  VALUES (NEW.id, 0, 0, 0);
  
  RETURN NEW;
END;
$$;

-- Create trigger for new user
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

-- Create triggers for updated_at
CREATE TRIGGER update_profiles_updated_at BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_kyc_documents_updated_at BEFORE UPDATE ON public.kyc_documents
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_products_updated_at BEFORE UPDATE ON public.products
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_bundles_updated_at BEFORE UPDATE ON public.bundles
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_orders_updated_at BEFORE UPDATE ON public.orders
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_ads_updated_at BEFORE UPDATE ON public.ads
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_earnings_updated_at BEFORE UPDATE ON public.earnings
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- Enable RLS on all tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.kyc_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.earnings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_logs ENABLE ROW LEVEL SECURITY;

-- RLS Policies for profiles
CREATE POLICY "Users can view all profiles" ON public.profiles FOR SELECT TO authenticated USING (true);
CREATE POLICY "Users can update own profile" ON public.profiles FOR UPDATE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "Users can insert own profile" ON public.profiles FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

-- RLS Policies for user_roles
CREATE POLICY "Users can view own roles" ON public.user_roles FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "Admins can manage all roles" ON public.user_roles FOR ALL TO authenticated USING (public.has_role(auth.uid(), 'admin'));

-- RLS Policies for KYC documents
CREATE POLICY "Users can view own KYC" ON public.kyc_documents FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "Users can insert own KYC" ON public.kyc_documents FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own KYC" ON public.kyc_documents FOR UPDATE TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "Admins can view all KYC" ON public.kyc_documents FOR SELECT TO authenticated USING (public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Admins can update all KYC" ON public.kyc_documents FOR UPDATE TO authenticated USING (public.has_role(auth.uid(), 'admin'));

-- RLS Policies for products
CREATE POLICY "Anyone can view approved products" ON public.products FOR SELECT TO authenticated USING (is_draft = false);
CREATE POLICY "Sellers can view own products" ON public.products FOR SELECT TO authenticated USING (auth.uid() = seller_id);
CREATE POLICY "Sellers can insert own products" ON public.products FOR INSERT TO authenticated WITH CHECK (auth.uid() = seller_id);
CREATE POLICY "Sellers can update own products" ON public.products FOR UPDATE TO authenticated USING (auth.uid() = seller_id);
CREATE POLICY "Sellers can delete own products" ON public.products FOR DELETE TO authenticated USING (auth.uid() = seller_id);

-- RLS Policies for bundles
CREATE POLICY "Anyone can view bundles" ON public.bundles FOR SELECT TO authenticated USING (true);
CREATE POLICY "Sellers can insert own bundles" ON public.bundles FOR INSERT TO authenticated WITH CHECK (auth.uid() = seller_id);
CREATE POLICY "Sellers can update own bundles" ON public.bundles FOR UPDATE TO authenticated USING (auth.uid() = seller_id);
CREATE POLICY "Sellers can delete own bundles" ON public.bundles FOR DELETE TO authenticated USING (auth.uid() = seller_id);

-- RLS Policies for orders
CREATE POLICY "Sellers can view own orders" ON public.orders FOR SELECT TO authenticated USING (auth.uid() = seller_id);
CREATE POLICY "Customers can view own orders" ON public.orders FOR SELECT TO authenticated USING (auth.uid() = customer_id);
CREATE POLICY "Anyone can insert orders" ON public.orders FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Sellers can update own orders" ON public.orders FOR UPDATE TO authenticated USING (auth.uid() = seller_id);

-- RLS Policies for ads
CREATE POLICY "Sellers can view own ads" ON public.ads FOR SELECT TO authenticated USING (auth.uid() = seller_id);
CREATE POLICY "Admins can view all ads" ON public.ads FOR SELECT TO authenticated USING (public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Approved ads are public" ON public.ads FOR SELECT TO authenticated USING (status = 'approved');
CREATE POLICY "Sellers can insert own ads" ON public.ads FOR INSERT TO authenticated WITH CHECK (auth.uid() = seller_id);
CREATE POLICY "Sellers can update own pending ads" ON public.ads FOR UPDATE TO authenticated USING (auth.uid() = seller_id AND status = 'pending');
CREATE POLICY "Admins can update all ads" ON public.ads FOR UPDATE TO authenticated USING (public.has_role(auth.uid(), 'admin'));

-- RLS Policies for earnings
CREATE POLICY "Users can view own earnings" ON public.earnings FOR SELECT TO authenticated USING (auth.uid() = seller_id);
CREATE POLICY "Users can update own earnings" ON public.earnings FOR UPDATE TO authenticated USING (auth.uid() = seller_id);

-- RLS Policies for media
CREATE POLICY "Sellers can view own media" ON public.media FOR SELECT TO authenticated USING (auth.uid() = seller_id);
CREATE POLICY "Sellers can insert own media" ON public.media FOR INSERT TO authenticated WITH CHECK (auth.uid() = seller_id);
CREATE POLICY "Sellers can delete own media" ON public.media FOR DELETE TO authenticated USING (auth.uid() = seller_id);

-- RLS Policies for chat_logs
CREATE POLICY "Users can view own chat logs" ON public.chat_logs FOR SELECT TO authenticated USING (auth.uid() = seller_id);
CREATE POLICY "Users can insert own chat logs" ON public.chat_logs FOR INSERT TO authenticated WITH CHECK (auth.uid() = seller_id);