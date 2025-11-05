-- Update kyc_documents table to match seller documents structure
ALTER TABLE kyc_documents DROP COLUMN IF EXISTS selfie_url;
ALTER TABLE kyc_documents DROP COLUMN IF EXISTS aadhaar_document_url;
ALTER TABLE kyc_documents DROP COLUMN IF EXISTS pan_document_url;
ALTER TABLE kyc_documents DROP COLUMN IF EXISTS gstin_document_url;

-- Add verification_result column if not exists
ALTER TABLE kyc_documents ADD COLUMN IF NOT EXISTS verification_result JSONB;

-- Create kyc_images table for storing KYC document images
CREATE TABLE IF NOT EXISTS kyc_images (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  doc_type TEXT NOT NULL CHECK (doc_type IN ('profile', 'aadhaar', 'pan')),
  file_name TEXT NOT NULL,
  file_size INTEGER NOT NULL,
  mime_type TEXT NOT NULL,
  storage_path TEXT NOT NULL,
  uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  UNIQUE(user_id, doc_type)
);

-- Enable RLS on kyc_images
ALTER TABLE kyc_images ENABLE ROW LEVEL SECURITY;

-- Policies for kyc_images
CREATE POLICY "Users can insert own KYC images" ON kyc_images
  FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can view own KYC images" ON kyc_images
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Admins can view all KYC images" ON kyc_images
  FOR SELECT USING (has_role(auth.uid(), 'admin'::app_role));

CREATE POLICY "Admins can update all KYC images" ON kyc_images
  FOR UPDATE USING (has_role(auth.uid(), 'admin'::app_role));

-- Create seller_documents table for document storage
CREATE TABLE IF NOT EXISTS seller_documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seller_id UUID NOT NULL,
  doc_type TEXT NOT NULL CHECK (doc_type IN (
    'pan', 'aadhaar_front', 'aadhaar_back', 
    'selfie', 'cancel_cheque', 'gst_certificate'
  )),
  file_name TEXT NOT NULL,
  file_size INTEGER NOT NULL,
  mime_type TEXT NOT NULL,
  storage_path TEXT NOT NULL,
  uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  uploaded_by UUID REFERENCES auth.users(id),
  verification_status TEXT DEFAULT 'pending'
);

-- Enable RLS on seller_documents
ALTER TABLE seller_documents ENABLE ROW LEVEL SECURITY;

-- Policies for seller_documents
CREATE POLICY "Admins can manage all seller documents" ON seller_documents
  FOR ALL USING (has_role(auth.uid(), 'admin'::app_role));

CREATE POLICY "Users can view own seller documents" ON seller_documents
  FOR SELECT USING (seller_id::text = auth.uid()::text);

-- Create seller_images table for image library
CREATE TABLE IF NOT EXISTS seller_images (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seller_id UUID NOT NULL,
  category TEXT NOT NULL,
  file_name TEXT NOT NULL,
  storage_path TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Enable RLS on seller_images
ALTER TABLE seller_images ENABLE ROW LEVEL SECURITY;

-- Policies for seller_images
CREATE POLICY "Admins can manage all seller images" ON seller_images
  FOR ALL USING (has_role(auth.uid(), 'admin'::app_role));

CREATE POLICY "Users can view own seller images" ON seller_images
  FOR SELECT USING (seller_id::text = auth.uid()::text);

-- Create restock_alerts table
CREATE TABLE IF NOT EXISTS restock_alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  seller_id UUID NOT NULL,
  threshold INTEGER NOT NULL DEFAULT 5,
  last_alerted_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Enable RLS on restock_alerts
ALTER TABLE restock_alerts ENABLE ROW LEVEL SECURITY;

-- Policies for restock_alerts
CREATE POLICY "Sellers can manage own restock alerts" ON restock_alerts
  FOR ALL USING (seller_id::text = auth.uid()::text);

CREATE POLICY "Admins can view all restock alerts" ON restock_alerts
  FOR SELECT USING (has_role(auth.uid(), 'admin'::app_role));

-- Create seller_earnings table
CREATE TABLE IF NOT EXISTS seller_earnings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seller_id UUID NOT NULL,
  amount NUMERIC(12,2) NOT NULL,
  source_order_id UUID REFERENCES orders(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Enable RLS on seller_earnings
ALTER TABLE seller_earnings ENABLE ROW LEVEL SECURITY;

-- Policies for seller_earnings
CREATE POLICY "Sellers can view own earnings" ON seller_earnings
  FOR SELECT USING (seller_id::text = auth.uid()::text);

CREATE POLICY "Admins can manage all earnings" ON seller_earnings
  FOR ALL USING (has_role(auth.uid(), 'admin'::app_role));

-- Create payout_requests table
CREATE TABLE IF NOT EXISTS payout_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  seller_id UUID NOT NULL,
  amount NUMERIC(12,2) NOT NULL,
  status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'COMPLETED')),
  requested_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  processed_at TIMESTAMP WITH TIME ZONE,
  bank_account_snapshot JSONB,
  admin_notes TEXT
);

-- Enable RLS on payout_requests
ALTER TABLE payout_requests ENABLE ROW LEVEL SECURITY;

-- Policies for payout_requests
CREATE POLICY "Sellers can create own payout requests" ON payout_requests
  FOR INSERT WITH CHECK (seller_id::text = auth.uid()::text);

CREATE POLICY "Sellers can view own payout requests" ON payout_requests
  FOR SELECT USING (seller_id::text = auth.uid()::text);

CREATE POLICY "Admins can manage all payout requests" ON payout_requests
  FOR ALL USING (has_role(auth.uid(), 'admin'::app_role));

-- Create order_events table for order status tracking
CREATE TABLE IF NOT EXISTS order_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  user_id UUID REFERENCES auth.users(id),
  note TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Enable RLS on order_events
ALTER TABLE order_events ENABLE ROW LEVEL SECURITY;

-- Policies for order_events
CREATE POLICY "Users can view events for their orders" ON order_events
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM orders 
      WHERE orders.id = order_events.order_id 
      AND (orders.seller_id = auth.uid() OR orders.customer_id = auth.uid())
    )
  );

CREATE POLICY "Admins can view all order events" ON order_events
  FOR SELECT USING (has_role(auth.uid(), 'admin'::app_role));

CREATE POLICY "Order participants can insert events" ON order_events
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM orders 
      WHERE orders.id = order_events.order_id 
      AND (orders.seller_id = auth.uid() OR orders.customer_id = auth.uid())
    )
  );