-- Update the products table structure
ALTER TABLE products 
ADD COLUMN stock_quantity INTEGER DEFAULT 0,
ADD COLUMN is_draft BOOLEAN DEFAULT FALSE;

-- Create table for product bundles
CREATE TABLE bundles (
  bundle_id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  seller_id UUID REFERENCES sellers(id),
  title VARCHAR(255) NOT NULL,
  description TEXT,
  original_price DECIMAL(10,2) NOT NULL,
  discount_percentage DECIMAL(5,2) NOT NULL CHECK (discount_percentage >= 0 AND discount_percentage <= 100),
  final_price DECIMAL(10,2) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'archived')),
  thumbnail_url TEXT
);

-- Create junction table for bundle products
CREATE TABLE bundle_products (
  bundle_id UUID REFERENCES bundles(bundle_id) ON DELETE CASCADE,
  product_id UUID REFERENCES products(product_id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (bundle_id, product_id)
);

-- Create function to calculate bundle final price
CREATE OR REPLACE FUNCTION calculate_bundle_final_price()
RETURNS TRIGGER AS $$
BEGIN
  NEW.final_price = NEW.original_price * (1 - NEW.discount_percentage / 100);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to automatically calculate final price
CREATE TRIGGER before_bundle_insert_update
  BEFORE INSERT OR UPDATE OF original_price, discount_percentage ON bundles
  FOR EACH ROW
  EXECUTE FUNCTION calculate_bundle_final_price();