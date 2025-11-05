-- Create bundles table
CREATE TABLE bundles (
  bundle_id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  seller_id UUID REFERENCES users(id),
  title VARCHAR(255) NOT NULL,
  description TEXT,
  original_price DECIMAL(10,2) NOT NULL,
  discount_percentage DECIMAL(5,2) NOT NULL,
  final_price DECIMAL(10,2) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  status public.product_status DEFAULT 'active',
  thumbnail_url TEXT
);

-- Create bundle_products junction table
CREATE TABLE bundle_products (
  bundle_id UUID REFERENCES bundles(bundle_id) ON DELETE CASCADE,
  product_id UUID REFERENCES products(product_id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (bundle_id, product_id)
);

-- Create view for bundle details including products
CREATE VIEW bundle_details AS
SELECT 
  b.*,
  array_agg(jsonb_build_object(
    'product_id', p.product_id,
    'title', p.title,
    'base_price', p.base_price
  )) as products
FROM bundles b
LEFT JOIN bundle_products bp ON b.bundle_id = bp.bundle_id
LEFT JOIN products p ON bp.product_id = p.product_id
GROUP BY b.bundle_id;