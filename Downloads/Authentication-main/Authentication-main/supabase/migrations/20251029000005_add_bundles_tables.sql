-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create ENUM for bundle status if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'bundle_status') THEN
        CREATE TYPE bundle_status AS ENUM ('active', 'inactive', 'archived');
    END IF;
END
$$;

-- Create the bundles table
CREATE TABLE bundles (
    id uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    discount_percentage DECIMAL(5,2) NOT NULL CHECK (discount_percentage >= 0 AND discount_percentage <= 100),
    seller_id UUID REFERENCES users(id),
    total_price DECIMAL(10,2) NOT NULL,
    discounted_price DECIMAL(10,2) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    status bundle_status DEFAULT 'active',
    CONSTRAINT valid_prices CHECK (discounted_price <= total_price)
);

-- Create the bundle_products table
CREATE TABLE bundle_products (
    bundle_id UUID REFERENCES bundles(id) ON DELETE CASCADE,
    product_id UUID REFERENCES products(product_id) ON DELETE CASCADE,
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    PRIMARY KEY (bundle_id, product_id)
);

-- Function to calculate total and discounted prices for a bundle
CREATE OR REPLACE FUNCTION update_bundle_prices() 
RETURNS trigger AS $$
DECLARE
    v_total DECIMAL(10,2);
BEGIN
    -- Calculate total price from all products in the bundle
    SELECT COALESCE(SUM(p.base_price * bp.quantity), 0)
    INTO v_total
    FROM bundle_products bp
    JOIN products p ON bp.product_id = p.product_id
    WHERE bp.bundle_id = NEW.id;

    -- Update the bundle prices
    NEW.total_price = v_total;
    NEW.discounted_price = v_total - (v_total * NEW.discount_percentage / 100);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to automatically update prices
CREATE TRIGGER before_bundle_change
    BEFORE INSERT OR UPDATE OF discount_percentage
    ON bundles
    FOR EACH ROW
    EXECUTE FUNCTION update_bundle_prices();

-- Create trigger function for bundle_products changes
CREATE OR REPLACE FUNCTION update_bundle_on_products_change() 
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        -- Recalculate bundle prices
        UPDATE bundles
        SET updated_at = now()
        WHERE id = NEW.bundle_id;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        -- Recalculate bundle prices
        UPDATE bundles
        SET updated_at = now()
        WHERE id = OLD.bundle_id;
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for bundle_products changes
CREATE TRIGGER after_bundle_products_change
    AFTER INSERT OR UPDATE OR DELETE
    ON bundle_products
    FOR EACH ROW
    EXECUTE FUNCTION update_bundle_on_products_change();

-- Add indexes
CREATE INDEX idx_bundles_seller ON bundles(seller_id);
CREATE INDEX idx_bundle_products_bundle ON bundle_products(bundle_id);
CREATE INDEX idx_bundle_products_product ON bundle_products(product_id);