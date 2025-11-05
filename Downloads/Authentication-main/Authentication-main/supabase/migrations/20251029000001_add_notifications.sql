-- Create notifications table
CREATE TABLE public.notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seller_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT false,
    data JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL
);

-- Add low_stock_threshold column to products
ALTER TABLE public.products
ADD COLUMN low_stock_threshold INTEGER DEFAULT 10;

-- Create function to check stock levels and create notifications
CREATE OR REPLACE FUNCTION check_low_stock()
RETURNS TRIGGER AS $$
BEGIN
    -- If stock quantity is below threshold and no unread notification exists
    IF (NEW.stock_quantity <= COALESCE(NEW.low_stock_threshold, 10)) AND 
       NOT EXISTS (
           SELECT 1 FROM notifications 
           WHERE seller_id = NEW.seller_id 
           AND type = 'low_stock'
           AND data->>'product_id' = NEW.id::TEXT
           AND is_read = false
       ) THEN
        -- Create notification
        INSERT INTO notifications (seller_id, type, title, message, data)
        VALUES (
            NEW.seller_id,
            'low_stock',
            'Low Stock Alert',
            'Product "' || NEW.name || '" is running low on stock (' || NEW.stock_quantity || ' remaining)',
            jsonb_build_object(
                'product_id', NEW.id,
                'product_name', NEW.name,
                'current_stock', NEW.stock_quantity,
                'threshold', COALESCE(NEW.low_stock_threshold, 10)
            )
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for low stock check
CREATE TRIGGER check_product_stock
    AFTER INSERT OR UPDATE OF stock_quantity
    ON products
    FOR EACH ROW
    EXECUTE FUNCTION check_low_stock();

-- Add RLS policies for notifications
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own notifications"
    ON public.notifications FOR SELECT
    TO authenticated
    USING (auth.uid() = seller_id);

CREATE POLICY "Users can update own notifications"
    ON public.notifications FOR UPDATE
    TO authenticated
    USING (auth.uid() = seller_id);