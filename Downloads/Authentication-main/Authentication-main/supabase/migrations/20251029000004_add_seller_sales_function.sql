-- Create function to get seller sales data
CREATE OR REPLACE FUNCTION get_seller_sales_data(p_seller_id UUID, p_interval INTERVAL)
RETURNS TABLE (
    date DATE,
    total_sales NUMERIC,
    total_profit NUMERIC
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE dates AS (
        SELECT
            current_date - p_interval AS start_date,
            current_date AS end_date
        UNION ALL
        SELECT
            dates.start_date + 1,
            dates.end_date
        FROM dates
        WHERE dates.start_date < dates.end_date
    ),
    daily_sales AS (
        SELECT
            DATE(created_at) AS sale_date,
            SUM(total_amount) AS sales,
            SUM(total_amount - total_cost) AS profit
        FROM orders o
        JOIN order_items oi ON o.id = oi.order_id
        JOIN products p ON oi.product_id = p.id
        WHERE p.seller_id = p_seller_id
        AND o.status = 'completed'
        GROUP BY DATE(created_at)
    )
    SELECT
        d.start_date AS date,
        COALESCE(ds.sales, 0) AS total_sales,
        COALESCE(ds.profit, 0) AS total_profit
    FROM dates d
    LEFT JOIN daily_sales ds ON d.start_date = ds.sale_date
    WHERE d.start_date <= current_date
    ORDER BY d.start_date;
END;
$$;