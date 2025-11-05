import { useEffect, useState } from 'react';
import { Card } from '@/components/ui/card';
import { supabase } from '@/integrations/supabase/client';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts';

interface SalesData {
  date: string;
  sales: number;
  profit: number;
}

interface SellerGraphProps {
  sellerId: string;
}

export function SellerGraph({ sellerId }: SellerGraphProps) {
  const [salesData, setSalesData] = useState<SalesData[]>([]);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<'week' | 'month' | 'year'>('month');

  useEffect(() => {
    loadSalesData();
  }, [sellerId, timeRange]);

  const loadSalesData = async () => {
    setLoading(true);
    try {
      let intervalStr = '';
      switch (timeRange) {
        case 'week':
          intervalStr = "interval '7 days'";
          break;
        case 'month':
          intervalStr = "interval '30 days'";
          break;
        case 'year':
          intervalStr = "interval '365 days'";
          break;
      }

      const { data, error } = await supabase
        .rpc('get_seller_sales_data', {
          p_seller_id: sellerId,
          p_interval: intervalStr
        });

      if (error) throw error;

      // Transform the data for the chart
      const formattedData = data.map((item: any) => ({
        date: new Date(item.date).toLocaleDateString(),
        sales: item.total_sales,
        profit: item.total_profit
      }));

      setSalesData(formattedData);
    } catch (error) {
      console.error('Error loading sales data:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Sales and Profit Overview</h2>
        <div className="flex gap-2">
          <button
            onClick={() => setTimeRange('week')}
            className={`px-3 py-1 rounded ${
              timeRange === 'week' ? 'bg-primary text-white' : 'bg-gray-100'
            }`}
          >
            Week
          </button>
          <button
            onClick={() => setTimeRange('month')}
            className={`px-3 py-1 rounded ${
              timeRange === 'month' ? 'bg-primary text-white' : 'bg-gray-100'
            }`}
          >
            Month
          </button>
          <button
            onClick={() => setTimeRange('year')}
            className={`px-3 py-1 rounded ${
              timeRange === 'year' ? 'bg-primary text-white' : 'bg-gray-100'
            }`}
          >
            Year
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-[400px]">
          Loading...
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={400}>
          <LineChart data={salesData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="date" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Line
              type="monotone"
              dataKey="sales"
              stroke="#8884d8"
              name="Total Sales"
            />
            <Line
              type="monotone"
              dataKey="profit"
              stroke="#82ca9d"
              name="Total Profit"
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </Card>
  );
}