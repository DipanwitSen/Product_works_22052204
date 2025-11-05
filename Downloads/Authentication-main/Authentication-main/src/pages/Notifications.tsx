import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export default function Notifications() {
  const [notes, setNotes] = useState<any[]>([]);

  useEffect(() => { fetchNotes(); }, []);

  const fetchNotes = async () => {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return;
    const { data: seller } = await supabase.from('sellers').select('id').eq('user_id', user.id).maybeSingle();
    if (!seller) return;
    const { data } = await supabase
      .from('seller_edit_notifications')
      .select('*')
      .eq('seller_id', seller.id)
      .order('created_at', { ascending: false });
    setNotes(data || []);
  };

  const markRead = async (id: string) => {
    await supabase.from('seller_edit_notifications').update({ status: 'read' }).eq('id', id);
    fetchNotes();
  };

  return (
    <div className="p-6">
      <h2 className="text-2xl font-semibold mb-4">Notifications</h2>
      <div className="space-y-4">
        {notes.length === 0 && <Card><CardContent className="p-4">No notifications</CardContent></Card>}
        {notes.map(n => (
          <Card key={n.id}>
            <CardHeader>
              <CardTitle className="text-sm">{n.status === 'unread' ? 'New' : 'Read'}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="mb-2">{n.message}</p>
              <div className="flex gap-2">
                {n.status === 'unread' && <Button onClick={() => markRead(n.id)}>Mark as read</Button>}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
