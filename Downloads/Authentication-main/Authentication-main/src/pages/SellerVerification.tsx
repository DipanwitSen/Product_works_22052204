import React, { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Loader2, CheckCircle, XCircle, RefreshCcw } from "lucide-react";
import { useNavigate } from "react-router-dom";

export default function SellerVerification() {
  const { toast } = useToast();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [seller, setSeller] = useState<any | null>(null);
  const [status, setStatus] = useState<string>("unknown");
  const [adminMessage, setAdminMessage] = useState<string | null>(null);
  const [allowedFields, setAllowedFields] = useState<string[]>([]);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [editFeedback, setEditFeedback] = useState<any[]>([]);
  const [docs, setDocs] = useState<any[]>([]);
  const [refreshToken, setRefreshToken] = useState(0);

  useEffect(() => {
    loadData();
  }, [refreshToken]);

  async function loadData() {
    setLoading(true);
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) {
        navigate("/login");
        return;
      }

      const { data: sellerData, error: sellerErr } = await supabase
        .from("sellers")
        .select("*")
        .eq("user_id", user.id)
        .maybeSingle();
      if (sellerErr) throw sellerErr;
      if (!sellerData) {
        navigate("/KYC");
        return;
      }

      setSeller(sellerData);
      setStatus(sellerData.verification_status || "pending");

      // load seller docs (aadhaar, pan, selfie)
      const { data: sellerDocs } = await supabase
        .from("seller_documents")
        .select("doc_type, storage_path")
        .eq("seller_id", sellerData.id);
      setDocs(sellerDocs || []);

      // load edit request feedback
      const { data: feedback } = await supabase
        .from("seller_verifications")
        .select("*")
        .eq("seller_id", sellerData.id)
        .eq("step", "edit_request_feedback")
        .order("verified_at", { ascending: false });
      setEditFeedback(feedback || []);

      // load notifications for seller
      const { data: notifData } = await supabase
        .from("notifications")
        .select("*")
        .eq("receiver_id", user.id)
        .order("created_at", { ascending: false })
        .limit(50);
      setNotifications(notifData || []);

      // set allowed fields + message if available
      if (feedback && feedback[0]?.details) {
        const det = feedback[0].details as any;
        setAllowedFields(det.allowed_fields || []);
        setAdminMessage(det.admin_message || det.admin_note || null);
      }
    } catch (err: any) {
      console.error(err);
      toast({ title: "Error loading", description: err?.message || "Failed to load data", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="p-8 text-center">
        <Loader2 className="animate-spin mx-auto h-6 w-6" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background py-10 px-6">
      <Card>
        <CardHeader>
          <CardTitle>Seller Verification Center</CardTitle>
          <CardDescription>Monitor your verification status, edit permissions, and notifications</CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="status">
            <TabsList>
              <TabsTrigger value="status">Status</TabsTrigger>
              <TabsTrigger value="edits">Edit Feedback</TabsTrigger>
              <TabsTrigger value="notifications">Notifications</TabsTrigger>
            </TabsList>

            {/* STATUS TAB */}
            <TabsContent value="status" className="mt-6">
              <div className="border rounded p-4 space-y-4">
                <div className="flex justify-between items-center">
                  <div>
                    <h3 className="text-lg font-semibold">Verification Status</h3>
                    <p className="text-sm text-muted-foreground">Current: {status}</p>
                  </div>
                  <Button variant="outline" onClick={() => setRefreshToken(t => t + 1)}>
                    <RefreshCcw className="h-4 w-4 mr-1" /> Refresh
                  </Button>
                </div>

                {adminMessage && (
                  <div className="p-3 bg-yellow-50 border rounded">
                    <strong>Admin Message:</strong>
                    <p className="text-sm mt-1">{adminMessage}</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      Allowed fields: {allowedFields.length ? allowedFields.join(", ") : "None"}
                    </p>
                  </div>
                )}

                <div>
                  <h4 className="text-md font-medium mt-3 mb-2">Uploaded Documents</h4>
                  {docs.length ? (
                    <div className="grid grid-cols-3 gap-4">
                      {docs.map((d) => (
                        <div key={d.doc_type} className="text-center">
                          <p className="text-sm font-medium mb-1">{d.doc_type.toUpperCase()}</p>
                          <img
                            src={d.storage_path}
                            alt={d.doc_type}
                            className="rounded border shadow-sm w-full h-40 object-cover"
                          />
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">No documents found</p>
                  )}
                </div>

                <div className="text-right">
                  {status === "approved" ? (
                    <Button variant="secondary" onClick={() => navigate("/dashboard")}>
                      <CheckCircle className="h-4 w-4 mr-1" /> Verified - Go to Dashboard
                    </Button>
                  ) : status === "rejected" ? (
                    <Button variant="secondary" onClick={() => navigate("/KYC")}>
                      <XCircle className="h-4 w-4 mr-1" /> Resubmit KYC
                    </Button>
                  ) : (
                    <Button disabled>
                      <Loader2 className="animate-spin h-4 w-4 mr-1" /> Under Review
                    </Button>
                  )}
                </div>
              </div>
            </TabsContent>

            {/* EDIT FEEDBACK TAB */}
            <TabsContent value="edits" className="mt-6">
              {editFeedback.length === 0 ? (
                <div className="p-4 text-sm text-muted-foreground text-center">
                  No feedback or edit permissions yet.
                </div>
              ) : (
                editFeedback.map((ef) => (
                  <div key={ef.id} className="mb-3 border rounded p-4">
                    <h4 className="text-md font-semibold mb-2">Admin Feedback</h4>
                    <pre className="bg-gray-50 p-2 rounded text-xs overflow-auto">
                      {JSON.stringify(ef.details, null, 2)}
                    </pre>
                    <p className="text-xs mt-2 text-muted-foreground">
                      Updated at {new Date(ef.verified_at).toLocaleString()}
                    </p>
                  </div>
                ))
              )}
            </TabsContent>

            {/* NOTIFICATIONS TAB */}
            <TabsContent value="notifications" className="mt-6">
              {notifications.length === 0 ? (
                <div className="p-4 text-sm text-muted-foreground text-center">No notifications</div>
              ) : (
                notifications.map((n) => (
                  <div key={n.id} className="border rounded p-3 mb-2 flex justify-between">
                    <div>
                      <p className="font-semibold">{n.title || n.type}</p>
                      <p className="text-sm text-muted-foreground">{n.message}</p>
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {new Date(n.created_at).toLocaleString()}
                    </span>
                  </div>
                ))
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
