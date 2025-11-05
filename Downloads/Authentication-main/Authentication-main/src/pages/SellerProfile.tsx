// src/pages/SellerProfile.tsx
import React, { useEffect, useState } from "react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  CardDescription,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { Loader2, Save, PlusCircle, Send } from "lucide-react";

export default function SellerProfile() {
  const { toast } = useToast();
  const [seller, setSeller] = useState<any | null>(null);
  const [allowedFields, setAllowedFields] = useState<string[]>([]);
  const [adminMessage, setAdminMessage] = useState<string | null>(null);
  const [docs, setDocs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [submittingRequest, setSubmittingRequest] = useState(false);
  const [reason, setReason] = useState("");
  const [formData, setFormData] = useState<any>({});
  const [selectedFiles, setSelectedFiles] = useState<{ [key: string]: File | null }>({
    aadhaar: null,
    pan: null,
    selfie: null,
  });
  const [requestedFields, setRequestedFields] = useState<string[]>([]);

  // 🔒 Restricted fields needing admin approval (GSTIN now included)
  const restrictedFields = [
    "aadhaar",
    "pan",
    "selfie",
    "bank_details",
    "email",
    "gstin",
  ];

  // ✅ Instantly editable fields
  const alwaysAllowed = ["businessname", "businesstype", "address", "phone"];

  const isAllowed = (logicalField: string) => {
    if (alwaysAllowed.includes(logicalField)) return true;
    if (!allowedFields.length) return !restrictedFields.includes(logicalField);
    return allowedFields.includes(logicalField) || !restrictedFields.includes(logicalField);
  };

  useEffect(() => {
    loadSellerProfile();
  }, []);

  async function loadSellerProfile() {
    setLoading(true);
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return;

      const { data: s } = await supabase.from("sellers").select("*").eq("user_id", user.id).maybeSingle();
      if (!s) return;
      setSeller(s);

      const { data: feedback } = await supabase
        .from("seller_verifications")
        .select("*")
        .eq("seller_id", s.id)
        .eq("step", "edit_request_feedback")
        .order("verified_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (feedback?.details) {
        const det = feedback.details as any;
        setAllowedFields(det.allowed_fields || []);
        setAdminMessage(det.admin_message || null);
      }

      const { data: documents } = await supabase
        .from("seller_documents")
        .select("doc_type, storage_path")
        .eq("seller_id", s.id);
      setDocs(documents || []);

      setFormData({
        businessName: s.business_name || "",
        businessType: s.business_type || "",
        gstin: s.gstin || "",
        aadhaar: s.aadhaar || "",
        pan: s.pan || "",
        address: s.address_line1 || "",
        bankName: s.bank_name || "",
        accountNumber: s.account_number || "",
        ifsc: s.ifsc_code || "",
        accountHolderName: s.account_holder_name || "",
        email: s.email || "",
        phone: s.phone || "",
      });
    } catch (err: any) {
      toast({ title: "Error loading profile", description: err.message, variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }

  async function uploadFile(file: File, folder: string) {
    if (!seller?.id) throw new Error("Seller not found");
    const ext = file.name.split(".").pop();
    const path = `${seller.id}/${folder}/${Date.now()}.${ext}`;
    const up = await supabase.storage.from("seller_details").upload(path, file, { upsert: true });
    if (up.error) throw up.error;
    const { data: urlData } = await supabase.storage
      .from("seller_details")
      .createSignedUrl(up.data.path, 60 * 60 * 24 * 365 * 5);
    return urlData.signedUrl;
  }

  // ✅ Save only allowed fields directly
  async function handleSave() {
    setSaving(true);
    try {
      const editableNow: any = {};

      for (const key of Object.keys(formData)) {
        const newVal = formData[key];
        const oldVal =
          key === "businessName"
            ? seller.business_name
            : key === "gstin"
            ? seller.gstin
            : seller[key] || "";

        if (newVal === oldVal) continue;

        const logical = key.toLowerCase();
        if (isAllowed(logical)) editableNow[key] = newVal;
      }

      if (Object.keys(editableNow).length) {
        await supabase
          .from("sellers")
          .update({
            business_name: editableNow.businessName,
            business_type: editableNow.businessType,
            address_line1: editableNow.address,
            phone: editableNow.phone,
          })
          .eq("id", seller.id);

        toast({ title: "Saved", description: "Profile updated successfully." });
      } else {
        toast({ title: "No editable changes found" });
      }

      loadSellerProfile();
    } catch (err: any) {
      toast({ title: "Error saving", description: err.message, variant: "destructive" });
    } finally {
      setSaving(false);
    }
  }

  // 🔒 Send restricted edit request (e.g. GSTIN, Aadhaar, PAN, Bank, Email)
  async function handleRequestChange() {
    if (!requestedFields.length) {
      toast({ title: "No requested fields", description: "Use + icons to select locked fields." });
      return;
    }
    if (!reason.trim()) {
      toast({ title: "Reason required", description: "Please explain why you need this change." });
      return;
    }

    setSubmittingRequest(true);
    try {
      const restrictedChanges: any = {};

      for (const field of requestedFields) {
        if (field === "bank_details") {
          restrictedChanges["bank_details"] = {
            old_value: {
              bank_name: seller.bank_name,
              account_number: seller.account_number,
              ifsc: seller.ifsc_code,
              account_holder_name: seller.account_holder_name,
            },
            new_value: {
              bank_name: formData.bankName,
              account_number: formData.accountNumber,
              ifsc: formData.ifsc,
              account_holder_name: formData.accountHolderName,
            },
          };
        } else {
          restrictedChanges[field] = {
            old_value: seller[field] || "",
            new_value: formData[field] || "",
          };
        }
      }

      await supabase.from("seller_verifications").insert({
        seller_id: seller.id,
        step: "edit_request",
        status: "pending",
        details: { requested_changes: restrictedChanges, reason },
        verified_at: new Date().toISOString(),
      });

      const { data: { user } } = await supabase.auth.getUser();
      await supabase.from("notifications").insert({
        sender_id: user?.id,
        receiver_id: null,
        related_seller_id: seller.id,
        type: "edit_request",
        title: "Seller requested change",
        message: `Requested updates: ${requestedFields.join(", ")}`,
      });

      toast({ title: "Request Sent", description: "Your edit request has been sent to admin." });
      setRequestedFields([]);
      setReason("");
      loadSellerProfile();
    } catch (err: any) {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    } finally {
      setSubmittingRequest(false);
    }
  }

  const toggleRequestField = (field: string) => {
    setRequestedFields((prev) =>
      prev.includes(field) ? prev.filter((f) => f !== field) : [...prev, field]
    );
  };

  if (loading) return <div className="p-8 text-center">Loading...</div>;

  return (
    <div className="min-h-screen bg-background py-10 px-6">
      <Card className="max-w-3xl mx-auto">
        <CardHeader>
          <CardTitle>Seller Profile</CardTitle>
          <CardDescription>View or edit your business and KYC information</CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* ✅ Instantly Editable Fields */}
          <div className="grid md:grid-cols-2 gap-4">
            {[
              ["Business Name", "businessName"],
              ["Business Type", "businessType"],
              ["Address", "address"],
              ["Phone", "phone"],
            ].map(([label, key]) => (
              <div key={key}>
                <Label>{label}</Label>
                <Input
                  value={formData[key]}
                  onChange={(e) => setFormData({ ...formData, [key]: e.target.value })}
                />
              </div>
            ))}
          </div>

          {/* 🔒 GSTIN (locked + requestable) */}
          <div className="relative">
            <Label>GSTIN</Label>
            <Input
              value={formData.gstin}
              onChange={(e) => setFormData({ ...formData, gstin: e.target.value })}
              disabled={!isAllowed("gstin") && !requestedFields.includes("gstin")}
              className={requestedFields.includes("gstin") ? "border-blue-400 bg-blue-50" : ""}
            />
            <Button
              size="icon"
              variant={requestedFields.includes("gstin") ? "secondary" : "outline"}
              className="absolute right-2 top-7"
              onClick={() => toggleRequestField("gstin")}
            >
              <PlusCircle className={`h-4 w-4 ${requestedFields.includes("gstin") ? "text-blue-600" : ""}`} />
            </Button>
          </div>

          {/* 🔒 Aadhaar */}
          <div className="relative">
            <Label>Aadhaar Number & Photo</Label>
            <Input
              value={formData.aadhaar}
              onChange={(e) => setFormData({ ...formData, aadhaar: e.target.value })}
              disabled={!isAllowed("aadhaar") && !requestedFields.includes("aadhaar")}
              className={requestedFields.includes("aadhaar") ? "border-blue-400 bg-blue-50" : ""}
            />
            <Input
              type="file"
              accept="image/*"
              disabled={!isAllowed("aadhaar") && !requestedFields.includes("aadhaar")}
              className="mt-2"
              onChange={(e) => setSelectedFiles({ ...selectedFiles, aadhaar: e.target.files?.[0] || null })}
            />
            <Button
              size="icon"
              variant={requestedFields.includes("aadhaar") ? "secondary" : "outline"}
              className="absolute right-2 top-7"
              onClick={() => toggleRequestField("aadhaar")}
            >
              <PlusCircle className={`h-4 w-4 ${requestedFields.includes("aadhaar") ? "text-blue-600" : ""}`} />
            </Button>
          </div>

          {/* 🔒 PAN */}
          <div className="relative">
            <Label>PAN Number & Photo</Label>
            <Input
              value={formData.pan}
              onChange={(e) => setFormData({ ...formData, pan: e.target.value })}
              disabled={!isAllowed("pan") && !requestedFields.includes("pan")}
              className={requestedFields.includes("pan") ? "border-blue-400 bg-blue-50" : ""}
            />
            <Input
              type="file"
              accept="image/*"
              disabled={!isAllowed("pan") && !requestedFields.includes("pan")}
              className="mt-2"
              onChange={(e) => setSelectedFiles({ ...selectedFiles, pan: e.target.files?.[0] || null })}
            />
            <Button
              size="icon"
              variant={requestedFields.includes("pan") ? "secondary" : "outline"}
              className="absolute right-2 top-7"
              onClick={() => toggleRequestField("pan")}
            >
              <PlusCircle className={`h-4 w-4 ${requestedFields.includes("pan") ? "text-blue-600" : ""}`} />
            </Button>
          </div>

          {/* 🔒 Selfie */}
          <div className="relative">
            <Label>Selfie Photo</Label>
            <Input
              type="file"
              accept="image/*"
              disabled={!isAllowed("selfie") && !requestedFields.includes("selfie")}
              onChange={(e) => setSelectedFiles({ ...selectedFiles, selfie: e.target.files?.[0] || null })}
            />
            <Button
              size="icon"
              variant={requestedFields.includes("selfie") ? "secondary" : "outline"}
              className="absolute right-2 top-7"
              onClick={() => toggleRequestField("selfie")}
            >
              <PlusCircle className={`h-4 w-4 ${requestedFields.includes("selfie") ? "text-blue-600" : ""}`} />
            </Button>
          </div>

          {/* 🔒 Bank Details (grouped) */}
          <div className="relative border rounded-md p-3 mt-4">
            <Label className="font-medium">Bank Details</Label>
            <div className="grid grid-cols-2 gap-3 mt-2">
              {[
                ["Bank Name", "bankName"],
                ["Account Number", "accountNumber"],
                ["IFSC Code", "ifsc"],
                ["Account Holder Name", "accountHolderName"],
              ].map(([label, key]) => (
                <div key={key}>
                  <Label>{label}</Label>
                  <Input
                    value={formData[key]}
                    onChange={(e) => setFormData({ ...formData, [key]: e.target.value })}
                    disabled={!isAllowed("bank_details") && !requestedFields.includes("bank_details")}
                    className={requestedFields.includes("bank_details") ? "border-blue-400 bg-blue-50" : ""}
                  />
                </div>
              ))}
            </div>
            <Button
              size="icon"
              variant={requestedFields.includes("bank_details") ? "secondary" : "outline"}
              className="absolute right-2 top-2"
              onClick={() => toggleRequestField("bank_details")}
            >
              <PlusCircle
                className={`h-4 w-4 ${requestedFields.includes("bank_details") ? "text-blue-600" : ""}`}
              />
            </Button>
          </div>

          {/* 🔒 Email */}
          <div className="relative">
            <Label>Email</Label>
            <Input
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              disabled={!isAllowed("email") && !requestedFields.includes("email")}
              className={requestedFields.includes("email") ? "border-blue-400 bg-blue-50" : ""}
            />
            <Button
              size="icon"
              variant={requestedFields.includes("email") ? "secondary" : "outline"}
              className="absolute right-2 top-7"
              onClick={() => toggleRequestField("email")}
            >
              <PlusCircle className={`h-4 w-4 ${requestedFields.includes("email") ? "text-blue-600" : ""}`} />
            </Button>
          </div>

          {requestedFields.length > 0 && (
            <div className="mt-4">
              <Label>Reason for Requested Edits</Label>
              <Input
                placeholder="Explain why you need to edit these fields"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
          )}

          <div className="flex justify-end gap-3 mt-6">
            <Button onClick={handleSave} disabled={saving}>
              {saving ? <Loader2 className="animate-spin h-4 w-4 mr-1" /> : <Save className="h-4 w-4 mr-1" />}
              Save Changes
            </Button>
            <Button
              variant="secondary"
              onClick={handleRequestChange}
              disabled={requestedFields.length === 0 || submittingRequest}
            >
              {submittingRequest ? (
                <Loader2 className="animate-spin h-4 w-4 mr-1" />
              ) : (
                <Send className="h-4 w-4 mr-1" />
              )}
              Request Change
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
