// src/pages/KYC.tsx
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { Camera, CheckCircle, Loader2 } from "lucide-react";
import { z } from "zod";

// ✅ Validation schema
const kycSchema = z.object({
  aadhaarNumber: z
    .string()
    .regex(/^[2-9]{1}[0-9]{11}$/, "Invalid Aadhaar number")
    .optional(),
  panNumber: z
    .string()
    .regex(/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/, "Invalid PAN number")
    .optional(),
  gstin: z
    .string()
    .regex(
      /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$/,
      "Invalid GSTIN"
    )
    .optional(),
  bankAccountNumber: z
    .string()
    .min(9, "Invalid account number")
    .max(18, "Invalid account number")
    .optional(),
  bankIfscCode: z
    .string()
    .regex(/^[A-Z]{4}0[A-Z0-9]{6}$/, "Invalid IFSC code")
    .optional(),
});

// ✅ Business types (match EXACTLY Supabase enum)
const BUSINESS_TYPES = [
  { label: "Individual", value: "individual" },
  { label: "Sole Proprietorship", value: "sole_proprietorship" },
  { label: "Partnership", value: "partnership" },
  { label: "Private Limited", value: "private_limited" },
  { label: "Public Limited", value: "public_limited" },
  { label: "LLP", value: "llp" },
  { label: "Other", value: "other" },
];

export default function KYC() {
  const { toast } = useToast();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [seller, setSeller] = useState<any | null>(null);
  const [kycStatus, setKycStatus] = useState<string | null>(null);
  const [notifications, setNotifications] = useState<any[]>([]);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const [formData, setFormData] = useState({
    aadhaarNumber: "",
    panNumber: "",
    gstin: "",
    businessName: "",
    businessType: "individual", // ✅ default valid enum
    phone: "",
    address: "",
    bankName: "",
    bankAccountNumber: "",
    bankIfscCode: "",
    bankAccountHolderName: "",
    accountType: "savings",
    email: "",
  });

  const [selfiePhoto, setSelfiePhoto] = useState<File | null>(null);
  const [aadhaarPhoto, setAadhaarPhoto] = useState<File | null>(null);
  const [panPhoto, setPanPhoto] = useState<File | null>(null);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const {
          data: { user },
        } = await supabase.auth.getUser();
        if (!user) {
          navigate("/auth/signin");
          return;
        }

        const { data: s, error } = await supabase
          .from("sellers")
          .select("*")
          .eq("user_id", user.id)
          .maybeSingle();
        if (error) throw error;

        if (s) {
          setSeller(s);
          setKycStatus(s.verification_status);

          if (s.verification_status === "pending") {
            navigate("/seller-verification");
            return;
          }

          setFormData({
            aadhaarNumber: s.aadhaar ?? "",
            panNumber: s.pan ?? "",
            gstin: s.gstin ?? "",
            businessName: s.business_name ?? "",
            businessType: s.business_type || "individual", // ✅ default if null
            phone: s.phone ?? "",
            address: s.address_line1 ?? "",
            bankName: s.bank_name ?? "",
            bankAccountNumber: s.account_number ?? "",
            bankIfscCode: s.ifsc_code ?? "",
            bankAccountHolderName: s.account_holder_name ?? "",
            accountType: s.account_type ?? "savings",
            email: s.email ?? "",
          });

          const { data: notifs } = await supabase
            .from("notifications")
            .select("*")
            .eq("related_seller_id", s.id)
            .order("created_at", { ascending: false })
            .limit(20);
          setNotifications(notifs ?? []);
        }
      } catch (err: any) {
        console.error("KYC load error", err);
        toast({
          title: "Error",
          description: err.message || "Failed to load KYC",
          variant: "destructive",
        });
      } finally {
        setLoading(false);
      }
    })();
  }, [navigate, toast]);

  const uploadFile = async (file: File, folder: string) => {
    if (!seller?.id) throw new Error("No seller id");
    const ext = (file.name.split(".").pop() || "dat").toLowerCase();
    const path = `${seller.id}/${folder}/${Date.now()}.${ext}`;
    const up = await supabase.storage
      .from("seller_details")
      .upload(path, file, { upsert: true });
    if (up.error) throw up.error;
    const signed = await supabase.storage
      .from("seller_details")
      .createSignedUrl(up.data.path, 60 * 60 * 24 * 365 * 10);
    if (signed.error) throw signed.error;
    return signed.data.signedUrl;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrors({});
    setSubmitting(true);

    try {
      const validation = kycSchema.safeParse({
        aadhaarNumber: formData.aadhaarNumber || undefined,
        panNumber: formData.panNumber || undefined,
        gstin: formData.gstin || undefined,
        bankAccountNumber: formData.bankAccountNumber || undefined,
        bankIfscCode: formData.bankIfscCode || undefined,
      });

      if (!validation.success) {
        const errs: Record<string, string> = {};
        validation.error.errors.forEach(
          (er) => (errs[er.path[0] as string] = er.message)
        );
        setErrors(errs);
        toast({
          title: "Validation error",
          description: "Fix form errors",
          variant: "destructive",
        });
        setSubmitting(false);
        return;
      }

      // Ensure GSTIN includes PAN
      if (
        formData.gstin &&
        formData.panNumber &&
        !formData.gstin.includes(formData.panNumber)
      ) {
        setErrors({ gstin: "GSTIN must contain PAN" });
        toast({
          title: "Validation error",
          description: "GSTIN must contain PAN",
          variant: "destructive",
        });
        setSubmitting(false);
        return;
      }

      // ✅ Always send a valid enum value for business_type
      const safeBusinessType =
        BUSINESS_TYPES.find(
          (b) => b.value === formData.businessType?.toLowerCase()
        )?.value || "individual";

      if (!seller) {
        if (!selfiePhoto || !aadhaarPhoto || !panPhoto) {
          toast({
            title: "Missing photos",
            description: "Please upload Selfie, Aadhaar and PAN photos",
            variant: "destructive",
          });
          setSubmitting(false);
          return;
        }

        const {
          data: { user },
        } = await supabase.auth.getUser();
        if (!user) throw new Error("Not authenticated");

        const { data: newSeller, error } = await supabase
          .from("sellers")
          .insert({
            user_id: user.id,
            name: formData.businessName || user.email,
            email: user.email,
            phone: formData.phone || null,
            aadhaar: formData.aadhaarNumber || null,
            pan: formData.panNumber || null,
            gstin: formData.gstin || null,
            business_name: formData.businessName || null,
            business_type: safeBusinessType, // ✅ valid enum guaranteed
            address_line1: formData.address || null,
            bank_name: formData.bankName || null,
            account_number: formData.bankAccountNumber || null,
            ifsc_code: formData.bankIfscCode || null,
            account_holder_name: formData.bankAccountHolderName || null,
            account_type: formData.accountType || null,
            verification_status: "pending",
            onboarding_status: "in_review",
          })
          .select()
          .single();

        if (error) throw error;

        toast({
          title: "KYC submitted",
          description: "Documents are under review",
        });
        navigate("/seller-verification");
        return;
      }

      const { error: updErr } = await supabase
        .from("sellers")
        .update({
          aadhaar: formData.aadhaarNumber,
          pan: formData.panNumber,
          gstin: formData.gstin,
          business_name: formData.businessName,
          business_type: safeBusinessType, // ✅ enum-safe always
          address_line1: formData.address,
          bank_name: formData.bankName,
          account_number: formData.bankAccountNumber,
          ifsc_code: formData.bankIfscCode,
          account_holder_name: formData.bankAccountHolderName,
          email: formData.email,
          verification_status: "pending",
        })
        .eq("id", seller.id);

      if (updErr) throw updErr;

      toast({ title: "Resubmitted", description: "Your KYC was resubmitted" });
      navigate("/seller-verification");
    } catch (err: any) {
      console.error("KYC submit error", err);
      toast({
        title: "Error",
        description: err.message || "Failed to submit KYC",
        variant: "destructive",
      });
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) return <div className="p-8 text-center">Loading...</div>;

  if (kycStatus === "approved" || kycStatus === "verified")
    return (
      <div className="min-h-screen flex items-center justify-center bg-background px-4">
        <Card className="w-full max-w-md text-center">
          <CardHeader>
            <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4" />
            <CardTitle className="text-2xl">KYC Verified</CardTitle>
            <CardDescription>Your account is verified.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => navigate("/dashboard")}>
              Go to Dashboard
            </Button>
          </CardContent>
        </Card>
      </div>
    );

  return (
    <div className="min-h-screen bg-background py-12 px-4">
      <div className="max-w-4xl mx-auto">
        <Card>
          <CardHeader>
            <CardTitle className="text-3xl">Complete KYC Verification</CardTitle>
            <CardDescription>Provide accurate information</CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="kyc">
              <TabsList>
                <TabsTrigger value="kyc">KYC</TabsTrigger>
                <TabsTrigger value="notifications">
                  Notifications ({notifications.length})
                </TabsTrigger>
              </TabsList>

              <TabsContent value="kyc" className="mt-4">
                <form onSubmit={handleSubmit} className="space-y-6">
                  <div className="space-y-4 p-4 bg-accent/20 rounded-lg">
                    <h3 className="text-lg font-semibold flex items-center gap-2">
                      <Camera className="w-5 h-5" /> Upload Documents
                    </h3>
                    <div className="grid md:grid-cols-3 gap-4">
                      <div>
                        <Label>Selfie Photo</Label>
                        <Input
                          type="file"
                          accept="image/*"
                          onChange={(e) =>
                            setSelfiePhoto(e.target.files?.[0] || null)
                          }
                        />
                      </div>
                      <div>
                        <Label>Aadhaar Photo</Label>
                        <Input
                          type="file"
                          accept="image/*"
                          onChange={(e) =>
                            setAadhaarPhoto(e.target.files?.[0] || null)
                          }
                        />
                      </div>
                      <div>
                        <Label>PAN Photo</Label>
                        <Input
                          type="file"
                          accept="image/*"
                          onChange={(e) =>
                            setPanPhoto(e.target.files?.[0] || null)
                          }
                        />
                      </div>
                    </div>
                  </div>

                  <div className="grid md:grid-cols-2 gap-4">
                    <div>
                      <Label>Aadhaar Number</Label>
                      <Input
                        value={formData.aadhaarNumber}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            aadhaarNumber: e.target.value,
                          })
                        }
                      />
                      {errors.aadhaarNumber && (
                        <p className="text-sm text-destructive">
                          {errors.aadhaarNumber}
                        </p>
                      )}
                    </div>

                    <div>
                      <Label>PAN Number</Label>
                      <Input
                        value={formData.panNumber}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            panNumber: e.target.value.toUpperCase(),
                          })
                        }
                      />
                      {errors.panNumber && (
                        <p className="text-sm text-destructive">
                          {errors.panNumber}
                        </p>
                      )}
                    </div>

                    <div>
                      <Label>GSTIN</Label>
                      <Input
                        value={formData.gstin}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            gstin: e.target.value.toUpperCase(),
                          })
                        }
                      />
                      {errors.gstin && (
                        <p className="text-sm text-destructive">
                          {errors.gstin}
                        </p>
                      )}
                    </div>

                    <div>
                      <Label>Business Name</Label>
                      <Input
                        value={formData.businessName}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            businessName: e.target.value,
                          })
                        }
                      />
                    </div>

                    {/* ✅ ENUM dropdown always valid */}
                    <div>
                      <Label>Business Type</Label>
                      <select
                        className="w-full border border-input rounded-md p-2 bg-background"
                        value={formData.businessType}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            businessType: e.target.value,
                          })
                        }
                        required
                      >
                        {BUSINESS_TYPES.map((t) => (
                          <option key={t.value} value={t.value}>
                            {t.label}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <Label>Phone</Label>
                      <Input
                        value={formData.phone}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            phone: e.target.value,
                          })
                        }
                      />
                    </div>

                    <div className="md:col-span-2">
                      <Label>Address</Label>
                      <Input
                        value={formData.address}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            address: e.target.value,
                          })
                        }
                      />
                    </div>

                    <div>
                      <Label>Bank Name</Label>
                      <Input
                        value={formData.bankName}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            bankName: e.target.value,
                          })
                        }
                      />
                    </div>

                    <div>
                      <Label>Account Number</Label>
                      <Input
                        value={formData.bankAccountNumber}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            bankAccountNumber: e.target.value,
                          })
                        }
                      />
                      {errors.bankAccountNumber && (
                        <p className="text-sm text-destructive">
                          {errors.bankAccountNumber}
                        </p>
                      )}
                    </div>

                    <div>
                      <Label>IFSC Code</Label>
                      <Input
                        value={formData.bankIfscCode}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            bankIfscCode: e.target.value.toUpperCase(),
                          })
                        }
                      />
                      {errors.bankIfscCode && (
                        <p className="text-sm text-destructive">
                          {errors.bankIfscCode}
                        </p>
                      )}
                    </div>

                    <div>
                      <Label>Account Holder Name</Label>
                      <Input
                        value={formData.bankAccountHolderName}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            bankAccountHolderName: e.target.value,
                          })
                        }
                      />
                    </div>

                    <div>
                      <Label>Email</Label>
                      <Input
                        value={formData.email}
                        onChange={(e) =>
                          setFormData({
                            ...formData,
                            email: e.target.value,
                          })
                        }
                      />
                    </div>
                  </div>

                  <div className="flex justify-end">
                    <Button type="submit" disabled={submitting}>
                      {submitting && (
                        <Loader2 className="animate-spin h-4 w-4 mr-2" />
                      )}
                      Submit KYC
                    </Button>
                  </div>
                </form>
              </TabsContent>

              <TabsContent value="notifications" className="mt-4">
                <div className="space-y-2">
                  {notifications.length === 0 ? (
                    <div className="p-4 text-sm text-muted-foreground">
                      No notifications
                    </div>
                  ) : (
                    notifications.map((n: any) => (
                      <div
                        key={n.id}
                        className="border rounded p-3 flex justify-between items-start"
                      >
                        <div>
                          <div className="text-sm font-semibold">
                            {n.title || n.type}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {n.message}
                          </div>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {new Date(n.created_at).toLocaleString()}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}