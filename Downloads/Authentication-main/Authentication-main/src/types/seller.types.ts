/**
 * Type definitions for seller-related entities
 */

export type DocumentType = 
  | "aadhaar" 
  | "pan" 
  | "gstin"
  | "selfie" 
  | "bank_statement" 
  | "address_proof"
  | "other";

export interface UploadedDocument {
  id: string;
  docType: DocumentType;
  fileName: string;
  fileSize: number;
  mimeType: string;
  storagePath: string;
  uploadedAt: string;
  url?: string;
}

export interface Seller {
  id: string;
  user_id: string;
  name: string | null;
  email: string | null;
  phone: string | null;
  aadhaar: string | null;
  aadhaar_verified: boolean | null;
  pan: string | null;
  pan_verified: boolean | null;
  gstin: string | null;
  gstin_verified: boolean | null;
  business_name: string | null;
  business_type: string | null;
  address_line1: string | null;
  address_line2: string | null;
  city: string | null;
  state: string | null;
  pincode: string | null;
  country: string | null;
  verification_status: string | null;
  onboarding_status: string | null;
  onboarding_step: number | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface SellerBankAccount {
  id: string;
  seller_id: string;
  account_holder_name: string | null;
  account_number: string | null;
  account_type: string | null;
  bank_name: string | null;
  ifsc_code: string | null;
  is_primary: boolean | null;
  verification_status: string | null;
  razorpay_fund_account_id: string | null;
  created_at: string | null;
}

export interface SellerDocument {
  id: string;
  seller_id: string;
  doc_type: string | null;
  file_name: string | null;
  file_size: number | null;
  mime_type: string | null;
  storage_path: string | null;
  uploaded_at: string | null;
  ocr_extracted_data: Record<string, unknown> | null;
  verification_confidence: number | null;
}
