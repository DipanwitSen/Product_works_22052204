/**
 * Zod validation schemas for document upload and management
 */

import { z } from "zod";
import type { DocumentType } from "@/types/seller.types";

// File validation constants
export const FILE_VALIDATION_CONSTANTS = {
  MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
  ALLOWED_IMAGE_TYPES: ["image/jpeg", "image/jpg", "image/png", "image/webp"] as const,
  ALLOWED_DOCUMENT_TYPES: ["application/pdf", "image/jpeg", "image/jpg", "image/png"] as const,
} as const;

// Document type validation
const documentTypeSchema = z.enum([
  "aadhaar",
  "pan",
  "gstin",
  "selfie",
  "bank_statement",
  "address_proof",
  "other",
]);

// File validation schema
const fileSchema = z.custom<File>(
  (file) => file instanceof File,
  { message: "Invalid file object" }
).refine(
  (file) => file.size <= FILE_VALIDATION_CONSTANTS.MAX_FILE_SIZE,
  { message: `File size must be less than ${FILE_VALIDATION_CONSTANTS.MAX_FILE_SIZE / 1024 / 1024}MB` }
).refine(
  (file) => (FILE_VALIDATION_CONSTANTS.ALLOWED_DOCUMENT_TYPES as readonly string[]).includes(file.type),
  { message: "Invalid file type. Only PDF and images are allowed" }
);

// Document upload schema
export const documentUploadSchema = z.object({
  sellerId: z.string().uuid("Invalid seller ID"),
  file: fileSchema,
  docType: documentTypeSchema,
});

// Document delete schema
export const documentDeleteSchema = z.object({
  documentId: z.string().uuid("Invalid document ID"),
  storagePath: z.string().min(1, "Storage path is required"),
});

// Seller ID validation schema
export const sellerIdSchema = z.string().uuid("Invalid seller ID");

// File validation helper function
export const validateFile = (file: File): { valid: boolean; error?: string } => {
  try {
    fileSchema.parse(file);
    return { valid: true };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return { valid: false, error: error.errors[0]?.message || "File validation failed" };
    }
    return { valid: false, error: "Unknown validation error" };
  }
};

// Validate document type
export const validateDocumentType = (docType: string): docType is DocumentType => {
  return documentTypeSchema.safeParse(docType).success;
};

// Types exported from schemas
export type DocumentUploadInput = z.infer<typeof documentUploadSchema>;
export type DocumentDeleteInput = z.infer<typeof documentDeleteSchema>;
