import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import type { DocumentType, UploadedDocument } from "@/types/seller.types";
import {
  documentUploadSchema,
  validateFile as zodValidateFile,
  FILE_VALIDATION_CONSTANTS,
  documentDeleteSchema,
} from "@/lib/validations/document.schema";
import { ZodError } from "zod";

export const useDocumentUpload = () => {
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const uploadDocument = async (
    sellerId: string,
    file: File,
    docType: DocumentType
  ): Promise<{ success: boolean; document?: UploadedDocument; error?: string }> => {
    setUploading(true);
    setError(null);

    try {
      // Validate using Zod schema
      const validationResult = documentUploadSchema.safeParse({
        sellerId,
        file,
        docType,
      });

      if (!validationResult.success) {
        const errorMessage = validationResult.error.errors[0]?.message || "Validation failed";
        throw new Error(errorMessage);
      }

      // Upload file to storage
      // Bucket: seller_details
      // Path inside bucket: seller_details/{sellerId}/{docType}/{timestamp}_{filename}
      const filePath = `seller_details/${sellerId}/${docType}/${Date.now()}_${file.name}`;

      console.log("Uploading to bucket 'seller_details', path:", filePath);

      const { data: uploadData, error: uploadError } = await supabase.storage
        .from("seller_details")
        .upload(filePath, file, {
          cacheControl: "3600",
          upsert: false,
        });

      if (uploadError) {
        throw new Error(`Upload failed: ${uploadError.message}`);
      }

      // Get signed URL (valid for 100 years - effectively permanent)
      const { data: signedUrlData, error: signedUrlError } = await supabase.storage
        .from("seller_details")
        .createSignedUrl(filePath, 60 * 60 * 24 * 365 * 100);

      if (signedUrlError) {
        throw new Error(`Signed URL generation failed: ${signedUrlError.message}`);
      }

      // Save document metadata to seller_documents table
      const { data: docData, error: docError } = await supabase
        .from("seller_documents")
        .insert({
          seller_id: sellerId,
          doc_type: docType,
          file_name: file.name,
          file_size: file.size,
          mime_type: file.type,
          storage_path: filePath,
          uploaded_at: new Date().toISOString(),
        })
        .select()
        .single();

      if (docError) {
        // If metadata save fails, try to delete the uploaded file
        await supabase.storage.from("seller_details").remove([filePath]);
        throw new Error(`Failed to save document metadata: ${docError.message}`);
      }

      const uploadedDoc: UploadedDocument = {
        id: docData.id,
        docType: docType,
        fileName: file.name,
        fileSize: file.size,
        mimeType: file.type,
        storagePath: filePath,
        uploadedAt: docData.uploaded_at,
      };

      setUploading(false);
      return { success: true, document: uploadedDoc };
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Failed to upload document";
      setError(errorMessage);
      setUploading(false);
      console.error("Document upload error:", err);
      return { success: false, error: errorMessage };
    }
  };

  const deleteDocument = async (documentId: string, storagePath: string): Promise<boolean> => {
    try {
      // Validate input using Zod schema
      const validationResult = documentDeleteSchema.safeParse({
        documentId,
        storagePath,
      });

      if (!validationResult.success) {
        console.error("Invalid delete parameters:", validationResult.error);
        return false;
      }

      // Delete from storage
      const { error: storageError } = await supabase.storage
        .from("seller_details")
        .remove([storagePath]);

      if (storageError) {
        console.error("Failed to delete file from storage:", storageError);
      }

      // Delete from database
      const { error: dbError } = await supabase
        .from("seller_documents")
        .delete()
        .eq("id", documentId);

      if (dbError) {
        throw new Error(`Failed to delete document: ${dbError.message}`);
      }

      return true;
    } catch (err) {
      console.error("Document deletion error:", err);
      return false;
    }
  };

  const validateFile = (file: File): { valid: boolean; error?: string } => {
    // Use Zod validation helper
    return zodValidateFile(file);
  };

  return {
    uploadDocument,
    deleteDocument,
    validateFile,
    uploading,
    error,
  };
};
