export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "13.0.5"
  }
  public: {
    Tables: {
      ads: {
        Row: {
          ad_type: string
          admin_comments: string | null
          approved_at: string | null
          clicks: number
          created_at: string
          description: string | null
          duration_days: number | null
          id: string
          media_url: string | null
          seller_id: string
          status: Database["public"]["Enums"]["ad_status"]
          target_audience: string | null
          title: string
          updated_at: string
          views: number
        }
        Insert: {
          ad_type: string
          admin_comments?: string | null
          approved_at?: string | null
          clicks?: number
          created_at?: string
          description?: string | null
          duration_days?: number | null
          id?: string
          media_url?: string | null
          seller_id: string
          status?: Database["public"]["Enums"]["ad_status"]
          target_audience?: string | null
          title: string
          updated_at?: string
          views?: number
        }
        Update: {
          ad_type?: string
          admin_comments?: string | null
          approved_at?: string | null
          clicks?: number
          created_at?: string
          description?: string | null
          duration_days?: number | null
          id?: string
          media_url?: string | null
          seller_id?: string
          status?: Database["public"]["Enums"]["ad_status"]
          target_audience?: string | null
          title?: string
          updated_at?: string
          views?: number
        }
        Relationships: []
      }
      bundles: {
        Row: {
          created_at: string
          description: string | null
          discount_percentage: number | null
          id: string
          image_url: string | null
          name: string
          product_ids: string[]
          seller_id: string
          total_price: number
          updated_at: string
        }
        Insert: {
          created_at?: string
          description?: string | null
          discount_percentage?: number | null
          id?: string
          image_url?: string | null
          name: string
          product_ids: string[]
          seller_id: string
          total_price: number
          updated_at?: string
        }
        Update: {
          created_at?: string
          description?: string | null
          discount_percentage?: number | null
          id?: string
          image_url?: string | null
          name?: string
          product_ids?: string[]
          seller_id?: string
          total_price?: number
          updated_at?: string
        }
        Relationships: []
      }
      chat_logs: {
        Row: {
          created_at: string
          id: string
          message: string
          response: string
          seller_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          message: string
          response: string
          seller_id: string
        }
        Update: {
          created_at?: string
          id?: string
          message?: string
          response?: string
          seller_id?: string
        }
        Relationships: []
      }
      earnings: {
        Row: {
          ad_credits: number
          created_at: string
          id: string
          redeemed_amount: number
          seller_id: string
          total_earned: number
          updated_at: string
        }
        Insert: {
          ad_credits?: number
          created_at?: string
          id?: string
          redeemed_amount?: number
          seller_id: string
          total_earned?: number
          updated_at?: string
        }
        Update: {
          ad_credits?: number
          created_at?: string
          id?: string
          redeemed_amount?: number
          seller_id?: string
          total_earned?: number
          updated_at?: string
        }
        Relationships: []
      }
      kyc_documents: {
        Row: {
          aadhaar_document_url: string | null
          aadhaar_number: string | null
          bank_account_holder_name: string | null
          bank_account_number: string | null
          bank_ifsc_code: string | null
          created_at: string
          gstin: string | null
          gstin_document_url: string | null
          id: string
          pan_document_url: string | null
          pan_number: string | null
          rejection_reason: string | null
          selfie_url: string | null
          updated_at: string
          user_id: string
          verification_status: Database["public"]["Enums"]["kyc_status"]
          verified_at: string | null
        }
        Insert: {
          aadhaar_document_url?: string | null
          aadhaar_number?: string | null
          bank_account_holder_name?: string | null
          bank_account_number?: string | null
          bank_ifsc_code?: string | null
          created_at?: string
          gstin?: string | null
          gstin_document_url?: string | null
          id?: string
          pan_document_url?: string | null
          pan_number?: string | null
          rejection_reason?: string | null
          selfie_url?: string | null
          updated_at?: string
          user_id: string
          verification_status?: Database["public"]["Enums"]["kyc_status"]
          verified_at?: string | null
        }
        Update: {
          aadhaar_document_url?: string | null
          aadhaar_number?: string | null
          bank_account_holder_name?: string | null
          bank_account_number?: string | null
          bank_ifsc_code?: string | null
          created_at?: string
          gstin?: string | null
          gstin_document_url?: string | null
          id?: string
          pan_document_url?: string | null
          pan_number?: string | null
          rejection_reason?: string | null
          selfie_url?: string | null
          updated_at?: string
          user_id?: string
          verification_status?: Database["public"]["Enums"]["kyc_status"]
          verified_at?: string | null
        }
        Relationships: []
      }
      media: {
        Row: {
          created_at: string
          id: string
          is_profile_photo: boolean | null
          linked_bundle_id: string | null
          linked_product_id: string | null
          media_type: string
          seller_id: string
          url: string
        }
        Insert: {
          created_at?: string
          id?: string
          is_profile_photo?: boolean | null
          linked_bundle_id?: string | null
          linked_product_id?: string | null
          media_type: string
          seller_id: string
          url: string
        }
        Update: {
          created_at?: string
          id?: string
          is_profile_photo?: boolean | null
          linked_bundle_id?: string | null
          linked_product_id?: string | null
          media_type?: string
          seller_id?: string
          url?: string
        }
        Relationships: [
          {
            foreignKeyName: "media_linked_bundle_id_fkey"
            columns: ["linked_bundle_id"]
            isOneToOne: false
            referencedRelation: "bundles"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "media_linked_product_id_fkey"
            columns: ["linked_product_id"]
            isOneToOne: false
            referencedRelation: "products"
            referencedColumns: ["id"]
          },
        ]
      }
      orders: {
        Row: {
          bundle_id: string | null
          created_at: string
          customer_email: string | null
          customer_id: string | null
          customer_name: string | null
          customer_phone: string | null
          estimated_delivery_date: string | null
          feedback_rating: number | null
          feedback_text: string | null
          id: string
          product_id: string | null
          quantity: number
          seller_id: string
          shipping_address: string | null
          status: Database["public"]["Enums"]["order_status"]
          total_amount: number
          updated_at: string
        }
        Insert: {
          bundle_id?: string | null
          created_at?: string
          customer_email?: string | null
          customer_id?: string | null
          customer_name?: string | null
          customer_phone?: string | null
          estimated_delivery_date?: string | null
          feedback_rating?: number | null
          feedback_text?: string | null
          id?: string
          product_id?: string | null
          quantity: number
          seller_id: string
          shipping_address?: string | null
          status?: Database["public"]["Enums"]["order_status"]
          total_amount: number
          updated_at?: string
        }
        Update: {
          bundle_id?: string | null
          created_at?: string
          customer_email?: string | null
          customer_id?: string | null
          customer_name?: string | null
          customer_phone?: string | null
          estimated_delivery_date?: string | null
          feedback_rating?: number | null
          feedback_text?: string | null
          id?: string
          product_id?: string | null
          quantity?: number
          seller_id?: string
          shipping_address?: string | null
          status?: Database["public"]["Enums"]["order_status"]
          total_amount?: number
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "orders_bundle_id_fkey"
            columns: ["bundle_id"]
            isOneToOne: false
            referencedRelation: "bundles"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "orders_product_id_fkey"
            columns: ["product_id"]
            isOneToOne: false
            referencedRelation: "products"
            referencedColumns: ["id"]
          },
        ]
      }
      products: {
        Row: {
          allergens: string | null
          barcode: string | null
          certificate_urls: string[] | null
          created_at: string
          description: string | null
          expiry_date: string | null
          health_score: number | null
          id: string
          image_urls: string[] | null
          ingredients: string | null
          is_draft: boolean
          manufacturing_date: string | null
          name: string
          price: number
          return_policy: string | null
          seller_id: string
          stock_quantity: number
          updated_at: string
          variants: Json | null
          video_urls: string[] | null
        }
        Insert: {
          allergens?: string | null
          barcode?: string | null
          certificate_urls?: string[] | null
          created_at?: string
          description?: string | null
          expiry_date?: string | null
          health_score?: number | null
          id?: string
          image_urls?: string[] | null
          ingredients?: string | null
          is_draft?: boolean
          manufacturing_date?: string | null
          name: string
          price: number
          return_policy?: string | null
          seller_id: string
          stock_quantity?: number
          updated_at?: string
          variants?: Json | null
          video_urls?: string[] | null
        }
        Update: {
          allergens?: string | null
          barcode?: string | null
          certificate_urls?: string[] | null
          created_at?: string
          description?: string | null
          expiry_date?: string | null
          health_score?: number | null
          id?: string
          image_urls?: string[] | null
          ingredients?: string | null
          is_draft?: boolean
          manufacturing_date?: string | null
          name?: string
          price?: number
          return_policy?: string | null
          seller_id?: string
          stock_quantity?: number
          updated_at?: string
          variants?: Json | null
          video_urls?: string[] | null
        }
        Relationships: []
      }
      profiles: {
        Row: {
          address: string | null
          business_name: string | null
          business_type: string | null
          created_at: string
          email: string
          id: string
          phone: string | null
          profile_photo_url: string | null
          updated_at: string
          user_id: string
          username: string
        }
        Insert: {
          address?: string | null
          business_name?: string | null
          business_type?: string | null
          created_at?: string
          email: string
          id?: string
          phone?: string | null
          profile_photo_url?: string | null
          updated_at?: string
          user_id: string
          username: string
        }
        Update: {
          address?: string | null
          business_name?: string | null
          business_type?: string | null
          created_at?: string
          email?: string
          id?: string
          phone?: string | null
          profile_photo_url?: string | null
          updated_at?: string
          user_id?: string
          username?: string
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
    }
    Enums: {
      ad_status: "pending" | "approved" | "rejected"
      app_role: "admin" | "seller" | "customer"
      kyc_status: "pending" | "approved" | "rejected"
      order_status:
        | "pending"
        | "accepted"
        | "rejected"
        | "shipped"
        | "delivered"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      ad_status: ["pending", "approved", "rejected"],
      app_role: ["admin", "seller", "customer"],
      kyc_status: ["pending", "approved", "rejected"],
      order_status: ["pending", "accepted", "rejected", "shipped", "delivered"],
    },
  },
} as const
