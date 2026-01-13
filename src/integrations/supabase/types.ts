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
      domain_blacklist: {
        Row: {
          created_at: string
          created_by: string | null
          domain: string
          id: string
        }
        Insert: {
          created_at?: string
          created_by?: string | null
          domain: string
          id?: string
        }
        Update: {
          created_at?: string
          created_by?: string | null
          domain?: string
          id?: string
        }
        Relationships: []
      }
      intelligence_summaries: {
        Row: {
          content: string
          created_at: string
          created_by: string
          entity_metadata: Json | null
          id: string
          period_end: string
          period_start: string
          title: string
        }
        Insert: {
          content: string
          created_at?: string
          created_by: string
          entity_metadata?: Json | null
          id?: string
          period_end: string
          period_start: string
          title: string
        }
        Update: {
          content?: string
          created_at?: string
          created_by?: string
          entity_metadata?: Json | null
          id?: string
          period_end?: string
          period_start?: string
          title?: string
        }
        Relationships: []
      }
      lifetime_access_slots: {
        Row: {
          created_at: string | null
          id: string
          max_slots: number
          plan_id: string | null
          slots_used: number
        }
        Insert: {
          created_at?: string | null
          id?: string
          max_slots?: number
          plan_id?: string | null
          slots_used?: number
        }
        Update: {
          created_at?: string | null
          id?: string
          max_slots?: number
          plan_id?: string | null
          slots_used?: number
        }
        Relationships: [
          {
            foreignKeyName: "lifetime_access_slots_plan_id_fkey"
            columns: ["plan_id"]
            isOneToOne: false
            referencedRelation: "subscription_plans"
            referencedColumns: ["id"]
          },
        ]
      }
      lifetime_grants: {
        Row: {
          granted_at: string
          granted_by: string | null
          id: string
          notes: string | null
          user_id: string
        }
        Insert: {
          granted_at?: string
          granted_by?: string | null
          id?: string
          notes?: string | null
          user_id: string
        }
        Update: {
          granted_at?: string
          granted_by?: string | null
          id?: string
          notes?: string | null
          user_id?: string
        }
        Relationships: []
      }
      media_reports: {
        Row: {
          created_at: string | null
          description: string | null
          guid: string
          id: string
          link: string
          pub_date: string | null
          source: string | null
          summary: string | null
          title: string
        }
        Insert: {
          created_at?: string | null
          description?: string | null
          guid: string
          id?: string
          link: string
          pub_date?: string | null
          source?: string | null
          summary?: string | null
          title: string
        }
        Update: {
          created_at?: string | null
          description?: string | null
          guid?: string
          id?: string
          link?: string
          pub_date?: string | null
          source?: string | null
          summary?: string | null
          title?: string
        }
        Relationships: []
      }
      media_source_blacklist: {
        Row: {
          created_at: string | null
          created_by: string | null
          id: string
          source: string
        }
        Insert: {
          created_at?: string | null
          created_by?: string | null
          id?: string
          source: string
        }
        Update: {
          created_at?: string | null
          created_by?: string | null
          id?: string
          source?: string
        }
        Relationships: []
      }
      profiles: {
        Row: {
          created_at: string
          email: string | null
          id: string
          user_id: string
        }
        Insert: {
          created_at?: string
          email?: string | null
          id?: string
          user_id: string
        }
        Update: {
          created_at?: string
          email?: string | null
          id?: string
          user_id?: string
        }
        Relationships: []
      }
      reports: {
        Row: {
          content: string
          created_at: string
          id: string
          query: string
          title: string
          user_id: string
        }
        Insert: {
          content: string
          created_at?: string
          id?: string
          query: string
          title: string
          user_id: string
        }
        Update: {
          content?: string
          created_at?: string
          id?: string
          query?: string
          title?: string
          user_id?: string
        }
        Relationships: []
      }
      subscription_plans: {
        Row: {
          created_at: string
          id: string
          is_active: boolean
          name: string
          price_annual: number
          price_monthly: number
          trial_days: number | null
        }
        Insert: {
          created_at?: string
          id?: string
          is_active?: boolean
          name: string
          price_annual: number
          price_monthly: number
          trial_days?: number | null
        }
        Update: {
          created_at?: string
          id?: string
          is_active?: boolean
          name?: string
          price_annual?: number
          price_monthly?: number
          trial_days?: number | null
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          created_at: string
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
      user_subscriptions: {
        Row: {
          billing_period: Database["public"]["Enums"]["billing_period"]
          created_at: string
          current_period_end: string
          current_period_start: string
          id: string
          plan_id: string | null
          status: Database["public"]["Enums"]["subscription_status"]
          tokens_granted_this_period: number
          updated_at: string
          user_id: string
        }
        Insert: {
          billing_period: Database["public"]["Enums"]["billing_period"]
          created_at?: string
          current_period_end: string
          current_period_start?: string
          id?: string
          plan_id?: string | null
          status?: Database["public"]["Enums"]["subscription_status"]
          tokens_granted_this_period?: number
          updated_at?: string
          user_id: string
        }
        Update: {
          billing_period?: Database["public"]["Enums"]["billing_period"]
          created_at?: string
          current_period_end?: string
          current_period_start?: string
          id?: string
          plan_id?: string | null
          status?: Database["public"]["Enums"]["subscription_status"]
          tokens_granted_this_period?: number
          updated_at?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "user_subscriptions_plan_id_fkey"
            columns: ["plan_id"]
            isOneToOne: false
            referencedRelation: "subscription_plans"
            referencedColumns: ["id"]
          },
        ]
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
      app_role: "admin" | "user"
      billing_period: "monthly" | "annual"
      subscription_status: "active" | "cancelled" | "expired"
      token_transaction_type:
        | "ai_query"
        | "subscription_grant"
        | "admin_grant"
        | "package_purchase"
        | "refund"
        | "signup_bonus"
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
      app_role: ["admin", "user"],
      billing_period: ["monthly", "annual"],
      subscription_status: ["active", "cancelled", "expired"],
      token_transaction_type: [
        "ai_query",
        "subscription_grant",
        "admin_grant",
        "package_purchase",
        "refund",
        "signup_bonus",
      ],
    },
  },
} as const
