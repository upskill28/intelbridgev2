import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "./useAuth";
import { toast } from "sonner";

export interface Asset {
  id: string;
  user_id: string;
  asset_type: "domain" | "email_domain";
  value: string;
  description: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface AssetCreate {
  asset_type: "domain" | "email_domain";
  value: string;
  description?: string;
}

export interface AssetUpdate {
  description?: string;
  is_active?: boolean;
}

// Cast supabase to any to bypass strict type checking
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const db = supabase as any;

async function fetchAssets(userId: string): Promise<Asset[]> {
  const { data, error } = await db
    .from("user_assets")
    .select("*")
    .eq("user_id", userId)
    .order("created_at", { ascending: false });

  if (error) throw error;
  return data as Asset[];
}

async function createAsset(userId: string, asset: AssetCreate): Promise<Asset> {
  const { data, error } = await db
    .from("user_assets")
    .insert({
      user_id: userId,
      asset_type: asset.asset_type,
      value: asset.value.toLowerCase().trim(),
      description: asset.description || null,
      is_active: true,
    })
    .select()
    .single();

  if (error) throw error;
  return data as Asset;
}

async function updateAsset(assetId: string, updates: AssetUpdate): Promise<Asset> {
  const { data, error } = await db
    .from("user_assets")
    .update({
      ...updates,
      updated_at: new Date().toISOString(),
    })
    .eq("id", assetId)
    .select()
    .single();

  if (error) throw error;
  return data as Asset;
}

async function deleteAsset(assetId: string): Promise<void> {
  const { error } = await db.from("user_assets").delete().eq("id", assetId);

  if (error) throw error;
}

export const useAssets = () => {
  const { user, session } = useAuth();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["user-assets", user?.id],
    queryFn: () => fetchAssets(user!.id),
    enabled: !!user?.id && !!session,
    staleTime: 5 * 60 * 1000,
  });

  const createMutation = useMutation({
    mutationFn: (asset: AssetCreate) => createAsset(user!.id, asset),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["user-assets", user?.id] });
      toast.success("Asset added successfully");
    },
    onError: (error: Error) => {
      toast.error(error.message || "Failed to add asset");
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ assetId, updates }: { assetId: string; updates: AssetUpdate }) =>
      updateAsset(assetId, updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["user-assets", user?.id] });
      toast.success("Asset updated");
    },
    onError: (error: Error) => {
      toast.error(error.message || "Failed to update asset");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (assetId: string) => deleteAsset(assetId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["user-assets", user?.id] });
      toast.success("Asset removed");
    },
    onError: (error: Error) => {
      toast.error(error.message || "Failed to remove asset");
    },
  });

  // Filter by asset type
  const domains = (query.data || []).filter((a) => a.asset_type === "domain");
  const emailDomains = (query.data || []).filter((a) => a.asset_type === "email_domain");

  return {
    assets: query.data || [],
    domains,
    emailDomains,
    isLoading: query.isLoading,
    error: query.error,
    refetch: query.refetch,
    addAsset: createMutation.mutateAsync,
    isAdding: createMutation.isPending,
    updateAsset: (assetId: string, updates: AssetUpdate) =>
      updateMutation.mutateAsync({ assetId, updates }),
    isUpdating: updateMutation.isPending,
    removeAsset: deleteMutation.mutateAsync,
    isRemoving: deleteMutation.isPending,
  };
};
