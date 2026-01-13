import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "./useAuth";

export interface UserIntelProfile {
  id: string;
  user_id: string;
  sectors: string[];
  countries: string[];
  regions: string[];
  threat_actors: string[];
  keywords: string[];
  alert_threshold: "critical" | "high" | "medium" | "all";
  summary_frequency: "realtime" | "daily" | "weekly";
  show_global_threats: boolean;
  created_at: string;
  updated_at: string;
}

export type UserIntelProfileUpdate = Partial<
  Omit<UserIntelProfile, "id" | "user_id" | "created_at" | "updated_at">
>;

// Cast supabase to any to bypass strict type checking
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const db = supabase as any;

async function fetchUserIntelProfile(userId: string): Promise<UserIntelProfile | null> {
  const { data, error } = await db
    .from("user_intel_profiles")
    .select("*")
    .eq("user_id", userId)
    .single();

  if (error) {
    if (error.code === "PGRST116") {
      // No profile exists yet
      return null;
    }
    throw error;
  }

  return data as UserIntelProfile;
}

async function createOrUpdateProfile(
  userId: string,
  profile: UserIntelProfileUpdate
): Promise<UserIntelProfile> {
  const { data, error } = await db
    .from("user_intel_profiles")
    .upsert(
      {
        user_id: userId,
        ...profile,
      },
      {
        onConflict: "user_id",
      }
    )
    .select()
    .single();

  if (error) throw error;
  return data as UserIntelProfile;
}

export const useUserIntelProfile = () => {
  const { user, session } = useAuth();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["user-intel-profile", user?.id],
    queryFn: () => fetchUserIntelProfile(user!.id),
    enabled: !!user?.id && !!session,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  const mutation = useMutation({
    mutationFn: (profile: UserIntelProfileUpdate) => createOrUpdateProfile(user!.id, profile),
    onSuccess: (data) => {
      queryClient.setQueryData(["user-intel-profile", user?.id], data);
    },
  });

  const updateProfile = (profile: UserIntelProfileUpdate) => {
    return mutation.mutateAsync(profile);
  };

  // Check if user has completed onboarding (has at least one preference set)
  const hasCompletedOnboarding = !!(
    query.data &&
    (query.data.sectors.length > 0 || query.data.regions.length > 0 || query.data.countries.length > 0)
  );

  return {
    profile: query.data,
    isLoading: query.isLoading,
    error: query.error,
    updateProfile,
    isUpdating: mutation.isPending,
    hasCompletedOnboarding,
    refetch: query.refetch,
  };
};
