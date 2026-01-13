import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "./useAuth";

export interface IntelOption {
  id: string;
  name: string;
}

export interface IntelOptions {
  sectors: IntelOption[];
  countries: IntelOption[];
  regions: IntelOption[];
  threatActors: IntelOption[];
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const intelDb = (supabase as any).schema("intel");

async function fetchIntelOptions(): Promise<IntelOptions> {
  const [sectorsResult, countriesResult, regionsResult, threatActorsResult] = await Promise.all([
    // Fetch sectors
    intelDb
      .from("object_current")
      .select("internal_id, name")
      .eq("entity_type", "Sector")
      .eq("is_deleted", false)
      .order("name"),

    // Fetch countries
    intelDb
      .from("object_current")
      .select("internal_id, name")
      .eq("entity_type", "Country")
      .eq("is_deleted", false)
      .order("name"),

    // Fetch regions
    intelDb
      .from("object_current")
      .select("internal_id, name")
      .eq("entity_type", "Region")
      .eq("is_deleted", false)
      .order("name"),

    // Fetch threat actors (Intrusion-Set)
    intelDb
      .from("object_current")
      .select("internal_id, name")
      .eq("entity_type", "Intrusion-Set")
      .eq("is_deleted", false)
      .order("name")
      .limit(200),
  ]);

  return {
    sectors: (sectorsResult.data || []).map((s: any) => ({ id: s.internal_id, name: s.name })),
    countries: (countriesResult.data || []).map((c: any) => ({ id: c.internal_id, name: c.name })),
    regions: (regionsResult.data || []).map((r: any) => ({ id: r.internal_id, name: r.name })),
    threatActors: (threatActorsResult.data || []).map((t: any) => ({ id: t.internal_id, name: t.name })),
  };
}

export const useIntelOptions = () => {
  const { session } = useAuth();
  return useQuery({
    queryKey: ["intel-options"],
    queryFn: fetchIntelOptions,
    staleTime: 30 * 60 * 1000, // 30 minutes - options don't change often
    refetchOnWindowFocus: false,
    enabled: !!session,
  });
};
