import { useQuery, useMutation } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "./useAuth";

export interface IOCResult {
  id: string;
  name: string;
  pattern: string;
  patternType: string;
  observableType: string | null;
  observableValue: string | null;
  score: number | null;
  validFrom: string | null;
  validUntil: string | null;
  created: string;
  modified: string;
  description: string;
  // Related entities
  relatedThreatActors: { id: string; name: string }[];
  relatedMalware: { id: string; name: string }[];
  relatedCampaigns: { id: string; name: string }[];
  relatedReports: { id: string; name: string }[];
}

export interface IOCSearchParams {
  query: string;
  type?: "all" | "ipv4" | "ipv6" | "domain" | "url" | "file-hash" | "email";
  limit?: number;
}

export interface BulkIOCResult {
  query: string;
  found: boolean;
  result: IOCResult | null;
}

// Create intel schema client
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const intelDb = (supabase as any).schema("intel");

// Extract observable value from STIX pattern
function extractObservableValue(pattern: string): string | null {
  if (!pattern) return null;

  // Match patterns like [ipv4-addr:value = '1.2.3.4']
  const valueMatch = pattern.match(/=\s*'([^']+)'/);
  if (valueMatch) return valueMatch[1];

  // Match patterns with double quotes
  const doubleQuoteMatch = pattern.match(/=\s*"([^"]+)"/);
  if (doubleQuoteMatch) return doubleQuoteMatch[1];

  return null;
}

// Determine IOC type from pattern or observable type
function getIOCType(pattern: string, observableType: string | null): string {
  if (observableType) {
    const type = observableType.toLowerCase();
    if (type.includes("ipv4")) return "IPv4";
    if (type.includes("ipv6")) return "IPv6";
    if (type.includes("domain")) return "Domain";
    if (type.includes("url")) return "URL";
    if (type.includes("file") || type.includes("hash")) return "File Hash";
    if (type.includes("email")) return "Email";
    return observableType;
  }

  if (pattern) {
    if (pattern.includes("ipv4-addr")) return "IPv4";
    if (pattern.includes("ipv6-addr")) return "IPv6";
    if (pattern.includes("domain-name")) return "Domain";
    if (pattern.includes("url:value")) return "URL";
    if (pattern.includes("file:hashes")) return "File Hash";
    if (pattern.includes("email-addr")) return "Email";
  }

  return "Unknown";
}

// Get IOC type color
export function getIOCTypeColor(type: string): string {
  const t = type.toLowerCase();
  if (t.includes("ipv4") || t.includes("ipv6")) return "bg-blue-500/20 text-blue-400 border-blue-500/30";
  if (t.includes("domain")) return "bg-green-500/20 text-green-400 border-green-500/30";
  if (t.includes("url")) return "bg-purple-500/20 text-purple-400 border-purple-500/30";
  if (t.includes("file") || t.includes("hash")) return "bg-orange-500/20 text-orange-400 border-orange-500/30";
  if (t.includes("email")) return "bg-pink-500/20 text-pink-400 border-pink-500/30";
  return "bg-muted text-muted-foreground";
}

// Transform intel.object_current data to IOCResult format
function transformIndicator(row: any): IOCResult {
  const data = row.data || {};
  const pattern = data.pattern || "";
  const observableType = data.x_opencti_main_observable_type || null;

  return {
    id: row.internal_id,
    name: row.name || data.name || "Unknown",
    pattern,
    patternType: data.pattern_type || "",
    observableType,
    observableValue: extractObservableValue(pattern),
    score: data.x_opencti_score || null,
    validFrom: data.valid_from || null,
    validUntil: data.valid_until || null,
    created: row.source_created_at || data.created || "",
    modified: row.source_updated_at || data.modified || "",
    description: data.description || "",
    relatedThreatActors: [],
    relatedMalware: [],
    relatedCampaigns: [],
    relatedReports: [],
  };
}

// Search for IOCs
async function searchIOCs(params: IOCSearchParams): Promise<IOCResult[]> {
  const { query, type = "all", limit = 50 } = params;

  if (!query.trim()) return [];

  // Build the search query
  let dbQuery = intelDb
    .from("object_current")
    .select("internal_id, name, data, source_created_at, source_updated_at")
    .eq("entity_type", "Indicator")
    .order("source_updated_at", { ascending: false })
    .limit(limit);

  // Search by name (which contains the observable value) or pattern
  dbQuery = dbQuery.or(`name.ilike.%${query}%,data->>pattern.ilike.%${query}%`);

  // Filter by type if specified
  if (type !== "all") {
    const typeFilters: Record<string, string> = {
      ipv4: "IPv4-Addr",
      ipv6: "IPv6-Addr",
      domain: "Domain-Name",
      url: "Url",
      "file-hash": "StixFile",
      email: "Email-Addr",
    };
    if (typeFilters[type]) {
      dbQuery = dbQuery.ilike("data->>x_opencti_main_observable_type", `%${typeFilters[type]}%`);
    }
  }

  const { data, error } = await dbQuery;

  if (error) throw error;

  const indicators = (data || []).map(transformIndicator);

  // Fetch related entities for each indicator
  if (indicators.length > 0) {
    const indicatorIds = indicators.map((i: IOCResult) => i.id);

    // Get relationships where indicators indicate threats
    const { data: rels } = await intelDb
      .from("relationship_current")
      .select("source_id, target_id, relationship_type")
      .in("source_id", indicatorIds)
      .eq("relationship_type", "indicates");

    if (rels && rels.length > 0) {
      const targetIds = rels.map((r: any) => r.target_id);

      const { data: targets } = await intelDb
        .from("object_current")
        .select("internal_id, name, entity_type")
        .in("internal_id", targetIds);

      const targetMap = new Map(targets?.map((t: any) => [t.internal_id, t]) || []);

      for (const indicator of indicators) {
        const indicatorRels = rels.filter((r: any) => r.source_id === indicator.id);
        for (const rel of indicatorRels) {
          const target = targetMap.get(rel.target_id) as any;
          if (target) {
            if (target.entity_type === "Intrusion-Set") {
              indicator.relatedThreatActors.push({ id: target.internal_id, name: target.name });
            } else if (target.entity_type === "Malware") {
              indicator.relatedMalware.push({ id: target.internal_id, name: target.name });
            } else if (target.entity_type === "Campaign") {
              indicator.relatedCampaigns.push({ id: target.internal_id, name: target.name });
            }
          }
        }
      }
    }
  }

  return indicators;
}

// Bulk lookup IOCs
async function bulkLookupIOCs(queries: string[]): Promise<BulkIOCResult[]> {
  const results: BulkIOCResult[] = [];

  for (const query of queries) {
    const trimmedQuery = query.trim();
    if (!trimmedQuery) {
      results.push({ query, found: false, result: null });
      continue;
    }

    try {
      const searchResults = await searchIOCs({ query: trimmedQuery, limit: 1 });
      if (searchResults.length > 0) {
        results.push({ query: trimmedQuery, found: true, result: searchResults[0] });
      } else {
        results.push({ query: trimmedQuery, found: false, result: null });
      }
    } catch (error) {
      results.push({ query: trimmedQuery, found: false, result: null });
    }
  }

  return results;
}

export const useIOCSearch = (params: IOCSearchParams) => {
  const { session } = useAuth();
  return useQuery({
    queryKey: ["ioc-search", params],
    queryFn: () => searchIOCs(params),
    enabled: !!session && !!params.query.trim(),
    staleTime: 5 * 60 * 1000,
  });
};

export const useBulkIOCLookup = () => {
  const { session } = useAuth();

  return useMutation({
    mutationFn: (queries: string[]) => {
      if (!session) throw new Error("Not authenticated");
      return bulkLookupIOCs(queries);
    },
  });
};

export { getIOCType };
