import { useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "./useAuth";

export interface VulnerabilityQueryParams {
  limit: number;
  cursor?: string | null;
  dateFrom?: Date;
  dateTo?: Date;
  search?: string;
}

export interface VulnerabilityLabel {
  id: string;
  value: string;
  color: string;
}

export interface Vulnerability {
  id: string;
  cve: string;
  description: string;
  severity: string;
  created: string;
  modified: string;
  confidence: number;
  labels: VulnerabilityLabel[];
  cvssScore: number | null;
  cisaKev: boolean;
  epssScore: number | null;
}

export interface PageInfo {
  hasNextPage: boolean;
  endCursor: string;
  globalCount: number;
}

// Create intel schema client
const intelDb = supabase.schema("intel");

// Get severity color
export function getSeverityColor(severity: string): string {
  const s = severity?.toLowerCase() || "";
  if (s === "critical") return "bg-red-500/20 text-red-400 border-red-500/30";
  if (s === "high") return "bg-orange-500/20 text-orange-400 border-orange-500/30";
  if (s === "medium") return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
  if (s === "low") return "bg-blue-500/20 text-blue-400 border-blue-500/30";
  return "bg-muted text-muted-foreground";
}

// Transform intel.object_current data to Vulnerability format
function transformVulnerability(row: any): Vulnerability {
  const data = row.data || {};

  // Extract severity from CVSS or labels
  let severity = "unknown";
  if (data.x_opencti_cvss_base_severity) {
    severity = data.x_opencti_cvss_base_severity;
  } else if (data.x_opencti_base_severity) {
    severity = data.x_opencti_base_severity;
  }

  return {
    id: row.internal_id,
    cve: row.name || data.name || "Unknown",
    description: data.description || "",
    severity,
    created: row.source_created_at || data.created || "",
    modified: row.source_updated_at || data.modified || "",
    confidence: data.confidence || 0,
    labels: (data.labels || []).map((l: any, index: number) => ({
      id: `label-${index}`,
      value: typeof l === "string" ? l : l.value || l,
      color: typeof l === "object" ? l.color || "#666666" : "#666666",
    })),
    cvssScore: data.x_opencti_cvss_base_score || null,
    cisaKev: data.x_opencti_cisa_kev || false,
    epssScore: data.x_opencti_epss_score || null,
  };
}

// Fetch vulnerabilities list from intel schema
async function fetchVulnerabilities(
  limit: number,
  cursor: string | null,
  search?: string,
  dateFrom?: Date,
  dateTo?: Date
): Promise<{ data: Vulnerability[]; pageInfo: PageInfo }> {
  const offset = cursor ? parseInt(cursor, 10) : 0;

  let query = intelDb
    .from("object_current")
    .select("internal_id, name, data, source_created_at, source_updated_at", { count: "exact" })
    .eq("entity_type", "Vulnerability")
    .order("source_updated_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (search) {
    query = query.ilike("name", `%${search}%`);
  }

  if (dateFrom) {
    query = query.gte("source_created_at", dateFrom.toISOString());
  }

  if (dateTo) {
    const endOfDay = new Date(dateTo);
    endOfDay.setHours(23, 59, 59, 999);
    query = query.lte("source_created_at", endOfDay.toISOString());
  }

  const { data, error, count } = await query;

  if (error) throw error;

  const vulnerabilities = (data || []).map(transformVulnerability);
  const hasNextPage = offset + limit < (count || 0);

  return {
    data: vulnerabilities,
    pageInfo: {
      hasNextPage,
      endCursor: hasNextPage ? String(offset + limit) : "",
      globalCount: count || 0,
    },
  };
}

export const useVulnerabilities = (initialLimit: number = 50) => {
  const { session } = useAuth();
  const [params, setParams] = useState<VulnerabilityQueryParams>({ limit: initialLimit });
  const [cursorHistory, setCursorHistory] = useState<(string | null)[]>([null]);
  const [currentPage, setCurrentPage] = useState(1);
  const [searchTrigger, setSearchTrigger] = useState(0);

  const query = useQuery({
    queryKey: ["vulnerabilities", params, searchTrigger],
    queryFn: () =>
      fetchVulnerabilities(params.limit, params.cursor || null, params.search, params.dateFrom, params.dateTo),
    enabled: !!session,
  });

  const search = useCallback((newParams: Partial<VulnerabilityQueryParams>) => {
    setParams((prev) => ({ ...prev, ...newParams, cursor: null }));
    setCursorHistory([null]);
    setCurrentPage(1);
    setSearchTrigger((t) => t + 1);
  }, []);

  const nextPage = useCallback(() => {
    if (query.data?.pageInfo?.hasNextPage && query.data.pageInfo.endCursor) {
      const newCursor = query.data.pageInfo.endCursor;
      setCursorHistory((prev) => [...prev, newCursor]);
      setParams((prev) => ({ ...prev, cursor: newCursor }));
      setCurrentPage((p) => p + 1);
    }
  }, [query.data?.pageInfo]);

  const previousPage = useCallback(() => {
    if (cursorHistory.length > 1) {
      const newHistory = cursorHistory.slice(0, -1);
      setCursorHistory(newHistory);
      setParams((prev) => ({ ...prev, cursor: newHistory[newHistory.length - 1] }));
      setCurrentPage((p) => p - 1);
    }
  }, [cursorHistory]);

  return {
    data: query.data?.data || [],
    pageInfo: query.data?.pageInfo,
    isLoading: query.isLoading,
    isFetching: query.isFetching,
    error: query.error,
    refetch: query.refetch,
    search,
    nextPage,
    previousPage,
    params,
    currentPage,
    hasPreviousPage: cursorHistory.length > 1,
  };
};

// Hook for fetching a single vulnerability detail
export interface VulnerabilityDetail {
  id: string;
  cve: string;
  description: string;
  created: string;
  modified: string;
  confidence: number;
  cvss: {
    vectorString: string | null;
    baseScore: number | null;
    baseSeverity: string | null;
    attackVector: string | null;
    attackComplexity: string | null;
    privilegesRequired: string | null;
    userInteraction: string | null;
    scope: string | null;
    confidentialityImpact: string | null;
    integrityImpact: string | null;
    availabilityImpact: string | null;
  };
  cisaKev: boolean;
  epssScore: number | null;
  epssPercentile: number | null;
  source: string;
  labels: { value: string; color: string }[];
  externalReferences: {
    id: string;
    sourceName: string;
    description: string | null;
    url: string;
  }[];
  // Related entities
  relatedThreatActors: { id: string; name: string }[];
  relatedMalware: { id: string; name: string }[];
  relatedTools: { id: string; name: string }[];
  mitigations: { id: string; name: string; description: string }[];
}

async function fetchVulnerabilityDetail(id: string): Promise<VulnerabilityDetail | null> {
  const { data: vulnData, error: vulnError } = await intelDb
    .from("object_current")
    .select("internal_id, name, data, source_created_at, source_updated_at")
    .eq("internal_id", id)
    .single();

  if (vulnError) {
    if (vulnError.code === "PGRST116") return null;
    throw vulnError;
  }

  const data = vulnData.data || {};

  // Extract CVSS data
  const cvss = {
    vectorString: data.x_opencti_cvss_vector || null,
    baseScore: data.x_opencti_cvss_base_score || null,
    baseSeverity: data.x_opencti_cvss_base_severity || null,
    attackVector: data.x_opencti_cvss_attack_vector || null,
    attackComplexity: data.x_opencti_cvss_attack_complexity || null,
    privilegesRequired: data.x_opencti_cvss_privileges_required || null,
    userInteraction: data.x_opencti_cvss_user_interaction || null,
    scope: data.x_opencti_cvss_scope || null,
    confidentialityImpact: data.x_opencti_cvss_confidentiality_impact || null,
    integrityImpact: data.x_opencti_cvss_integrity_impact || null,
    availabilityImpact: data.x_opencti_cvss_availability_impact || null,
  };

  // Extract external references
  const externalReferences = (data.external_references || []).map((ref: any, index: number) => ({
    id: ref.external_id || `ref-${index}`,
    sourceName: ref.source_name || "",
    description: ref.description || null,
    url: ref.url || "",
  }));

  // Fetch incoming relationships (who exploits/targets this vulnerability)
  const { data: incomingRels } = await intelDb
    .from("relationship_current")
    .select("source_id, relationship_type")
    .eq("target_id", id)
    .in("relationship_type", ["exploits", "targets"]);

  // Fetch outgoing relationships (mitigations)
  const { data: outgoingRels } = await intelDb
    .from("relationship_current")
    .select("target_id, relationship_type")
    .eq("source_id", id)
    .eq("relationship_type", "has");

  // Collect all related entity IDs
  const relatedIds = new Set<string>();
  (incomingRels || []).forEach((r: any) => relatedIds.add(r.source_id));
  (outgoingRels || []).forEach((r: any) => relatedIds.add(r.target_id));

  // Fetch all related entities
  let relatedEntities: any[] = [];
  if (relatedIds.size > 0) {
    const { data: entities } = await intelDb
      .from("object_current")
      .select("internal_id, name, entity_type, data")
      .in("internal_id", Array.from(relatedIds));
    relatedEntities = entities || [];
  }

  const entityMap = new Map(relatedEntities.map((e) => [e.internal_id, e]));

  // Initialize arrays
  const relatedThreatActors: { id: string; name: string }[] = [];
  const relatedMalware: { id: string; name: string }[] = [];
  const relatedTools: { id: string; name: string }[] = [];
  const mitigations: { id: string; name: string; description: string }[] = [];

  // Process incoming relationships
  for (const rel of incomingRels || []) {
    const source = entityMap.get(rel.source_id);
    if (!source) continue;

    if (source.entity_type === "Intrusion-Set") {
      relatedThreatActors.push({ id: source.internal_id, name: source.name });
    } else if (source.entity_type === "Malware") {
      relatedMalware.push({ id: source.internal_id, name: source.name });
    } else if (source.entity_type === "Tool") {
      relatedTools.push({ id: source.internal_id, name: source.name });
    }
  }

  // Process outgoing relationships for mitigations
  for (const rel of outgoingRels || []) {
    const target = entityMap.get(rel.target_id);
    if (!target) continue;

    if (target.entity_type === "Course-Of-Action") {
      const targetData = target.data || {};
      mitigations.push({
        id: target.internal_id,
        name: target.name,
        description: targetData.description || "",
      });
    }
  }

  return {
    id: vulnData.internal_id,
    cve: vulnData.name || data.name || "Unknown",
    description: data.description || "",
    created: vulnData.source_created_at || data.created || "",
    modified: vulnData.source_updated_at || data.modified || "",
    confidence: data.confidence || 0,
    cvss,
    cisaKev: data.x_opencti_cisa_kev || false,
    epssScore: data.x_opencti_epss_score || null,
    epssPercentile: data.x_opencti_epss_percentile || null,
    source: data.created_by_ref || "",
    labels: (data.labels || []).map((l: any) => ({
      value: typeof l === "string" ? l : l.value || l,
      color: typeof l === "object" ? l.color || "#666666" : "#666666",
    })),
    externalReferences,
    relatedThreatActors,
    relatedMalware,
    relatedTools,
    mitigations,
  };
}

export const useVulnerabilityDetail = (id: string) => {
  const { session } = useAuth();
  return useQuery({
    queryKey: ["vulnerability-detail", id],
    queryFn: () => fetchVulnerabilityDetail(id),
    enabled: !!id && !!session,
    retry: 2,
  });
};
