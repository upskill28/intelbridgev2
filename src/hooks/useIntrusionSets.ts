import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "./useAuth";

export interface IntrusionSet {
  id: string;
  name: string;
  description: string;
  aliases: string[];
  created: string;
  modified: string;
  firstSeen: string | null;
  lastSeen: string | null;
  resourceLevel: string | null;
  primaryMotivation: string | null;
  secondaryMotivations: string[];
  goals: string[];
  labels: { value: string; color: string }[];
  targetedCountries: { id: string; name: string }[];
  targetedSectors: { id: string; name: string }[];
}

export interface IntrusionSetDetail extends IntrusionSet {
  usedMalware: { id: string; name: string }[];
  usedTools: { id: string; name: string }[];
  usedAttackPatterns: { id: string; name: string; mitreId: string; killChainPhases?: { phaseName: string; order: number }[] }[];
  mitigatingActions: { id: string; mitreId: string; attackPatternName: string; name: string; description: string }[];
  externalReferences: { id: string; sourceName: string; url: string }[];
  relatedReports: { id: string; name: string; date: string }[];
  relatedCampaigns: { id: string; name: string }[];
  relatedIndicators: { id: string; name: string; pattern: string; observableType: string | null; score: number | null; created?: string }[];
  relatedVulnerabilities: { id: string; name: string; description: string }[];
}

export interface PageInfo {
  hasNextPage: boolean;
  endCursor: string | null;
  globalCount: number;
}

// Create intel schema client
const intelDb = supabase.schema("intel");

// Transform intel.object_current data to IntrusionSet format
function transformIntrusionSet(row: any): IntrusionSet {
  const data = row.data || {};

  return {
    id: row.internal_id,
    name: row.name || data.name || "Unknown",
    description: data.description || "",
    aliases: data.aliases || data.x_opencti_aliases || [],
    created: row.source_created_at || data.created || "",
    modified: row.source_updated_at || data.modified || "",
    firstSeen: data.first_seen || null,
    lastSeen: data.last_seen || null,
    resourceLevel: data.resource_level || null,
    primaryMotivation: data.primary_motivation || null,
    secondaryMotivations: data.secondary_motivations || [],
    goals: data.goals || [],
    labels: (data.labels || []).map((l: any) => ({
      value: typeof l === "string" ? l : l.value || l,
      color: typeof l === "object" ? l.color || "#666666" : "#666666",
    })),
    targetedCountries: [],
    targetedSectors: [],
  };
}

// Fetch intrusion sets list from intel schema
async function fetchIntrusionSets(
  limit: number,
  cursor: string | null,
  search?: string
): Promise<{ data: IntrusionSet[]; pageInfo: PageInfo }> {
  const offset = cursor ? parseInt(cursor, 10) : 0;

  let query = intelDb
    .from("object_current")
    .select("internal_id, name, data, source_created_at, source_updated_at", { count: "exact" })
    .eq("entity_type", "Intrusion-Set")
    .order("source_updated_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (search) {
    query = query.ilike("name", `%${search}%`);
  }

  const { data, error, count } = await query;

  if (error) throw error;

  const intrusionSets = (data || []).map(transformIntrusionSet);

  // Fetch targeted countries and sectors
  if (intrusionSets.length > 0) {
    const intrusionSetIds = intrusionSets.map((is) => is.id);

    const { data: targetRels } = await intelDb
      .from("relationship_current")
      .select("source_id, target_id")
      .eq("relationship_type", "targets")
      .in("source_id", intrusionSetIds);

    if (targetRels && targetRels.length > 0) {
      const targetIds = targetRels.map((r: any) => r.target_id);

      const { data: targets } = await intelDb
        .from("object_current")
        .select("internal_id, name, entity_type")
        .in("internal_id", targetIds);

      const targetMap = new Map(targets?.map((t: any) => [t.internal_id, t]) || []);

      for (const is of intrusionSets) {
        const isRels = targetRels.filter((r: any) => r.source_id === is.id);
        for (const rel of isRels) {
          const target = targetMap.get(rel.target_id);
          if (target) {
            if (target.entity_type === "Country") {
              is.targetedCountries.push({ id: target.internal_id, name: target.name });
            } else if (target.entity_type === "Sector") {
              is.targetedSectors.push({ id: target.internal_id, name: target.name });
            }
          }
        }
      }
    }
  }

  const hasNextPage = offset + limit < (count || 0);

  return {
    data: intrusionSets,
    pageInfo: {
      hasNextPage,
      endCursor: hasNextPage ? String(offset + limit) : null,
      globalCount: count || 0,
    },
  };
}

// Fetch single intrusion set detail
async function fetchIntrusionSetDetail(id: string): Promise<IntrusionSetDetail | null> {
  const { data: isData, error: isError } = await intelDb
    .from("object_current")
    .select("internal_id, name, data, source_created_at, source_updated_at")
    .eq("internal_id", id)
    .single();

  if (isError) {
    if (isError.code === "PGRST116") return null;
    throw isError;
  }

  const base = transformIntrusionSet(isData);
  const data = isData.data || {};

  // Fetch outgoing relationships
  const { data: outgoingRels } = await intelDb
    .from("relationship_current")
    .select("target_id, relationship_type")
    .eq("source_id", id);

  // Fetch incoming relationships
  const { data: incomingRels } = await intelDb
    .from("relationship_current")
    .select("source_id, relationship_type")
    .eq("target_id", id);

  // Collect all related entity IDs
  const relatedIds = new Set<string>();
  (outgoingRels || []).forEach((r: any) => relatedIds.add(r.target_id));
  (incomingRels || []).forEach((r: any) => relatedIds.add(r.source_id));

  // Fetch all related entities
  let relatedEntities: any[] = [];
  if (relatedIds.size > 0) {
    const { data: entities } = await intelDb
      .from("object_current")
      .select("internal_id, name, entity_type, data, source_created_at")
      .in("internal_id", Array.from(relatedIds));
    relatedEntities = entities || [];
  }

  // Fetch reports via object-ref relationships
  const { data: reportRels } = await intelDb
    .from("relationship_current")
    .select("data")
    .eq("relationship_type", "object-ref")
    .contains("data", { to: { id: id } });

  if (reportRels && reportRels.length > 0) {
    const reportIds = reportRels.map((r: any) => r.data?.from?.id).filter(Boolean);
    if (reportIds.length > 0) {
      const { data: reports } = await intelDb
        .from("object_current")
        .select("internal_id, name, data, source_created_at")
        .eq("entity_type", "Report")
        .in("internal_id", reportIds);

      for (const report of reports || []) {
        if (!relatedEntities.find((e) => e.internal_id === report.internal_id)) {
          relatedEntities.push({ ...report, entity_type: "Report" });
        }
      }
    }
  }

  const entityMap = new Map(relatedEntities.map((e) => [e.internal_id, e]));

  // Initialize arrays
  const targetedCountries: { id: string; name: string }[] = [];
  const targetedSectors: { id: string; name: string }[] = [];
  const usedMalware: { id: string; name: string }[] = [];
  const usedTools: { id: string; name: string }[] = [];
  const usedAttackPatterns: { id: string; name: string; mitreId: string; killChainPhases?: { phaseName: string; order: number }[] }[] = [];
  const relatedReports: { id: string; name: string; date: string }[] = [];
  const relatedCampaigns: { id: string; name: string }[] = [];
  const relatedIndicators: { id: string; name: string; pattern: string; observableType: string | null; score: number | null; created?: string }[] = [];
  const relatedVulnerabilities: { id: string; name: string; description: string }[] = [];

  // Process outgoing relationships
  for (const rel of outgoingRels || []) {
    const target = entityMap.get(rel.target_id);
    if (!target) continue;
    const targetData = target.data || {};

    switch (rel.relationship_type) {
      case "targets":
        if (target.entity_type === "Country") {
          targetedCountries.push({ id: target.internal_id, name: target.name });
        } else if (target.entity_type === "Sector") {
          targetedSectors.push({ id: target.internal_id, name: target.name });
        } else if (target.entity_type === "Vulnerability") {
          if (!relatedVulnerabilities.find((v) => v.id === target.internal_id)) {
            relatedVulnerabilities.push({ id: target.internal_id, name: target.name, description: targetData.description || "" });
          }
        }
        break;
      case "uses":
        if (target.entity_type === "Malware") {
          usedMalware.push({ id: target.internal_id, name: target.name });
        } else if (target.entity_type === "Tool") {
          usedTools.push({ id: target.internal_id, name: target.name });
        } else if (target.entity_type === "Attack-Pattern") {
          usedAttackPatterns.push({
            id: target.internal_id,
            name: target.name,
            mitreId: targetData.x_mitre_id || "",
            killChainPhases: (targetData.kill_chain_phases || []).map((p: any) => ({
              phaseName: p.phase_name || p.phaseName || "",
              order: p.x_opencti_order || p.order || 0,
            })),
          });
        }
        break;
      case "exploits":
        if (target.entity_type === "Vulnerability") {
          if (!relatedVulnerabilities.find((v) => v.id === target.internal_id)) {
            relatedVulnerabilities.push({ id: target.internal_id, name: target.name, description: targetData.description || "" });
          }
        }
        break;
    }
  }

  // Process incoming relationships
  for (const rel of incomingRels || []) {
    const source = entityMap.get(rel.source_id);
    if (!source) continue;
    const sourceData = source.data || {};

    switch (rel.relationship_type) {
      case "indicates":
        if (source.entity_type === "Indicator") {
          relatedIndicators.push({
            id: source.internal_id,
            name: source.name,
            pattern: sourceData.pattern || "",
            observableType: sourceData.x_opencti_main_observable_type || null,
            score: sourceData.x_opencti_score || null,
            created: sourceData.created || source.source_created_at || "",
          });
        }
        break;
      case "attributed-to":
        if (source.entity_type === "Campaign") {
          relatedCampaigns.push({ id: source.internal_id, name: source.name });
        }
        break;
    }
  }

  // Add reports from object-ref query
  for (const entity of relatedEntities) {
    if (entity.entity_type === "Report") {
      const reportData = entity.data || {};
      if (!relatedReports.find((r) => r.id === entity.internal_id)) {
        relatedReports.push({
          id: entity.internal_id,
          name: entity.name,
          date: reportData.published || reportData.created || "",
        });
      }
    }
  }

  // Extract external references from data
  const externalReferences = (data.external_references || []).map((ref: any, index: number) => ({
    id: ref.external_id || `ref-${index}`,
    sourceName: ref.source_name || "",
    url: ref.url || "",
  }));

  // Fetch mitigating actions
  const mitigatingActions: { id: string; mitreId: string; attackPatternName: string; name: string; description: string }[] = [];

  if (usedAttackPatterns.length > 0) {
    const attackPatternIds = usedAttackPatterns.map((ap) => ap.id);

    const { data: mitigationRels } = await intelDb
      .from("relationship_current")
      .select("source_id, target_id")
      .eq("relationship_type", "mitigates")
      .in("target_id", attackPatternIds);

    if (mitigationRels && mitigationRels.length > 0) {
      const coaIds = mitigationRels.map((r: any) => r.source_id);

      const { data: coas } = await intelDb
        .from("object_current")
        .select("internal_id, name, data")
        .in("internal_id", coaIds);

      const coaMap = new Map(coas?.map((c: any) => [c.internal_id, c]) || []);
      const apMap = new Map(usedAttackPatterns.map((ap) => [ap.id, ap]));

      for (const rel of mitigationRels) {
        const coa = coaMap.get(rel.source_id);
        const ap = apMap.get(rel.target_id);
        if (coa && ap) {
          const coaData = coa.data || {};
          mitigatingActions.push({
            id: coa.internal_id,
            mitreId: coaData.x_mitre_id || "",
            attackPatternName: ap.name,
            name: coa.name,
            description: coaData.description || "",
          });
        }
      }
    }
  }

  return {
    ...base,
    targetedCountries,
    targetedSectors,
    usedMalware,
    usedTools,
    usedAttackPatterns,
    mitigatingActions,
    externalReferences,
    relatedReports,
    relatedCampaigns,
    relatedIndicators,
    relatedVulnerabilities,
  };
}

export const useIntrusionSets = (limit = 25, cursor?: string | null, search?: string) => {
  const { session } = useAuth();
  return useQuery({
    queryKey: ["intrusion-sets", limit, cursor, search],
    queryFn: () => fetchIntrusionSets(limit, cursor || null, search),
    staleTime: 5 * 60 * 1000,
    enabled: !!session,
  });
};

export const useIntrusionSetDetail = (id: string) => {
  const { session } = useAuth();
  return useQuery({
    queryKey: ["intrusion-set-detail", id],
    queryFn: () => fetchIntrusionSetDetail(id),
    enabled: !!id && !!session,
  });
};
