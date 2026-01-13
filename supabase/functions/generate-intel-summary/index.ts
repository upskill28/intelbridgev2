import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { createClient } from "npm:@supabase/supabase-js@2.57.2";
import OpenAI from "npm:openai@4.70.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface MediaSummary {
  title: string;
  summary: string;
  sourceUrl: string;
  date: string;
  reportId: string;
  // Entity mentions extracted from object-ref relationships
  threatActors: string[];
  geographies: string[];
  sectors: string[];
  cves: string[];
  ttps: string[]; // Attack pattern IDs
  // Detailed entity data for aggregation
  sectorDetails?: Array<{ id: string; name: string }>;
  geographyDetails?: Array<{ id: string; name: string; entityType: string }>;
}

interface ThreatSummary {
  title: string;
  summary: string;
  sourceUrl: string;
  date: string;
  reportId: string;
  threatActor: string | null;
  severity: string;
  ttps: string[]; // Attack pattern IDs
  cves: string[]; // Vulnerabilities mentioned
  // Detailed entity data for aggregation
  sectorDetails?: Array<{ id: string; name: string }>;
  geographyDetails?: Array<{ id: string; name: string; entityType: string }>;
}

interface AdvisorySummary {
  title: string;
  summary: string;
  sourceUrl: string;
  date: string;
  reportId: string;
  severity: string;
  source: string;
  ttps: string[]; // Attack pattern IDs
  cves: string[]; // Vulnerabilities mentioned
  // Detailed entity data for aggregation
  sectorDetails?: Array<{ id: string; name: string }>;
  geographyDetails?: Array<{ id: string; name: string; entityType: string }>;
}

interface RansomwareActivity {
  actor: string;
  actorId?: string;
  victimCount: number;
  victims: string[];
}

interface TTPObserved {
  id: string;
  name: string;
  mitreId: string;
  source: 'observed' | 'inferred';
  evidenceIds: string[];
}

interface ActiveActor {
  id: string;
  name: string;
  linkPath: string;
  source: 'report' | 'ransomware' | 'advisory';
}

interface KeyRisk {
  risk: string;
  evidence: Array<{ type: string; id: string; name: string; linkPath: string }>;
}

interface RecommendedAction {
  action: string;
  confidence: 'HIGH' | 'MED';
  why: string;
  score: number;
  evidence: Array<{ type: string; id: string; name: string; linkPath: string }>;
  mitigates: Array<{ ttpId: string; ttpName: string; mitreId?: string }>;
}

interface ThreatPosture {
  level: 'Elevated' | 'Moderate' | 'Low';
  rationale: string;
}

interface TargetingMention {
  id: string;
  name: string;
  entityType: string; // 'Sector', 'Country', 'Region', 'City'
  count: number;
  confidence: 'HIGH' | 'MED'; // HIGH = directly extracted, MED = inferred
  evidence: Array<{
    type: string; // 'media-report', 'threat-report', 'advisory'
    id: string;
    name: string;
    linkPath: string;
    date: string;
  }>;
}

interface TargetingData {
  sectors: TargetingMention[];
  geographies: TargetingMention[];
}

// Report relevance scoring for intelligent selection
interface ReportRelevanceScore {
  reportId: string;
  score: number;
  factors: {
    recency: number;
    severity: number;
    entityRichness: number;
  };
}

// Calculate relevance score for a report (0-1 scale)
function calculateRelevanceScore(report: {
  date: string;
  description?: string;
  data?: any;
}): ReportRelevanceScore {
  const factors = {
    recency: 0,
    severity: 0,
    entityRichness: 0,
  };

  // Recency score: More recent = higher score
  const reportDate = new Date(report.date);
  const hoursOld = (Date.now() - reportDate.getTime()) / (1000 * 60 * 60);
  if (hoursOld <= 6) factors.recency = 1.0;
  else if (hoursOld <= 12) factors.recency = 0.8;
  else if (hoursOld <= 18) factors.recency = 0.6;
  else factors.recency = 0.4;

  // Severity score based on data content
  const data = report.data || {};
  const description = (report.description || data.description || '').toLowerCase();
  const name = (data.name || '').toLowerCase();

  // Check for severity indicators
  if (description.includes('critical') || name.includes('critical')) {
    factors.severity = 1.0;
  } else if (description.includes('high') || description.includes('urgent') ||
             description.includes('actively exploited')) {
    factors.severity = 0.8;
  } else if (description.includes('medium') || description.includes('moderate')) {
    factors.severity = 0.5;
  } else {
    factors.severity = 0.3;
  }

  // Entity richness: Reports with more entity mentions are more valuable
  let entityCount = 0;
  const objectRefs = data.objectMarkingRefs?.edges || data.objects?.edges || [];
  entityCount += objectRefs.length;

  // Check for CVE mentions
  const cveMatches = description.match(/CVE-\d{4}-\d+/gi) || [];
  entityCount += cveMatches.length * 2; // CVEs are highly valuable

  // Check for threat actor mentions
  if (description.includes('apt') || description.includes('threat actor') ||
      description.includes('campaign')) {
    entityCount += 3;
  }

  factors.entityRichness = Math.min(entityCount / 10, 1.0);

  // Weighted score calculation
  const score = (factors.recency * 0.3) + (factors.severity * 0.4) + (factors.entityRichness * 0.3);

  return {
    reportId: report.data?.internal_id || '',
    score,
    factors,
  };
}

// Calculate dynamic limit based on total volume
function getDynamicLimit(totalCount: number, baseLimit: number = 75): number {
  if (totalCount <= 30) return totalCount; // Process all for low volume
  if (totalCount <= 100) return Math.min(50, baseLimit); // Medium volume
  return Math.min(30, baseLimit); // High volume - be more selective
}

// Select top reports by relevance score
function selectTopReports<T extends { date: string; data?: any; description?: string }>(
  reports: T[],
  maxCount: number,
  alwaysIncludeCritical: boolean = true
): T[] {
  // Score all reports
  const scored = reports.map(r => ({
    report: r,
    relevance: calculateRelevanceScore(r),
  }));

  // Always include critical severity reports
  const critical: T[] = [];
  const others: typeof scored = [];

  if (alwaysIncludeCritical) {
    for (const item of scored) {
      const desc = (item.report.description || item.report.data?.description || '').toLowerCase();
      if (desc.includes('critical') || item.relevance.factors.severity >= 0.9) {
        critical.push(item.report);
      } else {
        others.push(item);
      }
    }
  } else {
    others.push(...scored);
  }

  // Sort remaining by score and take top N
  others.sort((a, b) => b.relevance.score - a.relevance.score);
  const remainingSlots = maxCount - critical.length;
  const selected = [...critical, ...others.slice(0, Math.max(0, remainingSlots)).map(o => o.report)];

  return selected;
}

// Stage timing tracker for performance monitoring
interface StageTiming {
  stage: string;
  startTime: number;
  endTime?: number;
  durationMs?: number;
}

class GenerationTimer {
  private timings: StageTiming[] = [];
  private currentStage?: StageTiming;

  startStage(stage: string): void {
    if (this.currentStage) {
      this.endStage();
    }
    this.currentStage = { stage, startTime: Date.now() };
    log(`Stage started: ${stage}`);
  }

  endStage(): void {
    if (this.currentStage) {
      this.currentStage.endTime = Date.now();
      this.currentStage.durationMs = this.currentStage.endTime - this.currentStage.startTime;
      this.timings.push(this.currentStage);
      log(`Stage completed: ${this.currentStage.stage}`, { durationMs: this.currentStage.durationMs });
      this.currentStage = undefined;
    }
  }

  getTimings(): Record<string, number> {
    this.endStage(); // Ensure last stage is recorded
    return Object.fromEntries(
      this.timings.map(t => [t.stage, t.durationMs || 0])
    );
  }

  getTotalTime(): number {
    return this.timings.reduce((sum, t) => sum + (t.durationMs || 0), 0);
  }
}

const log = (step: string, details?: unknown) => {
  console.log(`[INTEL-SUMMARY] ${step}`, details ? JSON.stringify(details) : "");
};

// === GENERATION STAGES (for progress tracking) ===
const GENERATION_STAGES = [
  'initializing',
  'fetching_reports',
  'media_agent',
  'threat_agent',
  'advisory_agent',
  'entity_aggregation',
  'comprehensive_analysis',
  'saving_results',
  'completed',
] as const;

type GenerationStage = typeof GENERATION_STAGES[number];

// Progress tracking functions
async function initializeProgress(
  supabaseUrl: string,
  serviceKey: string,
  summaryId: string
): Promise<void> {
  try {
    const response = await fetch(`${supabaseUrl}/rest/v1/intel_summary_generation_progress`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${serviceKey}`,
        "apikey": serviceKey,
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates",
      },
      body: JSON.stringify({
        summary_id: summaryId,
        started_at: new Date().toISOString(),
        current_stage: 'initializing',
        stages_completed: [],
        estimated_completion: new Date(Date.now() + 120000).toISOString(), // Estimate 2 minutes
      }),
    });
    if (!response.ok) {
      log("Progress init error", { status: response.status });
    }
  } catch (error) {
    log("Progress init failed", { error: String(error) });
  }
}

async function updateProgress(
  supabaseUrl: string,
  serviceKey: string,
  summaryId: string,
  stage: GenerationStage,
  completedStages: string[] = [],
  error?: string
): Promise<void> {
  try {
    const updateData: any = {
      current_stage: stage,
      stages_completed: completedStages,
    };
    if (error) {
      updateData.error = error;
    }
    // Update estimated completion based on progress
    const stageIndex = GENERATION_STAGES.indexOf(stage);
    const progressPercent = stageIndex / GENERATION_STAGES.length;
    const remainingMs = (1 - progressPercent) * 90000; // Estimate 90 seconds total
    updateData.estimated_completion = new Date(Date.now() + remainingMs).toISOString();

    const response = await fetch(
      `${supabaseUrl}/rest/v1/intel_summary_generation_progress?summary_id=eq.${summaryId}`,
      {
        method: "PATCH",
        headers: {
          "Authorization": `Bearer ${serviceKey}`,
          "apikey": serviceKey,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(updateData),
      }
    );
    if (!response.ok) {
      log("Progress update error", { status: response.status, stage });
    }
  } catch (error) {
    log("Progress update failed", { error: String(error), stage });
  }
}

async function cleanupProgress(
  supabaseUrl: string,
  serviceKey: string,
  summaryId: string
): Promise<void> {
  try {
    await fetch(
      `${supabaseUrl}/rest/v1/intel_summary_generation_progress?summary_id=eq.${summaryId}`,
      {
        method: "DELETE",
        headers: {
          "Authorization": `Bearer ${serviceKey}`,
          "apikey": serviceKey,
        },
      }
    );
  } catch (error) {
    log("Progress cleanup failed", { error: String(error) });
  }
}

// === METRICS COLLECTION (Phase 6) ===
interface GenerationMetrics {
  summaryId: string;
  stageTimings: Record<string, number>;
  tokenBreakdown?: {
    mediaAgent?: number;
    threatAgent?: number;
    advisoryAgent?: number;
    comprehensiveAnalysis?: number;
    total: number;
  };
  reportsStats: {
    mediaFetched: number;
    threatsFetched: number;
    advisoriesFetched: number;
    ransomwareVictims: number;
    mediaProcessed: number;
    threatsProcessed: number;
    advisoriesProcessed: number;
  };
  cacheStats: {
    cacheHits: number;
    cacheMisses: number;
    entriesWritten: number;
  };
}

// Track cache statistics
let cacheHits = 0;
let cacheMisses = 0;

async function saveMetrics(
  supabaseUrl: string,
  serviceKey: string,
  metrics: GenerationMetrics
): Promise<void> {
  try {
    const response = await fetch(`${supabaseUrl}/rest/v1/intel_summary_metrics`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${serviceKey}`,
        "apikey": serviceKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        summary_id: metrics.summaryId,
        stage_timings: metrics.stageTimings,
        token_breakdown: metrics.tokenBreakdown,
        reports_stats: metrics.reportsStats,
        cache_stats: metrics.cacheStats,
      }),
    });
    if (!response.ok) {
      log("Metrics save error", { status: response.status });
    } else {
      log("Metrics saved successfully");
    }
  } catch (error) {
    log("Metrics save failed", { error: String(error) });
  }
}

// Query intel schema directly via PostgREST
async function queryIntelSchema(
  supabaseUrl: string,
  serviceKey: string,
  table: string,
  query: string
): Promise<unknown[]> {
  const url = `${supabaseUrl}/rest/v1/${table}?${query}`;
  const response = await fetch(url, {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${serviceKey}`,
      "apikey": serviceKey,
      "Accept-Profile": "intel",
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Intel query error: ${response.status} - ${errorText}`);
  }

  return response.json();
}

// Fetch reports from intel schema by report type
async function fetchReportsByType(
  supabaseUrl: string,
  serviceKey: string,
  reportType: string,
  limit: number,
  since: string
): Promise<Array<{ id: string; name: string; description: string; date: string; externalReferences?: Array<{ url: string }>; data?: any }>> {
  // Use data->report_types (JSONB) with cs. operator, not data->>report_types (text)
  const query = `select=internal_id,name,data,source_created_at&entity_type=eq.Report&data->report_types=cs.["${reportType}"]&source_created_at=gte.${since}&order=source_created_at.desc&limit=${limit}`;

  const rows = await queryIntelSchema(supabaseUrl, serviceKey, "object_current", query) as any[];

  return rows.map(row => {
    const data = row.data || {};

    // Extract external references from GraphQL edges/node structure
    const edges = data.externalReferences?.edges || [];
    const externalRefs = edges.map((edge: any) => ({
      url: edge.node?.url || '',
      sourceName: edge.node?.source_name || '',
    }));

    // Log the first report's external references for debugging
    if (rows.indexOf(row) === 0) {
      log("First report external_references", {
        name: row.name?.substring(0, 50),
        hasEdges: !!data.externalReferences?.edges,
        edgesCount: edges.length,
        firstUrl: externalRefs[0]?.url || 'none'
      });
    }

    return {
      id: row.internal_id,
      name: row.name || data.name || 'Unknown',
      description: data.description || '',
      date: data.published || row.source_created_at || '',
      source: data.createdBy?.name || '',
      externalReferences: externalRefs,
      data: data, // Include raw data for entity extraction
    };
  });
}

// Fetch entity mentions for a report via multiple methods:
// 1. object-ref relationships in relationship_current table
// 2. Embedded objectRefs/objects in the report data (OpenCTI GraphQL structure)
// 3. Direct entity relationships (targets, uses, etc.)
// Entity cache result type
interface CachedEntityMentions {
  threatActors: Array<{ id: string; name: string }>;
  geographies: Array<{ id: string; name: string; entityType: string }>;
  sectors: Array<{ id: string; name: string }>;
  cves: string[];
  ttps: Array<{ id: string; name: string; mitreId: string }>;
}

// Cache for batch writes
const entityCacheBuffer: Map<string, CachedEntityMentions> = new Map();

// Check entity cache for a report
async function checkEntityCache(
  supabaseUrl: string,
  serviceKey: string,
  reportId: string
): Promise<CachedEntityMentions | null> {
  try {
    const response = await fetch(
      `${supabaseUrl}/rest/v1/report_entity_cache?report_id=eq.${reportId}&select=*`,
      {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${serviceKey}`,
          "apikey": serviceKey,
          "Content-Type": "application/json",
        },
      }
    );

    if (!response.ok) {
      cacheMisses++;
      return null;
    }

    const data = await response.json();
    if (!data || data.length === 0) {
      cacheMisses++;
      return null;
    }

    const cached = data[0];
    // Check if cache is fresh (24 hours)
    const extractedAt = new Date(cached.extracted_at);
    const hoursSinceExtraction = (Date.now() - extractedAt.getTime()) / (1000 * 60 * 60);
    if (hoursSinceExtraction > 24) {
      cacheMisses++;
      return null;
    }

    cacheHits++;
    return {
      threatActors: cached.threat_actors || [],
      geographies: cached.geographies || [],
      sectors: cached.sectors || [],
      cves: cached.cves || [],
      ttps: cached.ttps || [],
    };
  } catch (error) {
    cacheMisses++;
    log("Cache check error", { reportId, error: String(error) });
    return null;
  }
}

// Batch write cache entries
async function flushEntityCache(
  supabaseUrl: string,
  serviceKey: string
): Promise<void> {
  if (entityCacheBuffer.size === 0) return;

  const entries = Array.from(entityCacheBuffer.entries()).map(([reportId, data]) => ({
    report_id: reportId,
    threat_actors: data.threatActors,
    geographies: data.geographies,
    sectors: data.sectors,
    cves: data.cves,
    ttps: data.ttps,
    extracted_at: new Date().toISOString(),
    cache_version: 1,
  }));

  try {
    const response = await fetch(
      `${supabaseUrl}/rest/v1/report_entity_cache`,
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${serviceKey}`,
          "apikey": serviceKey,
          "Content-Type": "application/json",
          "Prefer": "resolution=merge-duplicates",
        },
        body: JSON.stringify(entries),
      }
    );

    if (response.ok) {
      log("Entity cache flushed", { entriesWritten: entries.length });
      entityCacheBuffer.clear();
    } else {
      log("Entity cache flush error", { status: response.status });
    }
  } catch (error) {
    log("Entity cache flush error", { error: String(error) });
  }
}

async function fetchReportEntityMentions(
  supabaseUrl: string,
  serviceKey: string,
  reportId: string,
  reportData?: any, // Optional: pass the report data to extract embedded refs
  useCache: boolean = true // Enable/disable caching
): Promise<CachedEntityMentions> {
  // Check cache first
  if (useCache) {
    const cached = await checkEntityCache(supabaseUrl, serviceKey, reportId);
    if (cached) {
      log("Entity cache hit", { reportId: reportId.substring(0, 20) });
      return cached;
    }
  }

  const result: CachedEntityMentions = {
    threatActors: [],
    geographies: [],
    sectors: [],
    cves: [],
    ttps: [],
  };

  const allEntityIds: string[] = [];

  try {
    // Method 1: Fetch object-ref relationships FROM this report
    const relQuery = `select=target_id&relationship_type=eq.object-ref&source_id=eq.${reportId}`;
    const relationships = await queryIntelSchema(supabaseUrl, serviceKey, "relationship_current", relQuery) as any[];

    if (relationships && relationships.length > 0) {
      const ids = relationships.map((r: any) => r.target_id).filter(Boolean);
      allEntityIds.push(...ids);
    }

    // Method 2: Check for other relationship types (targets, uses, indicates, etc.)
    const otherRelQuery = `select=target_id,relationship_type&source_id=eq.${reportId}&relationship_type=in.(targets,uses,indicates,attributed-to,related-to)`;
    const otherRels = await queryIntelSchema(supabaseUrl, serviceKey, "relationship_current", otherRelQuery) as any[];

    if (otherRels && otherRels.length > 0) {
      const ids = otherRels.map((r: any) => r.target_id).filter(Boolean);
      allEntityIds.push(...ids);
    }

    // Method 3: Extract from embedded objectRefs in report data (OpenCTI GraphQL structure)
    if (reportData) {
      // Log available keys in report data for debugging
      const dataKeys = Object.keys(reportData);
      log("Report data keys", { reportId: reportId.substring(0, 20), keys: dataKeys.slice(0, 20) });

      // Check for objects/objectRefs embedded in the report data
      const extractEmbeddedIds = (data: any): string[] => {
        const ids: string[] = [];

        // OpenCTI often stores related entities in edges/node structure
        const checkEdges = (edges: any[], source: string) => {
          if (Array.isArray(edges)) {
            for (const edge of edges) {
              if (edge?.node?.id) {
                ids.push(edge.node.id);
                log("Found embedded entity", { source, id: edge.node.id.substring(0, 30), name: edge.node.name?.substring(0, 30) });
              }
              if (edge?.node?.standard_id) ids.push(edge.node.standard_id);
              // Also check internal_id
              if (edge?.node?.internal_id) ids.push(edge.node.internal_id);
            }
          }
        };

        // Check various possible locations
        if (data?.objects?.edges) checkEdges(data.objects.edges, 'objects');
        if (data?.objectRefs?.edges) checkEdges(data.objectRefs.edges, 'objectRefs');
        if (data?.objectMarking?.edges) checkEdges(data.objectMarking.edges, 'objectMarking');

        // Direct arrays
        if (Array.isArray(data?.object_refs)) {
          ids.push(...data.object_refs.filter(Boolean));
          log("Found object_refs array", { count: data.object_refs.length });
        }

        // Check for intrusion sets, threat actors directly
        if (data?.intrusionSets?.edges) checkEdges(data.intrusionSets.edges, 'intrusionSets');
        if (data?.threatActors?.edges) checkEdges(data.threatActors.edges, 'threatActors');
        if (data?.indicators?.edges) checkEdges(data.indicators.edges, 'indicators');
        if (data?.attackPatterns?.edges) checkEdges(data.attackPatterns.edges, 'attackPatterns');
        if (data?.sectors?.edges) checkEdges(data.sectors.edges, 'sectors');
        if (data?.countries?.edges) checkEdges(data.countries.edges, 'countries');
        if (data?.regions?.edges) checkEdges(data.regions.edges, 'regions');

        // Also check objectsOrObservables and relatedContainers
        if (data?.objectsOrObservables?.edges) checkEdges(data.objectsOrObservables.edges, 'objectsOrObservables');
        if (data?.relatedContainers?.edges) checkEdges(data.relatedContainers.edges, 'relatedContainers');

        return ids;
      };

      const embeddedIds = extractEmbeddedIds(reportData);
      if (embeddedIds.length > 0) {
        log("Embedded entity IDs found", { reportId: reportId.substring(0, 20), count: embeddedIds.length });
      }
      allEntityIds.push(...embeddedIds);
    }

    // Get unique entity IDs
    const uniqueIds = [...new Set(allEntityIds)].filter(Boolean);

    if (uniqueIds.length === 0) {
      log("No entity IDs found for report", { reportId });
      return result;
    }

    log("Entity IDs found", { reportId: reportId.substring(0, 20), count: uniqueIds.length });

    // Fetch the target entities in batches (PostgREST has URL limits)
    const batchSize = 50;
    for (let i = 0; i < uniqueIds.length; i += batchSize) {
      const batch = uniqueIds.slice(i, i + batchSize);
      const entityQuery = `select=internal_id,name,entity_type,data&internal_id=in.(${batch.join(',')})`;
      const entities = await queryIntelSchema(supabaseUrl, serviceKey, "object_current", entityQuery) as any[];

      // Log entity types found for debugging
      const typeCounts: Record<string, number> = {};
      for (const e of entities) {
        const t = e.entity_type || 'unknown';
        typeCounts[t] = (typeCounts[t] || 0) + 1;
      }
      log("Entity types found in batch", { reportId: reportId.substring(0, 20), types: typeCounts, totalFound: entities.length, batchSize: batch.length });

      for (const entity of entities) {
        const name = entity.name || '';
        const type = entity.entity_type || '';
        const id = entity.internal_id || '';

        switch (type) {
          case 'Intrusion-Set':
          case 'Threat-Actor':
            if (name && !result.threatActors.find(a => a.id === id)) {
              result.threatActors.push({ id, name });
            }
            break;
          case 'Country':
          case 'Region':
          case 'City':
          case 'Location':
            // For Location type, try to determine subtype from data
            let geoType = type;
            if (type === 'Location') {
              const locationType = entity.data?.x_opencti_location_type || entity.data?.location_type || 'Location';
              geoType = locationType;
            }
            if (name && !result.geographies.find(g => g.id === id)) {
              result.geographies.push({ id, name, entityType: geoType });
            }
            break;
          case 'Sector':
            if (name && !result.sectors.find(s => s.id === id)) {
              result.sectors.push({ id, name });
            }
            break;
          case 'Vulnerability':
            if (name && !result.cves.includes(name)) {
              result.cves.push(name);
            }
            break;
          case 'Attack-Pattern':
            const mitreId = entity.data?.x_mitre_id || '';
            if (name && !result.ttps.find(t => t.id === id)) {
              result.ttps.push({ id, name, mitreId });
            }
            break;
        }
      }
    }
  } catch (error) {
    log("Entity fetch error", { reportId, error: String(error) });
  }

  // Add to cache buffer for batch write later
  if (useCache && (result.threatActors.length > 0 || result.geographies.length > 0 ||
      result.sectors.length > 0 || result.cves.length > 0 || result.ttps.length > 0)) {
    entityCacheBuffer.set(reportId, result);
    log("Entity cache buffered", { reportId: reportId.substring(0, 20) });
  }

  return result;
}

// Aggregate targeting mentions across all reports
function aggregateTargetingMentions(
  mediaSummaries: MediaSummary[],
  threatSummaries: ThreatSummary[],
  advisorySummaries: AdvisorySummary[],
  entityMentionsCache: Map<string, {
    sectors: Array<{ id: string; name: string }>;
    geographies: Array<{ id: string; name: string; entityType: string }>;
  }>
): TargetingData {
  // Aggregate sectors
  const sectorMap = new Map<string, {
    id: string;
    name: string;
    count: number;
    evidence: Array<{ type: string; id: string; name: string; linkPath: string; date: string }>;
  }>();

  // Aggregate geographies
  const geoMap = new Map<string, {
    id: string;
    name: string;
    entityType: string;
    count: number;
    evidence: Array<{ type: string; id: string; name: string; linkPath: string; date: string }>;
  }>();

  // Process media summaries
  for (const media of mediaSummaries) {
    if (!media.reportId) continue;
    const mentions = entityMentionsCache.get(media.reportId);
    if (!mentions) continue;

    const evidenceItem = {
      type: 'media-report',
      id: media.reportId,
      name: media.title,
      linkPath: `/threat-reports/${media.reportId}`,
      date: media.date,
    };

    for (const sector of mentions.sectors) {
      const existing = sectorMap.get(sector.id);
      if (existing) {
        existing.count++;
        if (existing.evidence.length < 5) {
          existing.evidence.push(evidenceItem);
        }
      } else {
        sectorMap.set(sector.id, {
          id: sector.id,
          name: sector.name,
          count: 1,
          evidence: [evidenceItem],
        });
      }
    }

    for (const geo of mentions.geographies) {
      const existing = geoMap.get(geo.id);
      if (existing) {
        existing.count++;
        if (existing.evidence.length < 5) {
          existing.evidence.push(evidenceItem);
        }
      } else {
        geoMap.set(geo.id, {
          id: geo.id,
          name: geo.name,
          entityType: geo.entityType,
          count: 1,
          evidence: [evidenceItem],
        });
      }
    }
  }

  // Process threat summaries
  for (const threat of threatSummaries) {
    if (!threat.reportId) continue;
    const mentions = entityMentionsCache.get(threat.reportId);
    if (!mentions) continue;

    const evidenceItem = {
      type: 'threat-report',
      id: threat.reportId,
      name: threat.title,
      linkPath: `/threat-reports/${threat.reportId}`,
      date: threat.date,
    };

    for (const sector of mentions.sectors) {
      const existing = sectorMap.get(sector.id);
      if (existing) {
        existing.count++;
        if (existing.evidence.length < 5) {
          existing.evidence.push(evidenceItem);
        }
      } else {
        sectorMap.set(sector.id, {
          id: sector.id,
          name: sector.name,
          count: 1,
          evidence: [evidenceItem],
        });
      }
    }

    for (const geo of mentions.geographies) {
      const existing = geoMap.get(geo.id);
      if (existing) {
        existing.count++;
        if (existing.evidence.length < 5) {
          existing.evidence.push(evidenceItem);
        }
      } else {
        geoMap.set(geo.id, {
          id: geo.id,
          name: geo.name,
          entityType: geo.entityType,
          count: 1,
          evidence: [evidenceItem],
        });
      }
    }
  }

  // Process advisory summaries
  for (const advisory of advisorySummaries) {
    if (!advisory.reportId) continue;
    const mentions = entityMentionsCache.get(advisory.reportId);
    if (!mentions) continue;

    const evidenceItem = {
      type: 'advisory',
      id: advisory.reportId,
      name: advisory.title,
      linkPath: `/advisories/${advisory.reportId}`,
      date: advisory.date,
    };

    for (const sector of mentions.sectors) {
      const existing = sectorMap.get(sector.id);
      if (existing) {
        existing.count++;
        if (existing.evidence.length < 5) {
          existing.evidence.push(evidenceItem);
        }
      } else {
        sectorMap.set(sector.id, {
          id: sector.id,
          name: sector.name,
          count: 1,
          evidence: [evidenceItem],
        });
      }
    }

    for (const geo of mentions.geographies) {
      const existing = geoMap.get(geo.id);
      if (existing) {
        existing.count++;
        if (existing.evidence.length < 5) {
          existing.evidence.push(evidenceItem);
        }
      } else {
        geoMap.set(geo.id, {
          id: geo.id,
          name: geo.name,
          entityType: geo.entityType,
          count: 1,
          evidence: [evidenceItem],
        });
      }
    }
  }

  // Convert to arrays and sort by count - include all (no artificial limit)
  const sectors: TargetingMention[] = [...sectorMap.values()]
    .sort((a, b) => b.count - a.count)
    .map(s => ({
      id: s.id,
      name: s.name,
      entityType: 'Sector',
      count: s.count,
      confidence: 'HIGH' as const, // All directly extracted
      evidence: s.evidence,
    }));

  const geographies: TargetingMention[] = [...geoMap.values()]
    .sort((a, b) => b.count - a.count)
    .map(g => ({
      id: g.id,
      name: g.name,
      entityType: g.entityType,
      count: g.count,
      confidence: 'HIGH' as const, // All directly extracted
      evidence: g.evidence,
    }));

  return { sectors, geographies };
}

// Fetch TTPs used by a threat actor via 'uses' relationship
async function fetchActorTTPs(
  supabaseUrl: string,
  serviceKey: string,
  actorId: string
): Promise<Array<{ id: string; name: string; mitreId: string }>> {
  const ttps: Array<{ id: string; name: string; mitreId: string }> = [];

  try {
    // Find TTPs via 'uses' relationship
    const relQuery = `select=target_id&relationship_type=eq.uses&source_id=eq.${actorId}`;
    const relationships = await queryIntelSchema(supabaseUrl, serviceKey, "relationship_current", relQuery) as any[];

    if (!relationships || relationships.length === 0) {
      return ttps;
    }

    const ttpIds = relationships.map((r: any) => r.target_id).filter(Boolean);

    if (ttpIds.length === 0) {
      return ttps;
    }

    // Fetch attack patterns
    const entityQuery = `select=internal_id,name,data&entity_type=eq.Attack-Pattern&internal_id=in.(${ttpIds.join(',')})`;
    const entities = await queryIntelSchema(supabaseUrl, serviceKey, "object_current", entityQuery) as any[];

    for (const entity of entities) {
      ttps.push({
        id: entity.internal_id,
        name: entity.name,
        mitreId: entity.data?.x_mitre_id || '',
      });
    }
  } catch (error) {
    log("Actor TTPs fetch error", { actorId, error: String(error) });
  }

  return ttps;
}

// Fetch mitigations (Courses of Action) for TTPs via 'mitigates' relationship
async function fetchMitigationsForTTPs(
  supabaseUrl: string,
  serviceKey: string,
  ttpIds: string[]
): Promise<Map<string, Array<{ id: string; name: string; description: string; mitreId: string }>>> {
  const mitigationMap = new Map<string, Array<{ id: string; name: string; description: string; mitreId: string }>>();

  if (ttpIds.length === 0) return mitigationMap;

  try {
    // Find mitigations that mitigate these TTPs
    // Course-of-Action --mitigates--> Attack-Pattern
    const relQuery = `select=source_id,target_id&relationship_type=eq.mitigates&target_id=in.(${ttpIds.join(',')})`;
    const relationships = await queryIntelSchema(supabaseUrl, serviceKey, "relationship_current", relQuery) as any[];

    if (!relationships || relationships.length === 0) {
      return mitigationMap;
    }

    // Group by TTP
    const ttpToMitigationIds = new Map<string, string[]>();
    for (const rel of relationships) {
      const ttpId = rel.target_id;
      const mitigationId = rel.source_id;
      if (!ttpToMitigationIds.has(ttpId)) {
        ttpToMitigationIds.set(ttpId, []);
      }
      ttpToMitigationIds.get(ttpId)!.push(mitigationId);
    }

    // Get all unique mitigation IDs
    const allMitigationIds = [...new Set(relationships.map((r: any) => r.source_id).filter(Boolean))];

    if (allMitigationIds.length === 0) {
      return mitigationMap;
    }

    // Fetch Course-of-Action entities
    const entityQuery = `select=internal_id,name,data&entity_type=eq.Course-Of-Action&internal_id=in.(${allMitigationIds.join(',')})`;
    const entities = await queryIntelSchema(supabaseUrl, serviceKey, "object_current", entityQuery) as any[];

    // Build lookup
    const mitigationLookup = new Map<string, { id: string; name: string; description: string; mitreId: string }>();
    for (const entity of entities) {
      mitigationLookup.set(entity.internal_id, {
        id: entity.internal_id,
        name: entity.name,
        description: entity.data?.description?.substring(0, 300) || '',
        mitreId: entity.data?.x_mitre_id || '',
      });
    }

    // Build the map
    for (const [ttpId, mitIds] of ttpToMitigationIds) {
      const mitigations = mitIds
        .map(id => mitigationLookup.get(id))
        .filter(Boolean) as Array<{ id: string; name: string; description: string; mitreId: string }>;
      if (mitigations.length > 0) {
        mitigationMap.set(ttpId, mitigations);
      }
    }
  } catch (error) {
    log("Mitigations fetch error", { error: String(error) });
  }

  return mitigationMap;
}

// Score and rank recommended actions based on TTPs and mitigations
function scoreAndRankActions(
  observedTTPs: TTPObserved[],
  mitigationMap: Map<string, Array<{ id: string; name: string; description: string; mitreId: string }>>,
  allEvidence: Map<string, Array<{ type: string; id: string; name: string; linkPath: string }>>
): RecommendedAction[] {
  // Collect all unique mitigations with scores
  const mitigationScores = new Map<string, {
    mitigation: { id: string; name: string; description: string; mitreId: string };
    score: number;
    confidence: 'HIGH' | 'MED';
    ttps: Array<{ ttpId: string; ttpName: string; mitreId?: string }>;
    evidence: Array<{ type: string; id: string; name: string; linkPath: string }>;
  }>();

  for (const ttp of observedTTPs) {
    const mitigations = mitigationMap.get(ttp.id) || [];
    const isObserved = ttp.source === 'observed';
    const baseScore = isObserved ? 3 : 2; // +3 observed, +2 inferred

    for (const mitigation of mitigations) {
      const existing = mitigationScores.get(mitigation.id);

      // Impact weight based on mitigation type
      let impactWeight = 1; // Default: hygiene
      const nameLower = mitigation.name.toLowerCase();
      const descLower = mitigation.description.toLowerCase();

      // +3 for ransomware-enabling controls
      if (nameLower.includes('mfa') || nameLower.includes('multi-factor') ||
          nameLower.includes('backup') || nameLower.includes('privileged access') ||
          nameLower.includes('remote access') || descLower.includes('backup') ||
          descLower.includes('multi-factor')) {
        impactWeight = 3;
      }
      // +2 for credential/phishing controls
      else if (nameLower.includes('credential') || nameLower.includes('phishing') ||
               nameLower.includes('password') || nameLower.includes('authentication') ||
               descLower.includes('credential') || descLower.includes('phishing')) {
        impactWeight = 2;
      }

      const totalScore = baseScore + impactWeight + 1; // +1 generic SMB applicability

      if (existing) {
        existing.score = Math.max(existing.score, totalScore);
        if (isObserved && existing.confidence !== 'HIGH') {
          existing.confidence = 'HIGH';
        }
        if (!existing.ttps.find(t => t.ttpId === ttp.id)) {
          existing.ttps.push({ ttpId: ttp.id, ttpName: ttp.name, mitreId: ttp.mitreId });
        }
        // Add evidence
        for (const evId of ttp.evidenceIds) {
          const ev = allEvidence.get(evId);
          if (ev) {
            for (const e of ev) {
              if (!existing.evidence.find(x => x.id === e.id)) {
                existing.evidence.push(e);
              }
            }
          }
        }
      } else {
        const evidence: Array<{ type: string; id: string; name: string; linkPath: string }> = [];
        for (const evId of ttp.evidenceIds) {
          const ev = allEvidence.get(evId);
          if (ev) {
            evidence.push(...ev);
          }
        }

        mitigationScores.set(mitigation.id, {
          mitigation,
          score: totalScore,
          confidence: isObserved ? 'HIGH' : 'MED',
          ttps: [{ ttpId: ttp.id, ttpName: ttp.name, mitreId: ttp.mitreId }],
          evidence,
        });
      }
    }
  }

  // Sort by score and take top 3
  const ranked = [...mitigationScores.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, 3);

  return ranked.map(item => ({
    action: item.mitigation.name,
    confidence: item.confidence,
    why: item.mitigation.description,
    score: item.score,
    evidence: item.evidence.slice(0, 5), // Limit to 5 evidence items
    mitigates: item.ttps.slice(0, 5), // Limit to 5 TTPs
  }));
}

// Calculate threat posture based on today's intelligence
function calculateThreatPosture(
  ransomwareActivity: RansomwareActivity[],
  advisorySummaries: AdvisorySummary[],
  threatSummaries: ThreatSummary[],
  mediaSummaries: MediaSummary[]
): ThreatPosture {
  let score = 0;
  const reasons: string[] = [];

  // Ransomware activity
  const totalVictims = ransomwareActivity.reduce((sum, a) => sum + a.victimCount, 0);
  if (totalVictims >= 10) {
    score += 3;
    reasons.push(`${totalVictims} ransomware victims reported across ${ransomwareActivity.length} groups`);
  } else if (totalVictims >= 5) {
    score += 2;
    reasons.push(`${totalVictims} ransomware victims reported`);
  } else if (totalVictims > 0) {
    score += 1;
    reasons.push(`${totalVictims} ransomware victim(s) reported`);
  }

  // Critical advisories
  const criticalAdvisories = advisorySummaries.filter(a =>
    a.severity?.toLowerCase() === 'critical'
  );
  if (criticalAdvisories.length >= 2) {
    score += 3;
    reasons.push(`${criticalAdvisories.length} critical security advisories issued`);
  } else if (criticalAdvisories.length === 1) {
    score += 2;
    reasons.push(`1 critical security advisory issued`);
  }

  // High severity threats
  const highSeverityThreats = threatSummaries.filter(t =>
    t.severity?.toLowerCase() === 'critical' || t.severity?.toLowerCase() === 'high'
  );
  if (highSeverityThreats.length >= 3) {
    score += 2;
    reasons.push(`${highSeverityThreats.length} high/critical severity threat reports`);
  } else if (highSeverityThreats.length >= 1) {
    score += 1;
  }

  // Determine level
  let level: 'Elevated' | 'Moderate' | 'Low';
  if (score >= 5) {
    level = 'Elevated';
  } else if (score >= 2) {
    level = 'Moderate';
  } else {
    level = 'Low';
  }

  const rationale = reasons.length > 0
    ? reasons.slice(0, 3).join('. ') + '.'
    : 'No significant threat activity detected in the reporting period.';

  return { level, rationale };
}

// Fetch ransomware victims - extract threat group from name pattern
async function fetchRansomwareVictims(
  supabaseUrl: string,
  serviceKey: string,
  limit: number,
  since: string
): Promise<Array<{ id: string; name: string; threatGroups?: Array<{ id: string; name: string }> }>> {
  // Get the ransomware reports - use data->report_types (JSONB) with cs. operator
  const query = `select=internal_id,name,data,source_created_at&entity_type=eq.Report&data->report_types=cs.["Ransomware-report"]&source_created_at=gte.${since}&order=source_created_at.desc&limit=${limit}`;

  const rows = await queryIntelSchema(supabaseUrl, serviceKey, "object_current", query) as any[];

  // Extract threat group from victim name pattern: "GROUP has published a new victim: VICTIM"
  return rows.map(row => {
    const name = row.name || row.data?.name || 'Unknown';
    const threatGroups: Array<{ id: string; name: string }> = [];

    // Try to extract threat group from name pattern
    const patterns = [
      /^(.+?)\s+has\s+published\s+a\s+new\s+victim:/i,
      /^(.+?)\s+published\s+a\s+new\s+victim:/i,
      /^(.+?)\s+claims\s+new\s+victim:/i,
      /^(.+?)\s+added\s+new\s+victim:/i,
      /^(.+?)\s+listed\s+new\s+victim:/i,
    ];

    for (const pattern of patterns) {
      const match = name.match(pattern);
      if (match) {
        threatGroups.push({ id: match[1].trim(), name: match[1].trim() });
        break;
      }
    }

    return {
      id: row.internal_id,
      name,
      threatGroups,
    };
  });
}

// Summarizer Agent - Takes content and generates factual summary (no assessments)
async function runSummarizerAgent(
  openai: OpenAI,
  title: string,
  content: string
): Promise<string> {
  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content: "You are a cybersecurity news analyst. Summarize articles with facts only. Do NOT make assessments, predictions, judgments, or recommendations. Just report what happened."
        },
        {
          role: "user",
          content: `Summarize this cybersecurity news article in exactly one paragraph (2-3 sentences).
Report ONLY the facts: What happened? Who was involved? What was the outcome?

DO NOT include:
- Assessments of severity or risk
- Recommendations for security teams
- Predictions about future implications
- Opinions or judgments

Article Title: ${title}
Article Content: ${content.substring(0, 5000)}

Provide ONLY the factual summary paragraph, no JSON, no formatting.`
        }
      ],
      temperature: 0.2,
      max_tokens: 250,
    });

    return completion.choices[0].message.content?.trim() || "Summary unavailable";
  } catch (error) {
    log("Summarizer error", { title, error: String(error) });
    return "Summary unavailable";
  }
}

// Media Agent - Coordinates summarization and entity extraction for each article
async function runMediaAgent(
  openai: OpenAI,
  supabaseUrl: string,
  serviceKey: string,
  reports: Array<{ id: string; name: string; description: string; date: string; externalReferences?: Array<{ url: string }>; data?: any }>,
): Promise<MediaSummary[]> {
  const summaries: MediaSummary[] = [];
  const BATCH_SIZE = 10; // Process 10 reports in parallel

  // Use dynamic limits based on volume and select by relevance
  const dynamicLimit = getDynamicLimit(reports.length, 75);
  const reportsToProcess = selectTopReports(
    reports.map(r => ({ ...r, description: r.description || r.data?.description || '' })),
    dynamicLimit,
    true // Always include critical severity
  );

  log("Media agent selection", {
    totalReports: reports.length,
    dynamicLimit,
    selectedCount: reportsToProcess.length,
  });

  // Process media reports in parallel batches
  for (let i = 0; i < reportsToProcess.length; i += BATCH_SIZE) {
    const batch = reportsToProcess.slice(i, i + BATCH_SIZE);
    log("Processing media batch", { batch: i / BATCH_SIZE + 1, size: batch.length });

    const batchResults = await Promise.all(batch.map(async (report): Promise<MediaSummary | null> => {
      try {
        // Get source URL from external references first, then try name pattern
        let sourceUrl = "";

        // First, check external references (most reliable source)
        if (report.externalReferences && report.externalReferences.length > 0) {
          for (const ref of report.externalReferences) {
            if (ref.url && ref.url.startsWith('http')) {
              sourceUrl = ref.url;
              break;
            }
          }
        }

        // Fallback: try to extract from "Original Site:" in name
        if (!sourceUrl) {
          const urlMatch = report.name.match(/Original Site:\s*(.+)/i);
          if (urlMatch) {
            const extracted = urlMatch[1].trim();
            if (extracted && !extracted.startsWith('http')) {
              sourceUrl = `https://${extracted}`;
            } else {
              sourceUrl = extracted;
            }
          }
        }

        // Clean title (remove "Original Site:" prefix)
        const title = report.name.split("Original Site:")[0].trim();
        const contentToSummarize = report.description || "";

        if (!contentToSummarize || contentToSummarize.length < 50) {
          return null;
        }

        // Fetch entity mentions and summarize in parallel
        const [entityMentions, summary] = await Promise.all([
          fetchReportEntityMentions(supabaseUrl, serviceKey, report.id, report.data),
          runSummarizerAgent(openai, title, contentToSummarize),
        ]);

        return {
          title,
          summary,
          sourceUrl,
          date: report.date,
          reportId: report.id,
          threatActors: entityMentions.threatActors.map(a => a.name),
          geographies: entityMentions.geographies.map(g => g.name),
          sectors: entityMentions.sectors.map(s => s.name),
          cves: entityMentions.cves,
          ttps: entityMentions.ttps.map(t => t.id),
          sectorDetails: entityMentions.sectors,
          geographyDetails: entityMentions.geographies,
        };
      } catch (error) {
        log("Media agent error", { title: report.name, error: String(error) });
        return null;
      }
    }));

    // Add successful results to summaries
    summaries.push(...batchResults.filter((r): r is MediaSummary => r !== null));
  }

  log("Media agent completed", { processed: summaries.length });
  return summaries;
}

// Threat Agent - Summarize each threat report
async function runThreatAgent(
  openai: OpenAI,
  supabaseUrl: string,
  serviceKey: string,
  reports: Array<{ id: string; name: string; description: string; date: string; source?: string; externalReferences?: Array<{ url: string; sourceName: string }>; data?: any }>,
): Promise<ThreatSummary[]> {
  const summaries: ThreatSummary[] = [];
  const BATCH_SIZE = 10;

  // Use dynamic limits based on volume and select by relevance
  const dynamicLimit = getDynamicLimit(reports.length, 75);
  const reportsToProcess = selectTopReports(
    reports.map(r => ({ ...r, description: r.description || r.data?.description || '' })),
    dynamicLimit,
    true // Always include critical severity
  );

  log("Threat agent selection", {
    totalReports: reports.length,
    dynamicLimit,
    selectedCount: reportsToProcess.length,
  });

  for (let i = 0; i < reportsToProcess.length; i += BATCH_SIZE) {
    const batch = reportsToProcess.slice(i, i + BATCH_SIZE);
    log("Processing threat batch", { batch: i / BATCH_SIZE + 1, size: batch.length });

    const batchResults = await Promise.all(batch.map(async (report): Promise<ThreatSummary | null> => {
      try {
        const sourceUrl = report.externalReferences?.[0]?.url || "";

        // Fetch entities and summarize in parallel
        const [entityMentions, completion] = await Promise.all([
          fetchReportEntityMentions(supabaseUrl, serviceKey, report.id, report.data),
          openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [
              {
                role: "system",
                content: "You are a senior threat intelligence analyst. Provide concise, actionable summaries. Always respond with valid JSON."
              },
              {
                role: "user",
                content: `Summarize this threat intelligence report in 2-3 sentences.
Include: threat actor (if named), targets, techniques used, and recommended defenses.

Report Title: ${report.name}
Report Content: ${report.description?.substring(0, 3000) || "No description available"}
Source: ${report.source || "Unknown"}

Respond with JSON only:
{"summary": "2-3 sentence summary here", "threatActor": "actor name or null", "severity": "critical|high|medium|low"}`
              }
            ],
            temperature: 0.3,
            max_tokens: 300,
            response_format: { type: "json_object" },
          }),
        ]);

        const result = JSON.parse(completion.choices[0].message.content || "{}");

        return {
          title: report.name,
          summary: result.summary || "Summary unavailable",
          sourceUrl,
          date: report.date,
          reportId: report.id,
          threatActor: result.threatActor || null,
          severity: result.severity || "medium",
          ttps: entityMentions.ttps.map(t => t.id),
          cves: entityMentions.cves,
          sectorDetails: entityMentions.sectors,
          geographyDetails: entityMentions.geographies,
        };
      } catch (error) {
        log("Threat agent error", { title: report.name, error: String(error) });
        return null;
      }
    }));

    summaries.push(...batchResults.filter((r): r is ThreatSummary => r !== null));
  }

  log("Threat agent completed", { processed: summaries.length });
  return summaries;
}

// Advisory Agent - Summarize each advisory
async function runAdvisoryAgent(
  openai: OpenAI,
  supabaseUrl: string,
  serviceKey: string,
  advisories: Array<{ id: string; name: string; description: string; date: string; source?: string; externalReferences?: Array<{ url: string }>; data?: any }>,
): Promise<AdvisorySummary[]> {
  const summaries: AdvisorySummary[] = [];
  const BATCH_SIZE = 10;

  // Use dynamic limits based on volume and select by relevance
  const dynamicLimit = getDynamicLimit(advisories.length, 75);
  const advisoriesToProcess = selectTopReports(
    advisories.map(a => ({ ...a, description: a.description || a.data?.description || '' })),
    dynamicLimit,
    true // Always include critical severity
  );

  log("Advisory agent selection", {
    totalAdvisories: advisories.length,
    dynamicLimit,
    selectedCount: advisoriesToProcess.length,
  });

  for (let i = 0; i < advisoriesToProcess.length; i += BATCH_SIZE) {
    const batch = advisoriesToProcess.slice(i, i + BATCH_SIZE);
    log("Processing advisory batch", { batch: i / BATCH_SIZE + 1, size: batch.length });

    const batchResults = await Promise.all(batch.map(async (advisory): Promise<AdvisorySummary | null> => {
      try {
        const sourceUrl = advisory.externalReferences?.[0]?.url || "";

        // Fetch entities and summarize in parallel
        const [entityMentions, completion] = await Promise.all([
          fetchReportEntityMentions(supabaseUrl, serviceKey, advisory.id, advisory.data),
          openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [
              {
                role: "system",
                content: "You are a security advisory analyst. Provide brief, actionable summaries. Always respond with valid JSON."
              },
              {
                role: "user",
                content: `Summarize this security advisory in 2-3 sentences.
Include: what systems are affected, what the vulnerability or issue is, and what action to take.

Advisory Title: ${advisory.name}
Advisory Content: ${advisory.description?.substring(0, 3000) || "No description available"}
Source: ${advisory.source || "Unknown"}

Respond with JSON only:
{"summary": "2-3 sentence summary here", "severity": "critical|high|medium|low"}`
              }
            ],
            temperature: 0.3,
            max_tokens: 300,
            response_format: { type: "json_object" },
          }),
        ]);

        const result = JSON.parse(completion.choices[0].message.content || "{}");

        return {
          title: advisory.name,
          summary: result.summary || "Summary unavailable",
          sourceUrl,
          date: advisory.date,
          reportId: advisory.id,
          severity: result.severity || "medium",
          source: advisory.source || "Unknown",
          ttps: entityMentions.ttps.map(t => t.id),
          cves: entityMentions.cves,
          sectorDetails: entityMentions.sectors,
          geographyDetails: entityMentions.geographies,
        };
      } catch (error) {
        log("Advisory agent error", { title: advisory.name, error: String(error) });
        return null;
      }
    }));

    summaries.push(...batchResults.filter((r): r is AdvisorySummary => r !== null));
  }

  log("Advisory agent completed", { processed: summaries.length });
  return summaries;
}

// Format victim display name: "X published a new victim: Y" -> "X listed Y"
function formatVictimName(
  rawName: string,
  threatGroupName?: string | null
): { displayName: string; victimName: string } {
  const patterns = [
    /^(.+?)\s+has\s+published\s+a\s+new\s+victim:\s*(.+)$/i,
    /^(.+?)\s+published\s+a\s+new\s+victim:\s*(.+)$/i,
    /^(.+?)\s+claims\s+new\s+victim:\s*(.+)$/i,
    /^(.+?)\s+added\s+new\s+victim:\s*(.+)$/i,
    /^(.+?)\s+listed\s+new\s+victim:\s*(.+)$/i,
    /^New\s+victim:\s*(.+)$/i,
  ];

  let victimName = rawName;

  for (const pattern of patterns) {
    const match = rawName.match(pattern);
    if (match) {
      victimName = match.length === 3 ? match[2].trim() : match[1].trim();
      break;
    }
  }

  // If no pattern matched but there's a colon, split on it
  if (victimName === rawName && rawName.includes(":")) {
    victimName = rawName.split(":").slice(1).join(":").trim();
  }

  const threatGroup = threatGroupName || null;
  const displayName = threatGroup ? `${threatGroup} listed ${victimName}` : victimName;

  return { displayName, victimName };
}

// Process ransomware victims to get activity by group
function processRansomwareActivity(
  victims: Array<{ id: string; name: string; threatGroups?: Array<{ id: string; name: string }> }>
): RansomwareActivity[] {
  const actorMap = new Map<string, { id?: string; count: number; victims: string[] }>();

  for (const victim of victims) {
    // Get threat group from threatGroups array
    const threatGroup = victim.threatGroups?.[0];
    const actorName = threatGroup?.name || "Unknown";
    const actorId = threatGroup?.id;

    if (!actorMap.has(actorName)) {
      actorMap.set(actorName, { id: actorId, count: 0, victims: [] });
    }

    const entry = actorMap.get(actorName)!;
    entry.count++;
    // Set the actor ID if we have it (in case first entry didn't have it)
    if (actorId && !entry.id) {
      entry.id = actorId;
    }
    if (entry.victims.length < 5) {
      // Format the victim name (extracts clean victim name from raw data)
      const { victimName } = formatVictimName(victim.name, actorName);
      entry.victims.push(victimName);
    }
  }

  // Convert to array and sort by victim count descending
  const activities: RansomwareActivity[] = [];
  for (const [actor, data] of actorMap.entries()) {
    if (actor !== "Unknown") {
      activities.push({
        actor,
        actorId: data.id,
        victimCount: data.count,
        victims: data.victims,
      });
    }
  }

  return activities.sort((a, b) => b.victimCount - a.victimCount);
}

// Confidence level type for professional intelligence assessments
type ConfidenceLevel = 'HIGH' | 'MODERATE' | 'LOW';

// Comprehensive Intelligence Assessment - AI-driven analysis of all evidence
interface ComprehensiveAssessment {
  executive_summary: string;
  key_takeaways: string[];
  threat_landscape: {
    bluf?: string;
    confidence?: ConfidenceLevel;
    confidence_rationale?: string;
    observations?: string[];
    assessment: string;
    key_themes: string[];
    threat_level_rationale?: string;  // Kept for backwards compatibility
    limitations?: string[];
  };
  actor_analysis: {
    bluf?: string;
    confidence?: ConfidenceLevel;
    confidence_rationale?: string;
    assessment: string;
    active_actors: Array<{
      name: string;
      activity_summary: string;
      ttps_used: string[];
      source_count?: number;
    }>;
  };
  ransomware_analysis: {
    bluf?: string;
    confidence?: ConfidenceLevel;
    confidence_rationale?: string;
    observations?: string[];
    assessment: string;
    total_victims: number;
    active_groups: Array<{
      name: string;
      victim_count: number;
      notable_victims?: string[];
    }>;
  };
  vulnerability_analysis: {
    bluf?: string;
    confidence?: ConfidenceLevel;
    confidence_rationale?: string;
    assessment: string;
    critical_vulns: Array<{
      cve: string;
      context: string;
      urgency: string;
      source_type?: string;
    }>;
  };
  targeting_analysis: {
    bluf?: string;
    confidence?: ConfidenceLevel;
    confidence_rationale?: string;
    assessment: string;
    sectors_at_risk: string[];
    geographic_focus: string[];
  };
  recommended_mitigations: Array<{
    priority: number;
    action: string;
    responsible_party?: string;
    urgency?: string;
    rationale: string;
    success_criteria?: string;
    addresses_ttps: string[];
    evidence_sources: string[];
  }>;
}

// Compress report context for token efficiency
function compressMediaContext(summaries: MediaSummary[]): string {
  // Group by main entities to reduce redundancy
  return summaries.map(m => {
    const parts = [];
    // Truncate title to 80 chars
    parts.push(`"${m.title.substring(0, 80)}${m.title.length > 80 ? '...' : ''}"`);
    // Compress entities into single line
    const entities = [
      m.threatActors?.slice(0, 2).join(','),
      m.cves?.slice(0, 3).join(','),
      m.sectors?.slice(0, 2).join(','),
    ].filter(Boolean);
    if (entities.length) parts.push(`[${entities.join(' | ')}]`);
    // Truncate summary to first sentence or 150 chars
    const summaryEnd = Math.min(m.summary.indexOf('. ') + 1 || 150, 150);
    parts.push(m.summary.substring(0, summaryEnd));
    return `- ${parts.join(' ')}`;
  }).join("\n");
}

function compressThreatContext(summaries: ThreatSummary[]): string {
  return summaries.map(t => {
    const parts = [
      `"${t.title.substring(0, 60)}${t.title.length > 60 ? '...' : ''}"`,
      `[${t.severity?.toUpperCase() || 'MED'}]`,
    ];
    if (t.threatActor) parts.push(`Actor:${t.threatActor}`);
    if (t.cves?.length) parts.push(`CVEs:${t.cves.slice(0, 3).join(',')}`);
    // First sentence of summary
    const summaryEnd = Math.min(t.summary.indexOf('. ') + 1 || 120, 120);
    parts.push(t.summary.substring(0, summaryEnd));
    return `- ${parts.join(' ')}`;
  }).join("\n");
}

function compressAdvisoryContext(summaries: AdvisorySummary[]): string {
  return summaries.map(a => {
    const parts = [
      `"${a.title.substring(0, 60)}${a.title.length > 60 ? '...' : ''}"`,
      `[${a.severity?.toUpperCase() || 'MED'}]`,
      `(${a.source.substring(0, 20)})`,
    ];
    if (a.cves?.length) parts.push(`CVEs:${a.cves.slice(0, 3).join(',')}`);
    // First sentence of summary
    const summaryEnd = Math.min(a.summary.indexOf('. ') + 1 || 120, 120);
    parts.push(a.summary.substring(0, summaryEnd));
    return `- ${parts.join(' ')}`;
  }).join("\n");
}

// === PARALLEL SECTION GENERATION (Phase 4) ===

// Shared context interface for all section generators
interface AnalysisContext {
  mediaContext: string;
  threatContext: string;
  advisoryContext: string;
  ransomwareContext: string;
  ttpContext: string;
  mitigationContext: string;
  sectorContext: string;
  geoContext: string;
  cveContext: string;
  counts: {
    media: number;
    threats: number;
    advisories: number;
    ransomwareVictims: number;
    ttps: number;
    sectors: number;
    geos: number;
    cves: number;
  };
  ransomwareActivity: RansomwareActivity[];
  observedTTPs: TTPObserved[];
}

// Base system prompt for all section generators
const INTELLIGENCE_SYSTEM_PROMPT = `You are a senior cyber threat intelligence analyst. Follow these rules:

CRITICAL RULES:
1. ONLY state facts directly evidenced in source data
2. NEVER assume intent, attribution, or future actions without evidence
3. Use hedging language: "reportedly", "allegedly", "multiple sources indicate"
4. Distinguish: OBSERVED (stated in source), INFERRED (logical conclusion), REPORTED (unverified)

AVOID:
- Attribution without evidence
- Predictive statements
- Value judgments ("sophisticated")
- Emotional language
- Unsupported superlatives

CONFIDENCE LEVELS:
- HIGH: Multiple independent sources, direct technical evidence
- MODERATE: Single credible source with corroborating evidence
- LOW: Single unverified source or significant inference`;

// Generate threat landscape section (uses gpt-4o for complexity)
async function generateThreatLandscape(
  openai: OpenAI,
  ctx: AnalysisContext
): Promise<{ bluf?: string; confidence?: ConfidenceLevel; confidence_rationale?: string; observations?: string[]; assessment: string; key_themes: string[]; limitations?: string[] }> {
  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: INTELLIGENCE_SYSTEM_PROMPT },
        {
          role: "user",
          content: `Analyze the threat landscape from these reports:

MEDIA (${ctx.counts.media}): ${ctx.mediaContext || "None"}
THREAT REPORTS (${ctx.counts.threats}): ${ctx.threatContext || "None"}
ADVISORIES (${ctx.counts.advisories}): ${ctx.advisoryContext || "None"}

Generate JSON:
{
  "bluf": "One sentence - most important finding",
  "confidence": "HIGH/MODERATE/LOW",
  "confidence_rationale": "Why this confidence level",
  "observations": ["Fact 1 from sources", "Fact 2"],
  "assessment": "2-3 paragraphs connecting observations",
  "key_themes": ["Theme 1", "Theme 2", "Theme 3"],
  "limitations": ["What we couldn't determine"]
}`
        }
      ],
      temperature: 0.3,
      max_tokens: 1500,
      response_format: { type: "json_object" },
    });
    return JSON.parse(completion.choices[0].message.content || "{}");
  } catch (error) {
    log("Threat landscape generation error", { error: String(error) });
    return { assessment: "Analysis generation failed.", key_themes: [] };
  }
}

// Generate actor analysis section (uses gpt-4o)
async function generateActorAnalysis(
  openai: OpenAI,
  ctx: AnalysisContext
): Promise<{ bluf?: string; confidence?: ConfidenceLevel; confidence_rationale?: string; assessment: string; active_actors: Array<{ name: string; activity_summary: string; ttps_used: string[]; source_count: number }> }> {
  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: INTELLIGENCE_SYSTEM_PROMPT },
        {
          role: "user",
          content: `Analyze threat actor activity from these reports:

THREAT REPORTS: ${ctx.threatContext || "None"}
MEDIA COVERAGE: ${ctx.mediaContext || "None"}
TTPs OBSERVED: ${ctx.ttpContext || "None"}

Generate JSON:
{
  "bluf": "One sentence - most significant actor finding",
  "confidence": "HIGH/MODERATE/LOW",
  "confidence_rationale": "Why this confidence level",
  "assessment": "Analysis of who is active and what was REPORTED",
  "active_actors": [
    { "name": "Actor name", "activity_summary": "What they reportedly did", "ttps_used": ["TTP1"], "source_count": 1 }
  ]
}`
        }
      ],
      temperature: 0.3,
      max_tokens: 1500,
      response_format: { type: "json_object" },
    });
    return JSON.parse(completion.choices[0].message.content || "{}");
  } catch (error) {
    log("Actor analysis generation error", { error: String(error) });
    return { assessment: "Analysis generation failed.", active_actors: [] };
  }
}

// Generate ransomware analysis (uses gpt-4o-mini for simpler analysis)
async function generateRansomwareAnalysis(
  openai: OpenAI,
  ctx: AnalysisContext
): Promise<{ bluf?: string; confidence?: ConfidenceLevel; confidence_rationale?: string; observations?: string[]; assessment: string; total_victims: number; active_groups: Array<{ name: string; victim_count: number; notable_victims: string[] }> }> {
  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",  // Simpler section - use mini
      messages: [
        { role: "system", content: INTELLIGENCE_SYSTEM_PROMPT },
        {
          role: "user",
          content: `Analyze ransomware activity:

RANSOMWARE DATA (${ctx.counts.ransomwareVictims} victims):
${ctx.ransomwareContext}

Generate JSON:
{
  "bluf": "One sentence - key finding (e.g., 'X victims across Y groups')",
  "confidence": "HIGH/MODERATE/LOW",
  "confidence_rationale": "Why this confidence level",
  "observations": ["Factual observations: victim counts, patterns"],
  "assessment": "1-2 paragraphs of what the data shows",
  "total_victims": ${ctx.counts.ransomwareVictims},
  "active_groups": [{ "name": "Group", "victim_count": 0, "notable_victims": ["Victim 1"] }]
}`
        }
      ],
      temperature: 0.2,
      max_tokens: 1000,
      response_format: { type: "json_object" },
    });
    const result = JSON.parse(completion.choices[0].message.content || "{}");
    // Ensure we have active_groups from actual data
    if (!result.active_groups?.length && ctx.ransomwareActivity.length > 0) {
      result.active_groups = ctx.ransomwareActivity.slice(0, 10).map(a => ({
        name: a.actor,
        victim_count: a.victimCount,
        notable_victims: a.victims.slice(0, 3),
      }));
    }
    result.total_victims = ctx.counts.ransomwareVictims;
    return result;
  } catch (error) {
    log("Ransomware analysis generation error", { error: String(error) });
    return {
      assessment: ctx.counts.ransomwareVictims > 0
        ? `${ctx.counts.ransomwareVictims} victims reported.`
        : "No ransomware activity recorded.",
      total_victims: ctx.counts.ransomwareVictims,
      active_groups: ctx.ransomwareActivity.slice(0, 10).map(a => ({
        name: a.actor,
        victim_count: a.victimCount,
        notable_victims: a.victims.slice(0, 3),
      })),
    };
  }
}

// Generate vulnerability analysis (uses gpt-4o)
async function generateVulnerabilityAnalysis(
  openai: OpenAI,
  ctx: AnalysisContext
): Promise<{ bluf?: string; confidence?: ConfidenceLevel; confidence_rationale?: string; assessment: string; critical_vulns: Array<{ cve: string; context: string; urgency: string; source_type: string }> }> {
  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: INTELLIGENCE_SYSTEM_PROMPT },
        {
          role: "user",
          content: `Analyze vulnerabilities from these reports:

ADVISORIES: ${ctx.advisoryContext || "None"}
CVEs MENTIONED: ${ctx.cveContext}

Generate JSON:
{
  "bluf": "One sentence - most critical vulnerability finding",
  "confidence": "HIGH/MODERATE/LOW",
  "confidence_rationale": "Why this confidence level",
  "assessment": "Analysis including whether exploitation is observed vs theoretical",
  "critical_vulns": [
    { "cve": "CVE-XXXX-XXXXX", "context": "What was reported", "urgency": "CRITICAL/HIGH/MEDIUM", "source_type": "advisory/threat_report/media" }
  ]
}`
        }
      ],
      temperature: 0.3,
      max_tokens: 1200,
      response_format: { type: "json_object" },
    });
    return JSON.parse(completion.choices[0].message.content || "{}");
  } catch (error) {
    log("Vulnerability analysis generation error", { error: String(error) });
    return { assessment: "Analysis generation failed.", critical_vulns: [] };
  }
}

// Generate targeting analysis (uses gpt-4o-mini for simpler analysis)
async function generateTargetingAnalysis(
  openai: OpenAI,
  ctx: AnalysisContext
): Promise<{ bluf?: string; confidence?: ConfidenceLevel; confidence_rationale?: string; assessment: string; sectors_at_risk: string[]; geographic_focus: string[] }> {
  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",  // Simpler section - use mini
      messages: [
        { role: "system", content: INTELLIGENCE_SYSTEM_PROMPT },
        {
          role: "user",
          content: `Analyze targeting patterns:

SECTOR TARGETING:
${ctx.sectorContext}

GEOGRAPHIC TARGETING:
${ctx.geoContext}

Generate JSON:
{
  "bluf": "One sentence - key targeting pattern",
  "confidence": "HIGH/MODERATE/LOW",
  "confidence_rationale": "Why this confidence level",
  "assessment": "Analysis of targeting patterns observed in data",
  "sectors_at_risk": ["Sector 1", "Sector 2"],
  "geographic_focus": ["Region/Country 1"]
}`
        }
      ],
      temperature: 0.2,
      max_tokens: 800,
      response_format: { type: "json_object" },
    });
    return JSON.parse(completion.choices[0].message.content || "{}");
  } catch (error) {
    log("Targeting analysis generation error", { error: String(error) });
    return { assessment: "Analysis generation failed.", sectors_at_risk: [], geographic_focus: [] };
  }
}

// Generate executive summary and key takeaways (uses gpt-4o)
async function generateExecutiveSummary(
  openai: OpenAI,
  ctx: AnalysisContext
): Promise<{ executive_summary: string; key_takeaways: string[] }> {
  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: INTELLIGENCE_SYSTEM_PROMPT },
        {
          role: "user",
          content: `Create executive summary from this intelligence:

MEDIA (${ctx.counts.media}): ${ctx.mediaContext || "None"}
THREATS (${ctx.counts.threats}): ${ctx.threatContext || "None"}
ADVISORIES (${ctx.counts.advisories}): ${ctx.advisoryContext || "None"}
RANSOMWARE (${ctx.counts.ransomwareVictims} victims): ${ctx.ransomwareContext}
TTPs (${ctx.counts.ttps}): ${ctx.ttpContext || "None"}
SECTORS: ${ctx.sectorContext}
CVEs: ${ctx.cveContext}

Generate JSON:
{
  "executive_summary": "BLUF: Start with single most important finding. Then 2-3 sentences on other critical findings. Be specific. No speculation.",
  "key_takeaways": ["5 factual, actionable bullet points - each cites supporting evidence"]
}`
        }
      ],
      temperature: 0.3,
      max_tokens: 1200,
      response_format: { type: "json_object" },
    });
    return JSON.parse(completion.choices[0].message.content || "{}");
  } catch (error) {
    log("Executive summary generation error", { error: String(error) });
    return {
      executive_summary: `Today's intelligence covers ${ctx.counts.media} media reports, ${ctx.counts.threats} threat reports, and ${ctx.counts.advisories} advisories.`,
      key_takeaways: ["Review detailed findings below."],
    };
  }
}

// Generate recommended mitigations (uses gpt-4o)
async function generateMitigations(
  openai: OpenAI,
  ctx: AnalysisContext
): Promise<Array<{ priority: number; action: string; responsible_party: string; urgency: string; rationale: string; success_criteria: string; addresses_ttps: string[]; evidence_sources: string[] }>> {
  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: INTELLIGENCE_SYSTEM_PROMPT },
        {
          role: "user",
          content: `Generate actionable mitigations based on:

TTPs OBSERVED: ${ctx.ttpContext || "None"}
AVAILABLE MITIGATIONS: ${ctx.mitigationContext || "None"}
VULNERABILITIES: ${ctx.cveContext}

Generate JSON array of 3-5 prioritized mitigations:
[
  {
    "priority": 1,
    "action": "Specific, measurable action",
    "responsible_party": "IT Security/SOC/IT Ops/Management",
    "urgency": "IMMEDIATE/THIS_WEEK/THIS_MONTH/ONGOING",
    "rationale": "Direct link to observed threat",
    "success_criteria": "How to verify completion",
    "addresses_ttps": ["TTP1"],
    "evidence_sources": ["Report title"]
  }
]`
        }
      ],
      temperature: 0.3,
      max_tokens: 1500,
      response_format: { type: "json_object" },
    });
    const result = JSON.parse(completion.choices[0].message.content || "{}");
    return result.mitigations || result.recommended_mitigations || [];
  } catch (error) {
    log("Mitigations generation error", { error: String(error) });
    return [];
  }
}

// Build analysis context from summaries
function buildAnalysisContext(
  mediaSummaries: MediaSummary[],
  threatSummaries: ThreatSummary[],
  advisorySummaries: AdvisorySummary[],
  ransomwareActivity: RansomwareActivity[],
  observedTTPs: TTPObserved[],
  mitigationMap: Map<string, Array<{ id: string; name: string; description: string; mitreId: string }>>,
  targetingData: TargetingData,
): AnalysisContext {
  const totalRansomwareVictims = ransomwareActivity.reduce((sum, a) => sum + a.victimCount, 0);

  const mediaContext = compressMediaContext(mediaSummaries);
  const threatContext = compressThreatContext(threatSummaries);
  const advisoryContext = compressAdvisoryContext(advisorySummaries);

  const ransomwareContext = ransomwareActivity.length > 0
    ? ransomwareActivity.map(a => `- ${a.actor}: ${a.victimCount} victim(s) - ${a.victims.slice(0, 3).join(', ')}${a.victims.length > 3 ? '...' : ''}`).join("\n")
    : "No ransomware activity recorded.";

  const ttpContext = observedTTPs.filter(t => t.name).map(t =>
    `- ${t.mitreId || t.id}: ${t.name} [${t.source}]`
  ).join("\n");

  const mitigationLines: string[] = [];
  for (const [ttpId, mitigations] of mitigationMap) {
    const ttp = observedTTPs.find(t => t.id === ttpId);
    if (ttp && mitigations.length > 0) {
      mitigationLines.push(`For ${ttp.mitreId || ttp.name}:\n${mitigations.slice(0, 2).map(m => `  - ${m.name}: ${m.description.substring(0, 150)}...`).join('\n')}`);
    }
  }
  const mitigationContext = mitigationLines.join("\n\n");

  const sectorContext = targetingData.sectors.length > 0
    ? targetingData.sectors.map(s => `- ${s.name}: ${s.count} mention(s)`).join("\n")
    : "No specific sector targeting identified.";

  const geoContext = targetingData.geographies.length > 0
    ? targetingData.geographies.map(g => `- ${g.name} (${g.entityType}): ${g.count} mention(s)`).join("\n")
    : "No specific geographic targeting identified.";

  const allCVEs = [...new Set([
    ...mediaSummaries.flatMap(m => m.cves || []),
    ...threatSummaries.flatMap(t => t.cves || []),
    ...advisorySummaries.flatMap(a => a.cves || []),
  ])];
  const cveContext = allCVEs.length > 0 ? allCVEs.join(", ") : "No specific CVEs mentioned.";

  return {
    mediaContext,
    threatContext,
    advisoryContext,
    ransomwareContext,
    ttpContext,
    mitigationContext,
    sectorContext,
    geoContext,
    cveContext,
    counts: {
      media: mediaSummaries.length,
      threats: threatSummaries.length,
      advisories: advisorySummaries.length,
      ransomwareVictims: totalRansomwareVictims,
      ttps: observedTTPs.length,
      sectors: targetingData.sectors.length,
      geos: targetingData.geographies.length,
      cves: allCVEs.length,
    },
    ransomwareActivity,
    observedTTPs,
  };
}

// Parallel comprehensive analysis - runs all sections concurrently
async function runComprehensiveAnalysisParallel(
  openai: OpenAI,
  mediaSummaries: MediaSummary[],
  threatSummaries: ThreatSummary[],
  advisorySummaries: AdvisorySummary[],
  ransomwareActivity: RansomwareActivity[],
  observedTTPs: TTPObserved[],
  mitigationMap: Map<string, Array<{ id: string; name: string; description: string; mitreId: string }>>,
  targetingData: TargetingData,
): Promise<ComprehensiveAssessment> {
  const startTime = Date.now();

  // Build shared context once
  const ctx = buildAnalysisContext(
    mediaSummaries,
    threatSummaries,
    advisorySummaries,
    ransomwareActivity,
    observedTTPs,
    mitigationMap,
    targetingData,
  );

  log("Starting parallel section generation", {
    media: ctx.counts.media,
    threats: ctx.counts.threats,
    advisories: ctx.counts.advisories,
    ransomwareVictims: ctx.counts.ransomwareVictims,
    ttps: ctx.counts.ttps,
  });

  // Run all sections in parallel
  const [
    execSummaryResult,
    threatLandscapeResult,
    actorAnalysisResult,
    ransomwareAnalysisResult,
    vulnerabilityAnalysisResult,
    targetingAnalysisResult,
    mitigationsResult,
  ] = await Promise.all([
    generateExecutiveSummary(openai, ctx),
    generateThreatLandscape(openai, ctx),
    generateActorAnalysis(openai, ctx),
    generateRansomwareAnalysis(openai, ctx),
    generateVulnerabilityAnalysis(openai, ctx),
    generateTargetingAnalysis(openai, ctx),
    generateMitigations(openai, ctx),
  ]);

  const elapsed = Date.now() - startTime;
  log("Parallel section generation completed", { elapsedMs: elapsed });

  return {
    executive_summary: execSummaryResult.executive_summary || `Today's intelligence covers ${ctx.counts.media} media reports, ${ctx.counts.threats} threat reports, and ${ctx.counts.advisories} advisories.`,
    key_takeaways: execSummaryResult.key_takeaways || ["Review detailed findings below."],
    threat_landscape: {
      bluf: threatLandscapeResult.bluf,
      confidence: threatLandscapeResult.confidence,
      confidence_rationale: threatLandscapeResult.confidence_rationale,
      observations: threatLandscapeResult.observations,
      assessment: threatLandscapeResult.assessment || "Analysis not available.",
      key_themes: threatLandscapeResult.key_themes || [],
      limitations: threatLandscapeResult.limitations,
    },
    actor_analysis: {
      bluf: actorAnalysisResult.bluf,
      confidence: actorAnalysisResult.confidence,
      confidence_rationale: actorAnalysisResult.confidence_rationale,
      assessment: actorAnalysisResult.assessment || "No significant actor activity identified.",
      active_actors: actorAnalysisResult.active_actors || [],
    },
    ransomware_analysis: {
      bluf: ransomwareAnalysisResult.bluf,
      confidence: ransomwareAnalysisResult.confidence,
      confidence_rationale: ransomwareAnalysisResult.confidence_rationale,
      observations: ransomwareAnalysisResult.observations,
      assessment: ransomwareAnalysisResult.assessment || "No ransomware activity recorded.",
      total_victims: ransomwareAnalysisResult.total_victims || 0,
      active_groups: ransomwareAnalysisResult.active_groups || [],
    },
    vulnerability_analysis: {
      bluf: vulnerabilityAnalysisResult.bluf,
      confidence: vulnerabilityAnalysisResult.confidence,
      confidence_rationale: vulnerabilityAnalysisResult.confidence_rationale,
      assessment: vulnerabilityAnalysisResult.assessment || "No critical vulnerabilities highlighted.",
      critical_vulns: vulnerabilityAnalysisResult.critical_vulns || [],
    },
    targeting_analysis: {
      bluf: targetingAnalysisResult.bluf,
      confidence: targetingAnalysisResult.confidence,
      confidence_rationale: targetingAnalysisResult.confidence_rationale,
      assessment: targetingAnalysisResult.assessment || "No clear targeting patterns identified.",
      sectors_at_risk: targetingAnalysisResult.sectors_at_risk || [],
      geographic_focus: targetingAnalysisResult.geographic_focus || [],
    },
    recommended_mitigations: mitigationsResult || [],
  };
}

// === END PARALLEL SECTION GENERATION ===

// Legacy sequential comprehensive analysis (kept for fallback)
async function runComprehensiveAnalysis(
  openai: OpenAI,
  mediaSummaries: MediaSummary[],
  threatSummaries: ThreatSummary[],
  advisorySummaries: AdvisorySummary[],
  ransomwareActivity: RansomwareActivity[],
  observedTTPs: TTPObserved[],
  mitigationMap: Map<string, Array<{ id: string; name: string; description: string; mitreId: string }>>,
  targetingData: TargetingData,
): Promise<ComprehensiveAssessment> {
  // Build comprehensive evidence context
  const totalRansomwareVictims = ransomwareActivity.reduce((sum, a) => sum + a.victimCount, 0);

  // Use compressed context to reduce token usage while preserving key signals
  const mediaContext = compressMediaContext(mediaSummaries);
  const threatContext = compressThreatContext(threatSummaries);
  const advisoryContext = compressAdvisoryContext(advisorySummaries);

  // Ransomware activity
  const ransomwareContext = ransomwareActivity.length > 0
    ? ransomwareActivity.map(a => `- ${a.actor}: ${a.victimCount} victim(s) - ${a.victims.slice(0, 3).join(', ')}${a.victims.length > 3 ? '...' : ''}`).join("\n")
    : "No ransomware activity recorded.";

  // TTPs observed with source info - include all for comprehensive analysis
  const ttpContext = observedTTPs.filter(t => t.name).map(t => {
    return `- ${t.mitreId || t.id}: ${t.name} [${t.source}]`;
  }).join("\n");

  // Available mitigations for observed TTPs
  const mitigationContext: string[] = [];
  for (const [ttpId, mitigations] of mitigationMap) {
    const ttp = observedTTPs.find(t => t.id === ttpId);
    if (ttp && mitigations.length > 0) {
      mitigationContext.push(`For ${ttp.mitreId || ttp.name}:\n${mitigations.slice(0, 2).map(m => `  - ${m.name}: ${m.description.substring(0, 150)}...`).join('\n')}`);
    }
  }

  // Targeting data
  const sectorContext = targetingData.sectors.length > 0
    ? targetingData.sectors.map(s => `- ${s.name}: ${s.count} mention(s)`).join("\n")
    : "No specific sector targeting identified.";

  const geoContext = targetingData.geographies.length > 0
    ? targetingData.geographies.map(g => `- ${g.name} (${g.entityType}): ${g.count} mention(s)`).join("\n")
    : "No specific geographic targeting identified.";

  // Extract CVEs from all report types (media, threat, advisory)
  const allCVEs = [...new Set([
    ...mediaSummaries.flatMap(m => m.cves || []),
    ...threatSummaries.flatMap(t => t.cves || []),
    ...advisorySummaries.flatMap(a => a.cves || []),
  ])];
  const cveContext = allCVEs.length > 0 ? allCVEs.join(", ") : "No specific CVEs mentioned.";

  log("Comprehensive analysis input", {
    mediaCount: mediaSummaries.length,
    threatCount: threatSummaries.length,
    advisoryCount: advisorySummaries.length,
    ransomwareVictims: totalRansomwareVictims,
    ttpsObserved: observedTTPs.length,
    mitigationsAvailable: mitigationMap.size,
    sectorsTargeted: targetingData.sectors.length,
    geosTargeted: targetingData.geographies.length,
    cvesFound: allCVEs.length,
  });

  const completion = await openai.chat.completions.create({
    model: "gpt-4o",  // Using GPT-4o for better analysis
    messages: [
      {
        role: "system",
        content: `You are a senior cyber threat intelligence analyst creating a daily briefing for SMB security teams.

CRITICAL RULES FOR PROFESSIONAL INTELLIGENCE:
1. ONLY state facts that are directly evidenced in the source data
2. NEVER assume intent, attribution, or future actions without evidence
3. Use hedging language when confidence is not high:
   - "reportedly" / "allegedly" - for single-source claims
   - "multiple sources indicate" - for corroborated findings
   - "assessed with moderate confidence" - when inferring patterns
4. Clearly distinguish between:
   - OBSERVED: Directly stated in source material
   - INFERRED: Logical conclusion from multiple data points
   - REPORTED: Claimed by source but not independently verified

AVOID THE FOLLOWING (ANTI-BIAS):
- Attribution without evidence ("This is likely state-sponsored")
- Predictive statements ("Attackers will probably target...")
- Value judgments ("This is a sophisticated attack")
- Emotional language ("Devastating breach", "Alarming increase")
- Unsupported superlatives ("The most dangerous", "Unprecedented")
- Speculation about attacker motives or intentions

INSTEAD USE:
- "The attack used techniques consistent with [GROUP]" (not "attributed to")
- "Based on targeting patterns, [SECTOR] organizations should monitor..." (not "will be targeted")
- "The attack employed [TECHNIQUE]" (not "sophisticated")
- "X victims were reported" (not "devastating")
- "Activity increased by X% compared to [baseline]" (not "alarming increase")

CONFIDENCE LEVELS (include for each assessment section):
- HIGH: Multiple independent sources, direct technical evidence, or official attribution
- MODERATE: Single credible source with corroborating circumstantial evidence
- LOW: Single unverified source or requires significant inference

Your role is to SYNTHESIZE and ORGANIZE evidence, not to SPECULATE or PREDICT.`
      },
      {
        role: "user",
        content: `Analyze the following threat intelligence from the last 24 hours and create a comprehensive assessment.

=== MEDIA REPORTS (${mediaSummaries.length}) ===
${mediaContext || "No media reports."}

=== THREAT INTELLIGENCE REPORTS (${threatSummaries.length}) ===
${threatContext || "No threat reports."}

=== SECURITY ADVISORIES (${advisorySummaries.length}) ===
${advisoryContext || "No advisories."}

=== RANSOMWARE ACTIVITY (${totalRansomwareVictims} victims) ===
${ransomwareContext}

=== TTPs OBSERVED (${observedTTPs.length}) ===
${ttpContext || "No TTPs identified."}

=== AVAILABLE MITIGATIONS FOR OBSERVED TTPs ===
${mitigationContext.join("\n\n") || "No specific mitigations mapped."}

=== SECTOR TARGETING ===
${sectorContext}

=== GEOGRAPHIC TARGETING ===
${geoContext}

=== CVEs MENTIONED ===
${cveContext}

---
Generate a comprehensive intelligence assessment in this JSON format.
Each section MUST include a "confidence" field (HIGH/MODERATE/LOW) and follow BLUF (Bottom Line Up Front) format.

{
  "executive_summary": "BLUF: Start with the single most important finding. Then 2-3 additional sentences covering other critical findings. Be specific about actors, campaigns, or vulnerabilities. No speculation.",

  "key_takeaways": ["Exactly 5 bullet points - factual, actionable items. Each should cite what evidence supports it. Merge related points if needed to stay at 5."],

  "threat_landscape": {
    "bluf": "One sentence: the single most important threat landscape finding.",
    "confidence": "HIGH/MODERATE/LOW",
    "confidence_rationale": "Why this confidence level - how many sources, what type of evidence?",
    "observations": ["Factual observations from the source data - what was reported"],
    "assessment": "2-3 paragraph analysis connecting the observations. What patterns emerge? Avoid speculation.",
    "key_themes": ["Theme 1", "Theme 2", "Theme 3"],
    "limitations": ["What we don't know or couldn't determine from the data"]
  },

  "actor_analysis": {
    "bluf": "One sentence: most significant actor activity finding.",
    "confidence": "HIGH/MODERATE/LOW",
    "confidence_rationale": "Why this confidence level?",
    "assessment": "Analysis of threat actors mentioned. Who is active? What was REPORTED (not assumed)?",
    "active_actors": [
      {
        "name": "Actor name from reports",
        "activity_summary": "What this actor reportedly did based on evidence",
        "ttps_used": ["TTP1", "TTP2"],
        "source_count": 1
      }
    ]
  },

  "ransomware_analysis": {
    "bluf": "One sentence: key ransomware finding (e.g., 'X victims reported across Y groups').",
    "confidence": "HIGH/MODERATE/LOW",
    "confidence_rationale": "Why this confidence level?",
    "observations": ["Factual observations: victim counts, group activity, patterns seen"],
    "assessment": "1-2 paragraph analysis of what the data shows. Avoid speculation about motives.",
    "total_victims": 0,
    "active_groups": [
      {
        "name": "Group name",
        "victim_count": 0,
        "notable_victims": ["Victim 1", "Victim 2"]
      }
    ]
  },

  "vulnerability_analysis": {
    "bluf": "One sentence: most critical vulnerability finding.",
    "confidence": "HIGH/MODERATE/LOW",
    "confidence_rationale": "Why this confidence level?",
    "assessment": "Analysis of vulnerabilities mentioned. Include source type (advisory vs media vs threat report).",
    "critical_vulns": [
      {
        "cve": "CVE-XXXX-XXXXX",
        "context": "What was reported about this CVE - is exploitation observed or theoretical?",
        "urgency": "CRITICAL/HIGH/MEDIUM",
        "source_type": "advisory/threat_report/media"
      }
    ]
  },

  "targeting_analysis": {
    "bluf": "One sentence: key targeting pattern finding.",
    "confidence": "HIGH/MODERATE/LOW",
    "confidence_rationale": "Why this confidence level?",
    "assessment": "Analysis of targeting patterns observed in the data. What sectors/geographies appear in reports?",
    "sectors_at_risk": ["Sector 1", "Sector 2"],
    "geographic_focus": ["Region/Country 1", "Region/Country 2"]
  },

  "recommended_mitigations": [
    {
      "priority": 1,
      "action": "Specific, measurable action",
      "responsible_party": "IT Security/SOC/IT Ops/Management",
      "urgency": "IMMEDIATE/THIS_WEEK/THIS_MONTH/ONGOING",
      "rationale": "Direct link to observed threat - what evidence supports this?",
      "success_criteria": "How to verify this is done",
      "addresses_ttps": ["TTP1", "TTP2"],
      "evidence_sources": ["Specific report/advisory title"]
    }
  ]
}

CRITICAL REQUIREMENTS:
- Every section MUST have confidence level with rationale
- Start each section with BLUF (most important finding first)
- Base ALL assessments on actual evidence - cite source types
- Include "observations" (facts) separate from "assessment" (analysis)
- Include "limitations" where relevant - what couldn't be determined
- NO speculation about future attacks, attacker motives, or unconfirmed attribution
- Use "reportedly", "allegedly", "according to [source]" for single-source claims
- If data is sparse, say "Insufficient data to assess" rather than inventing details
- Be specific - name actors, CVEs, TTPs by their actual identifiers`
      }
    ],
    temperature: 0.4,
    max_tokens: 8000, // Increased for comprehensive analysis
    response_format: { type: "json_object" },
  });

  try {
    const content = completion.choices[0].message.content || "{}";
    log("Comprehensive analysis response", { length: content.length });
    const result = JSON.parse(content);

    // Validate essential fields
    if (!result.executive_summary) {
      throw new Error("Executive summary missing");
    }

    return {
      executive_summary: result.executive_summary,
      threat_landscape: result.threat_landscape || {
        assessment: "Insufficient data for comprehensive threat landscape assessment.",
        key_themes: [],
        threat_level_rationale: "Unable to determine threat level due to limited data.",
      },
      actor_analysis: result.actor_analysis || {
        assessment: "No significant actor activity identified.",
        active_actors: [],
      },
      ransomware_analysis: result.ransomware_analysis || {
        assessment: totalRansomwareVictims > 0
          ? `${totalRansomwareVictims} victims across ${ransomwareActivity.length} ransomware groups.`
          : "No ransomware activity recorded in this period.",
        total_victims: totalRansomwareVictims,
        active_groups: ransomwareActivity.slice(0, 10).map(a => ({
          name: a.actor,
          victim_count: a.victimCount,
          notable_victims: a.victims.slice(0, 3),
        })),
      },
      vulnerability_analysis: result.vulnerability_analysis || {
        assessment: "No critical vulnerabilities highlighted in today's intelligence.",
        critical_vulns: [],
      },
      targeting_analysis: result.targeting_analysis || {
        assessment: "No clear targeting patterns identified.",
        sectors_at_risk: [],
        geographic_focus: [],
      },
      recommended_mitigations: result.recommended_mitigations || [],
      key_takeaways: result.key_takeaways || ["Review individual reports for detailed findings."],
    };
  } catch (error) {
    log("Comprehensive analysis error", { error: String(error) });
    // Return minimal fallback
    return {
      executive_summary: `Today's intelligence review covers ${mediaSummaries.length} media reports, ${threatSummaries.length} threat reports, and ${advisorySummaries.length} advisories. ${totalRansomwareVictims > 0 ? `${totalRansomwareVictims} ransomware victims were reported across ${ransomwareActivity.length} groups.` : ''} Review the detailed evidence below.`,
      threat_landscape: {
        assessment: "Analysis generation failed. Review individual reports manually.",
        key_themes: [],
        threat_level_rationale: "Unable to assess.",
      },
      actor_analysis: {
        assessment: "Analysis generation failed.",
        active_actors: [],
      },
      vulnerability_analysis: {
        assessment: "Analysis generation failed.",
        critical_vulns: [],
      },
      targeting_analysis: {
        assessment: "Analysis generation failed.",
        sectors_at_risk: [],
        geographic_focus: [],
      },
      recommended_mitigations: [],
      key_takeaways: ["Review individual reports for detailed findings."],
    };
  }
}

// Legacy Orchestrator - kept for backwards compatibility
async function runOrchestrator(
  openai: OpenAI,
  mediaSummaries: MediaSummary[],
  threatSummaries: ThreatSummary[],
  advisorySummaries: AdvisorySummary[],
  ransomwareActivity: RansomwareActivity[],
): Promise<{ executive_summary: string; key_takeaways: string[] }> {
  const mediaSection = mediaSummaries.map(m => `- ${m.title}: ${m.summary}`).join("\n");
  const threatSection = threatSummaries.map(t => `- ${t.title}${t.threatActor ? ` (${t.threatActor})` : ""}: ${t.summary}`).join("\n");
  const advisorySection = advisorySummaries.map(a => `- ${a.title} [${a.severity}]: ${a.summary}`).join("\n");

  const totalRansomwareVictims = ransomwareActivity.reduce((sum, a) => sum + a.victimCount, 0);
  const ransomwareSection = ransomwareActivity.length > 0
    ? ransomwareActivity.map(a => `- ${a.actor}: ${a.victimCount} victim(s)`).join("\n")
    : "No ransomware activity recorded in the last 24 hours.";

  log("Orchestrator input", {
    mediaCount: mediaSummaries.length,
    threatCount: threatSummaries.length,
    advisoryCount: advisorySummaries.length,
    ransomwareActors: ransomwareActivity.length,
    totalRansomwareVictims,
  });

  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      {
        role: "system",
        content: "You are a threat intelligence analyst providing factual summaries. Be concise and evidence-based. Always respond with valid JSON."
      },
      {
        role: "user",
        content: `Based on the following intelligence from the last 24 hours, create a factual briefing.

## Media Coverage (${mediaSummaries.length} articles):
${mediaSection || "No significant media coverage in the last 24 hours."}

## Threat Reports (${threatSummaries.length} reports):
${threatSection || "No new threat reports in the last 24 hours."}

## Security Advisories (${advisorySummaries.length} advisories):
${advisorySection || "No new advisories in the last 24 hours."}

## Ransomware Activity (${totalRansomwareVictims} victims across ${ransomwareActivity.length} groups):
${ransomwareSection}

Generate a briefing in this exact JSON format:
{
  "executive_summary": "Write a brief 3-5 sentence summary of key findings.",
  "key_takeaways": ["5 bullet points with key facts"]
}

Keep the executive_summary under 100 words.`
      }
    ],
    temperature: 0.3,
    max_tokens: 1000,
    response_format: { type: "json_object" },
  });

  try {
    const content = completion.choices[0].message.content || "{}";
    const result = JSON.parse(content);
    return {
      executive_summary: result.executive_summary || "Summary unavailable.",
      key_takeaways: result.key_takeaways || [],
    };
  } catch (error) {
    log("Orchestrator error", { error: String(error) });
    return {
      executive_summary: `Today's review covers ${mediaSummaries.length} media reports, ${threatSummaries.length} threat reports, and ${advisorySummaries.length} advisories.`,
      key_takeaways: ["Review detailed findings below."],
    };
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  const startTime = Date.now();

  const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
  const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  const openaiKey = Deno.env.get("OPENAI_API_KEY") ?? "";

  const supabase = createClient(supabaseUrl, supabaseServiceKey, {
    auth: { persistSession: false },
  });

  try {
    log("Function started");

    // Clean up expired entity cache entries (24-hour TTL) - runs asynchronously
    supabase.rpc('cleanup_old_entity_cache').then(({ data, error }) => {
      if (error) {
        log("Entity cache cleanup error", { error: error.message });
      } else if (data && data > 0) {
        log("Entity cache cleanup completed", { deletedEntries: data });
      }
    }).catch(err => {
      log("Entity cache cleanup failed", { error: String(err) });
    });

    // Get cron secret from database (app_config table) or env var as fallback
    let cronSecretKey = Deno.env.get("CRON_SECRET_KEY") ?? "";
    if (!cronSecretKey) {
      const { data: configData } = await supabase
        .from("app_config")
        .select("value")
        .eq("key", "cron_secret_key")
        .maybeSingle();
      cronSecretKey = configData?.value ?? "";
    }

    // Check for scheduled/cron mode first
    let isScheduledMode = false;
    let userId: string | null = null;

    // Check for cron secret key in Authorization header or query param
    const authHeader = req.headers.get("Authorization");
    const url = new URL(req.url);
    const scheduledSecret = url.searchParams.get("secret") || authHeader?.replace("Bearer ", "");

    if (scheduledSecret && cronSecretKey && scheduledSecret === cronSecretKey) {
      log("Scheduled mode activated via secret key");
      isScheduledMode = true;
      userId = null; // No user for scheduled runs - generated_by will be null
    } else {
      // Regular user authentication flow
      if (!authHeader) {
        log("No auth header found");
        return new Response(JSON.stringify({ error: "No authorization header" }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 401,
        });
      }

      const token = authHeader.replace("Bearer ", "");
      log("Token received", { tokenLength: token.length, tokenPrefix: token.substring(0, 20) });

      const { data: userData, error: userError } = await supabase.auth.getUser(token);
      if (userError) {
        log("Auth error", { error: userError.message });
        return new Response(JSON.stringify({ error: "Authentication failed", details: userError.message }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 401,
        });
      }
      if (!userData.user) {
        log("No user data");
        return new Response(JSON.stringify({ error: "No user found" }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 401,
        });
      }

      userId = userData.user.id;
      log("User authenticated", { userId });

      // Check if user is admin
      const { data: roleData, error: roleError } = await supabase
        .from("user_roles")
        .select("role")
        .eq("user_id", userId)
        .maybeSingle();

      if (roleError) {
        log("Role query error", { error: roleError.message });
        return new Response(JSON.stringify({
          error: "Role check failed",
          message: roleError.message
        }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 500,
        });
      }

      if (roleData?.role !== "admin") {
        return new Response(JSON.stringify({
          error: "Admin access required",
          message: "Only administrators can generate Intel Summaries"
        }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 403,
        });
      }
      log("Admin access verified");
    }

    // Check if report already exists for today
    const today = new Date().toISOString().split("T")[0];
    const { data: existing } = await supabase
      .from("intel_summaries")
      .select("id, created_at")
      .eq("report_date", today)
      .maybeSingle();

    // For scheduled mode: regenerate if last summary is more than 2.5 hours old
    // For manual mode: skip if summary exists
    if (existing) {
      const lastGenerated = new Date(existing.created_at);
      const hoursSinceLastGen = (Date.now() - lastGenerated.getTime()) / (1000 * 60 * 60);

      if (isScheduledMode && hoursSinceLastGen >= 2.5) {
        // Delete old summary to regenerate
        log("Scheduled regeneration - deleting old summary", {
          hoursOld: hoursSinceLastGen.toFixed(1),
          oldId: existing.id
        });
        await supabase.from("intel_summaries").delete().eq("id", existing.id);
      } else if (!isScheduledMode) {
        // Manual mode - return existing
        const { data: existingReport } = await supabase
          .from("intel_summaries")
          .select("*")
          .eq("id", existing.id)
          .single();

        return new Response(JSON.stringify({
          message: "Report already exists for today",
          report: existingReport,
        }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 200,
        });
      } else {
        // Scheduled mode but too soon
        log("Scheduled mode - too soon to regenerate", {
          hoursOld: hoursSinceLastGen.toFixed(1)
        });
        return new Response(JSON.stringify({
          message: "Report was generated recently",
          hoursAgo: hoursSinceLastGen.toFixed(1),
        }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 200,
        });
      }
    }

    // 4. Validate OpenAI key
    if (!openaiKey) {
      throw new Error("OPENAI_API_KEY not configured");
    }

    const openai = new OpenAI({ apiKey: openaiKey });
    log("OpenAI client initialized");

    // Generate summary ID upfront for progress tracking
    const summaryId = crypto.randomUUID();
    const completedStages: string[] = [];
    log("Summary ID generated for tracking", { summaryId: summaryId.substring(0, 8) });

    // Initialize progress tracking
    await initializeProgress(supabaseUrl, supabaseServiceKey, summaryId);

    // 5. Fetch data from intel schema directly
    // Using 24 hours for timely daily briefing
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    log("Fetching data from intel schema...", { since: yesterday });
    await updateProgress(supabaseUrl, supabaseServiceKey, summaryId, 'fetching_reports', completedStages);

    let mediaReports: Array<{ id: string; name: string; description: string; date: string; externalReferences?: Array<{ url: string }> }> = [];
    let threatReports: Array<{ id: string; name: string; description: string; date: string; source?: string; externalReferences?: Array<{ url: string; sourceName: string }> }> = [];
    let advisories: Array<{ id: string; name: string; description: string; date: string; source?: string; externalReferences?: Array<{ url: string }> }> = [];
    let ransomwareVictims: Array<{ id: string; name: string; threatGroups?: Array<{ id: string; name: string }> }> = [];

    try {
      // Fetch all report types in parallel
      // Reasonable limits to prevent timeout while still being comprehensive
      const [mediaResult, threatResult, advisoryResult, ransomwareResult] = await Promise.all([
        fetchReportsByType(supabaseUrl, supabaseServiceKey, "media-report", 75, yesterday),
        fetchReportsByType(supabaseUrl, supabaseServiceKey, "threat-report", 75, yesterday),
        fetchReportsByType(supabaseUrl, supabaseServiceKey, "threat-advisory", 75, yesterday),
        fetchRansomwareVictims(supabaseUrl, supabaseServiceKey, 300, yesterday),
      ]);

      mediaReports = mediaResult;
      threatReports = threatResult;
      advisories = advisoryResult;
      ransomwareVictims = ransomwareResult;
    } catch (fetchError) {
      log("Data fetch error", { error: String(fetchError) });
      throw new Error(`Failed to fetch data from intel schema: ${fetchError}`);
    }

    log("Data fetched", {
      media: mediaReports.length,
      threats: threatReports.length,
      advisories: advisories.length,
      ransomwareVictims: ransomwareVictims.length,
    });
    completedStages.push('fetching_reports');

    // 6. Process ransomware activity
    const ransomwareActivity = processRansomwareActivity(ransomwareVictims);
    log("Ransomware activity processed", {
      activeGroups: ransomwareActivity.length,
      totalVictims: ransomwareActivity.reduce((sum, a) => sum + a.victimCount, 0),
    });

    // 7. Run agents
    log("Running agents...");
    await updateProgress(supabaseUrl, supabaseServiceKey, summaryId, 'media_agent', completedStages);

    // Run media agent (sequential due to entity fetching)
    const mediaSummaries = await runMediaAgent(openai, supabaseUrl, supabaseServiceKey, mediaReports);
    log("Media agent completed", { count: mediaSummaries.length });
    completedStages.push('media_agent');
    await updateProgress(supabaseUrl, supabaseServiceKey, summaryId, 'threat_agent', completedStages);

    // Run threat and advisory agents in parallel
    const [threatSummaries, advisorySummaries] = await Promise.all([
      runThreatAgent(openai, supabaseUrl, supabaseServiceKey, threatReports),
      runAdvisoryAgent(openai, supabaseUrl, supabaseServiceKey, advisories),
    ]);
    completedStages.push('threat_agent', 'advisory_agent');

    log("All agents completed", {
      media: mediaSummaries.length,
      threats: threatSummaries.length,
      advisories: advisorySummaries.length,
    });
    await updateProgress(supabaseUrl, supabaseServiceKey, summaryId, 'entity_aggregation', completedStages);

    // Flush entity cache buffer to database (batch write)
    await flushEntityCache(supabaseUrl, supabaseServiceKey);
    log("Entity cache flushed to database");

    // Build entity mentions cache from summaries for targeting aggregation
    const entityMentionsCache = new Map<string, {
      sectors: Array<{ id: string; name: string }>;
      geographies: Array<{ id: string; name: string; entityType: string }>;
    }>();

    for (const media of mediaSummaries) {
      if (media.reportId && (media.sectorDetails || media.geographyDetails)) {
        entityMentionsCache.set(media.reportId, {
          sectors: media.sectorDetails || [],
          geographies: media.geographyDetails || [],
        });
      }
    }

    for (const threat of threatSummaries) {
      if (threat.reportId && (threat.sectorDetails || threat.geographyDetails)) {
        entityMentionsCache.set(threat.reportId, {
          sectors: threat.sectorDetails || [],
          geographies: threat.geographyDetails || [],
        });
      }
    }

    for (const advisory of advisorySummaries) {
      if (advisory.reportId && (advisory.sectorDetails || advisory.geographyDetails)) {
        entityMentionsCache.set(advisory.reportId, {
          sectors: advisory.sectorDetails || [],
          geographies: advisory.geographyDetails || [],
        });
      }
    }

    log("Entity mentions cache built", { entries: entityMentionsCache.size });

    // Aggregate targeting mentions across all reports
    const targetingData = aggregateTargetingMentions(
      mediaSummaries,
      threatSummaries,
      advisorySummaries,
      entityMentionsCache
    );

    log("Targeting data aggregated", {
      sectors: targetingData.sectors.length,
      geographies: targetingData.geographies.length,
    });

    // 8. Enhanced briefing: Collect TTPs and compute mitigations
    log("Processing enhanced briefing data...");

    // Collect all observed TTPs from reports (highest confidence)
    const observedTTPsMap = new Map<string, TTPObserved>();
    const allEvidence = new Map<string, Array<{ type: string; id: string; name: string; linkPath: string }>>();
    const activeActorsMap = new Map<string, ActiveActor>();

    // Process media summaries for TTPs
    for (const media of mediaSummaries) {
      if (media.reportId) {
        allEvidence.set(media.reportId, [{
          type: 'media-report',
          id: media.reportId,
          name: media.title,
          linkPath: `/threat-reports/${media.reportId}`,
        }]);
      }
      for (const ttpId of media.ttps || []) {
        const existing = observedTTPsMap.get(ttpId);
        if (existing) {
          if (media.reportId && !existing.evidenceIds.includes(media.reportId)) {
            existing.evidenceIds.push(media.reportId);
          }
        } else {
          observedTTPsMap.set(ttpId, {
            id: ttpId,
            name: '', // Will be filled later
            mitreId: '',
            source: 'observed',
            evidenceIds: media.reportId ? [media.reportId] : [],
          });
        }
      }
    }

    // Process threat summaries
    for (const threat of threatSummaries) {
      if (threat.reportId) {
        allEvidence.set(threat.reportId, [{
          type: 'threat-report',
          id: threat.reportId,
          name: threat.title,
          linkPath: `/threat-reports/${threat.reportId}`,
        }]);
      }
      for (const ttpId of threat.ttps || []) {
        const existing = observedTTPsMap.get(ttpId);
        if (existing) {
          if (threat.reportId && !existing.evidenceIds.includes(threat.reportId)) {
            existing.evidenceIds.push(threat.reportId);
          }
        } else {
          observedTTPsMap.set(ttpId, {
            id: ttpId,
            name: '',
            mitreId: '',
            source: 'observed',
            evidenceIds: threat.reportId ? [threat.reportId] : [],
          });
        }
      }
    }

    // Process advisory summaries
    for (const advisory of advisorySummaries) {
      if (advisory.reportId) {
        allEvidence.set(advisory.reportId, [{
          type: 'advisory',
          id: advisory.reportId,
          name: advisory.title,
          linkPath: `/advisories/${advisory.reportId}`,
        }]);
      }
      for (const ttpId of advisory.ttps || []) {
        const existing = observedTTPsMap.get(ttpId);
        if (existing) {
          if (advisory.reportId && !existing.evidenceIds.includes(advisory.reportId)) {
            existing.evidenceIds.push(advisory.reportId);
          }
        } else {
          observedTTPsMap.set(ttpId, {
            id: ttpId,
            name: '',
            mitreId: '',
            source: 'observed',
            evidenceIds: advisory.reportId ? [advisory.reportId] : [],
          });
        }
      }
    }

    // Collect active actors from ransomware activity
    for (const activity of ransomwareActivity) {
      if (activity.actorId) {
        activeActorsMap.set(activity.actorId, {
          id: activity.actorId,
          name: activity.actor,
          linkPath: `/intrusion-sets/${activity.actorId}`,
          source: 'ransomware',
        });
      }
    }

    log("Observed TTPs collected", { count: observedTTPsMap.size });
    log("Active actors collected", { count: activeActorsMap.size });

    // Fetch TTP details and inferred TTPs from active actors
    const observedTTPIds = [...observedTTPsMap.keys()];

    // Fetch details for observed TTPs
    if (observedTTPIds.length > 0) {
      try {
        const ttpQuery = `select=internal_id,name,data&entity_type=eq.Attack-Pattern&internal_id=in.(${observedTTPIds.join(',')})`;
        const ttpEntities = await queryIntelSchema(supabaseUrl, supabaseServiceKey, "object_current", ttpQuery) as any[];

        for (const entity of ttpEntities) {
          const existing = observedTTPsMap.get(entity.internal_id);
          if (existing) {
            existing.name = entity.name;
            existing.mitreId = entity.data?.x_mitre_id || '';
          }
        }
      } catch (error) {
        log("TTP details fetch error", { error: String(error) });
      }
    }

    // Fetch inferred TTPs from active threat actors (medium confidence)
    for (const actor of activeActorsMap.values()) {
      try {
        const actorTTPs = await fetchActorTTPs(supabaseUrl, supabaseServiceKey, actor.id);
        for (const ttp of actorTTPs) { // Include all TTPs per actor
          if (!observedTTPsMap.has(ttp.id)) {
            observedTTPsMap.set(ttp.id, {
              id: ttp.id,
              name: ttp.name,
              mitreId: ttp.mitreId,
              source: 'inferred',
              evidenceIds: [actor.id], // Actor is the evidence
            });
            // Add actor as evidence
            if (!allEvidence.has(actor.id)) {
              allEvidence.set(actor.id, [{
                type: 'threat-actor',
                id: actor.id,
                name: actor.name,
                linkPath: actor.linkPath,
              }]);
            }
          }
        }
      } catch (error) {
        log("Actor TTP fetch error", { actorId: actor.id, error: String(error) });
      }
    }

    const allTTPIds = [...observedTTPsMap.keys()];
    log("All TTPs collected", { observed: observedTTPIds.length, total: allTTPIds.length });

    // Fetch mitigations for all TTPs
    const mitigationMap = await fetchMitigationsForTTPs(supabaseUrl, supabaseServiceKey, allTTPIds);
    log("Mitigations fetched", { ttpsCovered: mitigationMap.size });

    // Score and rank recommended actions
    const observedTTPs = [...observedTTPsMap.values()];
    const recommendedActions = scoreAndRankActions(observedTTPs, mitigationMap, allEvidence);
    log("Recommended actions computed", { count: recommendedActions.length });

    // Calculate threat posture
    const threatPosture = calculateThreatPosture(ransomwareActivity, advisorySummaries, threatSummaries, mediaSummaries);
    log("Threat posture calculated", { level: threatPosture.level });

    // Prepare active actors list
    const activeActorsToday = [...activeActorsMap.values()];
    completedStages.push('entity_aggregation');

    // 9. Run comprehensive AI analysis (parallel for performance)
    await updateProgress(supabaseUrl, supabaseServiceKey, summaryId, 'comprehensive_analysis', completedStages);
    log("Running comprehensive AI analysis (parallel mode)...");
    const comprehensiveAnalysis = await runComprehensiveAnalysisParallel(
      openai,
      mediaSummaries,
      threatSummaries,
      advisorySummaries,
      ransomwareActivity,
      observedTTPs,
      mitigationMap,
      targetingData
    );
    completedStages.push('comprehensive_analysis');
    log("Comprehensive analysis completed", {
      summaryLength: comprehensiveAnalysis.executive_summary?.length,
      hasLandscape: !!comprehensiveAnalysis.threat_landscape?.assessment,
      hasActors: comprehensiveAnalysis.actor_analysis?.active_actors?.length || 0,
      hasVulns: comprehensiveAnalysis.vulnerability_analysis?.critical_vulns?.length || 0,
      hasMitigations: comprehensiveAnalysis.recommended_mitigations?.length || 0,
    });

    // Build analyst brief from the threat landscape assessment (first paragraph)
    const analystBrief = comprehensiveAnalysis.threat_landscape?.assessment?.split('\n\n')[0] ||
      `Threat posture is ${threatPosture.level.toLowerCase()}. ${threatPosture.rationale}`;

    // Convert AI-generated mitigations to our existing format for backwards compatibility
    const aiRecommendedActions: RecommendedAction[] = (comprehensiveAnalysis.recommended_mitigations || []).map((m, idx) => ({
      action: m.action,
      confidence: idx === 0 ? 'HIGH' : 'MED' as const,
      why: m.rationale,
      score: 10 - idx, // Higher score for higher priority
      evidence: m.evidence_sources.slice(0, 3).map(s => ({
        type: 'report',
        id: '',
        name: s,
        linkPath: '',
      })),
      mitigates: m.addresses_ttps.map(t => ({
        ttpId: '',
        ttpName: t,
      })),
    }));

    // Merge AI recommendations with algorithm-based ones (AI takes priority)
    const finalRecommendedActions = aiRecommendedActions.length > 0
      ? aiRecommendedActions
      : recommendedActions;

    // Build key risks from AI analysis
    const keyRisks: KeyRisk[] = [];

    // Add actor-based risks from AI analysis
    if (comprehensiveAnalysis.actor_analysis?.active_actors?.length > 0) {
      const topActors = comprehensiveAnalysis.actor_analysis.active_actors.slice(0, 2);
      for (const actor of topActors) {
        if (keyRisks.length < 3) {
          keyRisks.push({
            risk: `${actor.name}: ${actor.activity_summary}`,
            evidence: actor.ttps_used.slice(0, 3).map(ttp => ({
              type: 'ttp',
              id: '',
              name: ttp,
              linkPath: '',
            })),
          });
        }
      }
    }

    // Add vulnerability-based risks from AI analysis
    if (comprehensiveAnalysis.vulnerability_analysis?.critical_vulns?.length > 0) {
      const topVulns = comprehensiveAnalysis.vulnerability_analysis.critical_vulns.slice(0, 2);
      for (const vuln of topVulns) {
        if (keyRisks.length < 3) {
          keyRisks.push({
            risk: `${vuln.cve}: ${vuln.context}`,
            evidence: [{
              type: 'vulnerability',
              id: vuln.cve,
              name: vuln.cve,
              linkPath: `/vulnerabilities?search=${encodeURIComponent(vuln.cve)}`,
            }],
          });
        }
      }
    }

    // Fallback: add ransomware risk if no AI-generated risks
    if (keyRisks.length === 0) {
      const totalVictims = ransomwareActivity.reduce((s, a) => s + a.victimCount, 0);
      if (totalVictims > 0) {
        const topGroups = ransomwareActivity.slice(0, 3);
        keyRisks.push({
          risk: `Active ransomware groups: ${topGroups.map(g => g.actor).join(', ')} claimed ${totalVictims} victim${totalVictims !== 1 ? 's' : ''} today`,
          evidence: topGroups.map(g => ({
            type: 'ransomware-group',
            id: g.actorId || '',
            name: g.actor,
            linkPath: g.actorId ? `/intrusion-sets/${g.actorId}` : '',
          })).filter(e => e.id),
        });
      }
    }

    log("Key risks generated", { count: keyRisks.length });

    // 9. Calculate generation time
    const generationTime = Date.now() - startTime;

    // 10. Store in database
    await updateProgress(supabaseUrl, supabaseServiceKey, summaryId, 'saving_results', completedStages);
    const { data: newReport, error: insertError } = await supabase
      .from("intel_summaries")
      .insert({
        id: summaryId, // Use pre-generated ID for progress tracking continuity
        generated_by: userId,
        report_date: today,
        executive_summary: comprehensiveAnalysis.executive_summary,
        key_takeaways: comprehensiveAnalysis.key_takeaways,
        media_summaries: mediaSummaries,
        threat_summaries: threatSummaries,
        advisory_summaries: advisorySummaries,
        ransomware_activity: ransomwareActivity,
        source_counts: {
          media: mediaSummaries.length,
          threats: threatSummaries.length,
          advisories: advisorySummaries.length,
          ransomwareVictims: ransomwareVictims.length,
          ransomwareGroups: ransomwareActivity.length,
        },
        generation_time_ms: generationTime,
        // Enhanced briefing fields
        threat_posture: threatPosture,
        analyst_brief: analystBrief,
        org_relevance: "General SMB security posture", // Placeholder for org-specific relevance
        key_risks: keyRisks,
        recommended_actions: finalRecommendedActions,
        ttps_observed: observedTTPs.filter(t => t.name), // Include all TTPs with names
        active_actors_today: activeActorsToday,
        // Targeting data
        targeting_sectors: targetingData.sectors,
        targeting_geographies: targetingData.geographies,
        // Comprehensive AI analysis
        threat_landscape: comprehensiveAnalysis.threat_landscape,
        actor_analysis: comprehensiveAnalysis.actor_analysis,
        ransomware_analysis: comprehensiveAnalysis.ransomware_analysis,
        vulnerability_analysis: comprehensiveAnalysis.vulnerability_analysis,
        targeting_analysis: comprehensiveAnalysis.targeting_analysis,
      })
      .select()
      .single();

    if (insertError) {
      // Update progress with error
      await updateProgress(supabaseUrl, supabaseServiceKey, summaryId, 'saving_results', completedStages, insertError.message);
      throw new Error(`Database insert failed: ${insertError.message}`);
    }

    // Mark generation as completed and cleanup progress tracking
    completedStages.push('saving_results');
    await updateProgress(supabaseUrl, supabaseServiceKey, summaryId, 'completed', completedStages);
    await cleanupProgress(supabaseUrl, supabaseServiceKey, summaryId);

    log("Report saved", { id: newReport.id, time_ms: generationTime });

    // Save generation metrics (Phase 6)
    await saveMetrics(supabaseUrl, supabaseServiceKey, {
      summaryId,
      stageTimings: {
        total: generationTime,
      },
      reportsStats: {
        mediaFetched: mediaReports.length,
        threatsFetched: threatReports.length,
        advisoriesFetched: advisories.length,
        ransomwareVictims: ransomwareVictims.length,
        mediaProcessed: mediaSummaries.length,
        threatsProcessed: threatSummaries.length,
        advisoriesProcessed: advisorySummaries.length,
      },
      cacheStats: {
        cacheHits,
        cacheMisses,
        entriesWritten: entityCacheBuffer.size,
      },
    });

    // Reset cache stats for next run
    cacheHits = 0;
    cacheMisses = 0;

    return new Response(JSON.stringify({
      message: "Report generated successfully",
      report: newReport,
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 200,
    });

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    log("ERROR", { message: errorMessage });

    return new Response(JSON.stringify({ error: errorMessage }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 500,
    });
  }
});
