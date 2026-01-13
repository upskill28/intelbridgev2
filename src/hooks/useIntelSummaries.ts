import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "./useAuth";
import { toast } from "sonner";
import { useEffect, useState, useCallback, useMemo } from "react";

// Cast supabase to any to bypass strict type checking for tables not in generated types
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const db = supabase as any;

export interface MediaSummary {
  title: string;
  summary: string;
  sourceUrl: string;
  date: string;
  reportId?: string;
  // Entity mentions
  threatActors?: string[];
  geographies?: string[];
  sectors?: string[];
  cves?: string[];
  ttps?: string[];
}

export interface ThreatSummary {
  title: string;
  summary: string;
  sourceUrl: string;
  date: string;
  reportId?: string;
  threatActor: string | null;
  severity: string;
  ttps?: string[];
}

export interface AdvisorySummary {
  title: string;
  summary: string;
  sourceUrl: string;
  date: string;
  reportId?: string;
  severity: string;
  source: string;
  ttps?: string[];
}

export interface RansomwareActivity {
  actor: string;
  actorId?: string;
  victimCount: number;
  victims: string[];
}

export interface TTPObserved {
  id: string;
  name: string;
  mitreId: string;
  source: 'observed' | 'inferred';
  evidenceIds: string[];
}

export interface ActiveActor {
  id: string;
  name: string;
  linkPath: string;
  source: 'report' | 'ransomware' | 'advisory';
}

export interface KeyRisk {
  risk: string;
  evidence: Array<{ type: string; id: string; name: string; linkPath: string }>;
}

export interface RecommendedAction {
  action: string;
  confidence: 'HIGH' | 'MED';
  why: string;
  score: number;
  evidence: Array<{ type: string; id: string; name: string; linkPath: string }>;
  mitigates: Array<{ ttpId: string; ttpName: string; mitreId?: string }>;
  // New actionable framework fields
  responsible_party?: 'IT Security' | 'SOC' | 'IT Ops' | 'Management' | 'All Staff' | string;
  urgency?: 'IMMEDIATE' | 'THIS_WEEK' | 'THIS_MONTH' | 'ONGOING' | string;
  success_criteria?: string;
}

export interface ThreatPosture {
  level: 'Elevated' | 'Moderate' | 'Low';
  rationale: string;
}

export interface TargetingEvidence {
  type: string; // 'media-report', 'threat-report', 'advisory'
  id: string;
  name: string;
  linkPath: string;
  date: string;
}

export interface TargetingMention {
  id: string;
  name: string;
  entityType: string; // 'Sector', 'Country', 'Region', 'City'
  count: number;
  confidence: 'HIGH' | 'MED'; // HIGH = directly extracted, MED = inferred
  evidence: TargetingEvidence[];
}

// Confidence level type for professional intelligence assessments
export type ConfidenceLevel = 'HIGH' | 'MODERATE' | 'LOW';

// AI-generated comprehensive analysis interfaces with confidence tracking
export interface ThreatLandscape {
  bluf?: string;
  confidence?: ConfidenceLevel;
  confidence_rationale?: string;
  observations?: string[];
  assessment: string;
  key_themes: string[];
  threat_level_rationale?: string;
  limitations?: string[];
}

export interface ActiveActorAnalysis {
  name: string;
  activity_summary: string;
  ttps_used: string[];
  source_count?: number;
}

export interface ActorAnalysis {
  bluf?: string;
  confidence?: ConfidenceLevel;
  confidence_rationale?: string;
  assessment: string;
  active_actors: ActiveActorAnalysis[];
}

export interface RansomwareGroupAnalysis {
  name: string;
  victim_count: number;
  notable_victims?: string[];
}

export interface RansomwareAnalysis {
  bluf?: string;
  confidence?: ConfidenceLevel;
  confidence_rationale?: string;
  observations?: string[];
  assessment: string;
  total_victims: number;
  active_groups: RansomwareGroupAnalysis[];
}

export interface CriticalVuln {
  cve: string;
  context: string;
  urgency: string;
  source_type?: string;
}

export interface VulnerabilityAnalysis {
  bluf?: string;
  confidence?: ConfidenceLevel;
  confidence_rationale?: string;
  assessment: string;
  critical_vulns: CriticalVuln[];
}

export interface TargetingAnalysis {
  bluf?: string;
  confidence?: ConfidenceLevel;
  confidence_rationale?: string;
  assessment: string;
  sectors_at_risk: string[];
  geographic_focus: string[];
}

// Generation progress tracking interface
export type GenerationStage =
  | 'initializing'
  | 'fetching_reports'
  | 'media_agent'
  | 'threat_agent'
  | 'advisory_agent'
  | 'entity_aggregation'
  | 'comprehensive_analysis'
  | 'saving_results'
  | 'completed';

export interface GenerationProgress {
  summary_id: string;
  started_at: string;
  current_stage: GenerationStage;
  stages_completed: GenerationStage[];
  estimated_completion?: string;
  error?: string;
}

// Stage labels for UI display
export const STAGE_LABELS: Record<GenerationStage, string> = {
  initializing: 'Initializing...',
  fetching_reports: 'Fetching threat reports...',
  media_agent: 'Analyzing media coverage...',
  threat_agent: 'Processing threat intelligence...',
  advisory_agent: 'Reviewing security advisories...',
  entity_aggregation: 'Aggregating entities & TTPs...',
  comprehensive_analysis: 'Running AI analysis...',
  saving_results: 'Saving report...',
  completed: 'Complete!',
};

export interface IntelSummary {
  id: string;
  created_at: string;
  generated_by: string;
  report_date: string;
  executive_summary: string;
  key_takeaways: string[];
  media_summaries: MediaSummary[];
  threat_summaries: ThreatSummary[];
  advisory_summaries: AdvisorySummary[];
  ransomware_activity: RansomwareActivity[];
  source_counts: {
    media: number;
    threats: number;
    advisories: number;
    ransomwareVictims: number;
    ransomwareGroups: number;
  };
  token_usage?: {
    input: number;
    output: number;
    cost: number;
  };
  generation_time_ms: number;
  // Enhanced briefing fields
  threat_posture?: ThreatPosture;
  analyst_brief?: string;
  org_relevance?: string;
  key_risks?: KeyRisk[];
  recommended_actions?: RecommendedAction[];
  ttps_observed?: TTPObserved[];
  active_actors_today?: ActiveActor[];
  // Targeting data
  targeting_sectors?: TargetingMention[];
  targeting_geographies?: TargetingMention[];
  // AI-generated comprehensive analysis
  threat_landscape?: ThreatLandscape;
  actor_analysis?: ActorAnalysis;
  ransomware_analysis?: RansomwareAnalysis;
  vulnerability_analysis?: VulnerabilityAnalysis;
  targeting_analysis?: TargetingAnalysis;
}

interface UseIntelSummariesOptions {
  enabled?: boolean;
}

export const useIntelSummaries = (options: UseIntelSummariesOptions = {}) => {
  const { session } = useAuth();
  const queryClient = useQueryClient();
  const { enabled = true } = options;

  // Fetch list of all summaries
  const summariesQuery = useQuery({
    queryKey: ["intel-summaries"],
    queryFn: async () => {
      const { data, error } = await db
        .from("intel_summaries")
        .select("*")
        .order("report_date", { ascending: false });

      if (error) throw error;
      return data as IntelSummary[];
    },
    enabled: !!session && enabled,
  });

  // Fetch today's summary specifically
  const todaySummaryQuery = useQuery({
    queryKey: ["intel-summary-today"],
    queryFn: async () => {
      const today = new Date().toISOString().split("T")[0];
      const { data, error } = await db
        .from("intel_summaries")
        .select("*")
        .eq("report_date", today)
        .maybeSingle();

      if (error) throw error;
      return data as IntelSummary | null;
    },
    enabled: !!session && enabled,
  });

  // Generate new summary mutation
  const generateMutation = useMutation({
    mutationFn: async () => {
      if (!session) {
        throw new Error("Not authenticated");
      }

      // supabase.functions.invoke automatically uses the current session's auth
      const { data, error } = await supabase.functions.invoke("generate-intel-summary", {
        body: {},
      });

      if (error) throw error;

      if (data.error) {
        throw new Error(data.error);
      }

      return data.report as IntelSummary;
    },
    onSuccess: (data) => {
      toast.success("Intel summary generated successfully!");
      queryClient.invalidateQueries({ queryKey: ["intel-summaries"] });
      queryClient.invalidateQueries({ queryKey: ["intel-summary-today"] });
      queryClient.setQueryData(["intel-summary-today"], data);
    },
    onError: (error) => {
      const message = error instanceof Error ? error.message : "Failed to generate summary";
      toast.error(message);
    },
  });

  // Get a specific summary by ID
  const getSummary = async (id: string): Promise<IntelSummary | null> => {
    const { data, error } = await db
      .from("intel_summaries")
      .select("*")
      .eq("id", id)
      .single();

    if (error) throw error;
    return data as IntelSummary;
  };

  // Delete summary mutation
  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await db
        .from("intel_summaries")
        .delete()
        .eq("id", id);

      if (error) throw error;
    },
    onSuccess: () => {
      toast.success("Intel summary deleted");
      queryClient.invalidateQueries({ queryKey: ["intel-summaries"] });
      queryClient.invalidateQueries({ queryKey: ["intel-summary-today"] });
    },
    onError: (error) => {
      const message = error instanceof Error ? error.message : "Failed to delete summary";
      toast.error(message);
    },
  });

  return {
    // List of all summaries
    summaries: summariesQuery.data || [],
    isLoading: summariesQuery.isLoading,
    error: summariesQuery.error,

    // Today's summary
    todaySummary: todaySummaryQuery.data,
    isTodayLoading: todaySummaryQuery.isLoading,

    // Generation
    generateSummary: generateMutation.mutate,
    isGenerating: generateMutation.isPending,
    generationError: generateMutation.error,

    // Delete
    deleteSummary: deleteMutation.mutate,
    isDeleting: deleteMutation.isPending,

    // Utility
    getSummary,
    refetch: summariesQuery.refetch,
  };
};

// Hook for tracking generation progress via realtime subscription
export const useGenerationProgress = () => {
  const { session } = useAuth();
  const [progress, setProgress] = useState<GenerationProgress | null>(null);
  const [isSubscribed, setIsSubscribed] = useState(false);

  // Calculate progress percentage based on completed stages
  const getProgressPercent = useCallback((p: GenerationProgress | null) => {
    if (!p) return 0;
    const stages: GenerationStage[] = [
      'initializing',
      'fetching_reports',
      'media_agent',
      'threat_agent',
      'advisory_agent',
      'entity_aggregation',
      'comprehensive_analysis',
      'saving_results',
      'completed',
    ];
    const currentIndex = stages.indexOf(p.current_stage);
    return Math.round((currentIndex / (stages.length - 1)) * 100);
  }, []);

  // Get estimated time remaining
  const getTimeRemaining = useCallback((p: GenerationProgress | null) => {
    if (!p?.estimated_completion) return null;
    const remaining = new Date(p.estimated_completion).getTime() - Date.now();
    if (remaining <= 0) return 'Almost done...';
    const seconds = Math.ceil(remaining / 1000);
    if (seconds < 60) return `~${seconds}s remaining`;
    return `~${Math.ceil(seconds / 60)}m remaining`;
  }, []);

  useEffect(() => {
    if (!session) return;

    // Subscribe to generation progress changes
    const channel = db
      .channel('generation-progress')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'intel_summary_generation_progress',
        },
        (payload: { eventType: string; new: unknown }) => {
          if (payload.eventType === 'INSERT' || payload.eventType === 'UPDATE') {
            setProgress(payload.new as GenerationProgress);
          } else if (payload.eventType === 'DELETE') {
            // Generation completed, clear progress
            setProgress(null);
          }
        }
      )
      .subscribe((status: string) => {
        setIsSubscribed(status === 'SUBSCRIBED');
      });

    return () => {
      db.removeChannel(channel);
    };
  }, [session]);

  // Fetch any existing progress on mount
  useEffect(() => {
    if (!session) return;

    const fetchExistingProgress = async () => {
      const { data } = await db
        .from('intel_summary_generation_progress')
        .select('*')
        .order('started_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      if (data) {
        setProgress(data as GenerationProgress);
      }
    };

    fetchExistingProgress();
  }, [session]);

  return {
    progress,
    isSubscribed,
    progressPercent: getProgressPercent(progress),
    timeRemaining: getTimeRemaining(progress),
    currentStageLabel: progress ? STAGE_LABELS[progress.current_stage] : null,
    hasError: !!progress?.error,
    errorMessage: progress?.error,
  };
};

// Generation metrics interface
export interface GenerationMetricsData {
  id: string;
  summary_id: string;
  stage_timings: Record<string, number>;
  token_breakdown?: {
    total: number;
  };
  reports_stats: {
    mediaFetched: number;
    threatsFetched: number;
    advisoriesFetched: number;
    ransomwareVictims: number;
    mediaProcessed: number;
    threatsProcessed: number;
    advisoriesProcessed: number;
  };
  cache_stats: {
    cacheHits: number;
    cacheMisses: number;
    entriesWritten: number;
  };
  created_at: string;
}

// Hook for fetching generation metrics
export const useGenerationMetrics = (limit: number = 10) => {
  const { session } = useAuth();

  return useQuery({
    queryKey: ["generation-metrics", limit],
    queryFn: async () => {
      const { data, error } = await db
        .from("intel_summary_metrics")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(limit);

      if (error) throw error;
      return data as GenerationMetricsData[];
    },
    enabled: !!session,
  });
};

// Compute aggregate metrics
export const useAggregateMetrics = () => {
  const { data: metrics, isLoading } = useGenerationMetrics(50);

  const aggregates = useMemo(() => {
    if (!metrics || metrics.length === 0) {
      return null;
    }

    const totalGenerations = metrics.length;
    const avgGenerationTime = metrics.reduce((sum, m) => sum + (m.stage_timings?.total || 0), 0) / totalGenerations;
    const totalCacheHits = metrics.reduce((sum, m) => sum + (m.cache_stats?.cacheHits || 0), 0);
    const totalCacheMisses = metrics.reduce((sum, m) => sum + (m.cache_stats?.cacheMisses || 0), 0);
    const cacheHitRate = totalCacheHits + totalCacheMisses > 0
      ? (totalCacheHits / (totalCacheHits + totalCacheMisses)) * 100
      : 0;
    const avgReportsProcessed = metrics.reduce((sum, m) => {
      const stats = m.reports_stats;
      return sum + (stats?.mediaProcessed || 0) + (stats?.threatsProcessed || 0) + (stats?.advisoriesProcessed || 0);
    }, 0) / totalGenerations;

    return {
      totalGenerations,
      avgGenerationTime: Math.round(avgGenerationTime / 1000), // in seconds
      cacheHitRate: Math.round(cacheHitRate),
      avgReportsProcessed: Math.round(avgReportsProcessed),
    };
  }, [metrics]);

  return { aggregates, isLoading };
};
