-- Migration: Intel Summary Optimization Tables
-- Phase 3-6 infrastructure for caching, progress tracking, and metrics

-- Phase 3: Entity extraction cache for reducing redundant queries
CREATE TABLE IF NOT EXISTS report_entity_cache (
  report_id UUID PRIMARY KEY,
  extracted_at TIMESTAMPTZ DEFAULT NOW(),
  threat_actors JSONB DEFAULT '[]'::jsonb,
  geographies JSONB DEFAULT '[]'::jsonb,
  sectors JSONB DEFAULT '[]'::jsonb,
  cves TEXT[] DEFAULT '{}',
  ttps JSONB DEFAULT '[]'::jsonb,
  cache_version INT DEFAULT 1
);

-- Index for cache freshness queries
CREATE INDEX IF NOT EXISTS idx_report_entity_cache_extracted
  ON report_entity_cache(extracted_at);

-- Phase 5: Generation progress tracking for progressive UI
CREATE TABLE IF NOT EXISTS intel_summary_generation_progress (
  summary_id UUID PRIMARY KEY REFERENCES intel_summaries(id) ON DELETE CASCADE,
  started_at TIMESTAMPTZ DEFAULT NOW(),
  current_stage TEXT,
  stages_completed TEXT[] DEFAULT '{}',
  estimated_completion TIMESTAMPTZ,
  error TEXT
);

-- Enable realtime for progress tracking
ALTER PUBLICATION supabase_realtime ADD TABLE intel_summary_generation_progress;

-- Phase 6: Detailed metrics for analytics
CREATE TABLE IF NOT EXISTS intel_summary_metrics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  summary_id UUID REFERENCES intel_summaries(id) ON DELETE CASCADE,
  stage_timings JSONB,
  token_breakdown JSONB,
  reports_stats JSONB,
  cache_stats JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for metrics queries by summary
CREATE INDEX IF NOT EXISTS idx_intel_summary_metrics_summary
  ON intel_summary_metrics(summary_id);

-- Index for metrics time-series queries
CREATE INDEX IF NOT EXISTS idx_intel_summary_metrics_created
  ON intel_summary_metrics(created_at DESC);

-- Function to clean up old cache entries (24-hour TTL)
CREATE OR REPLACE FUNCTION cleanup_old_entity_cache()
RETURNS INTEGER AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM report_entity_cache
  WHERE extracted_at < NOW() - INTERVAL '24 hours';

  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- RLS policies for the new tables
ALTER TABLE report_entity_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel_summary_generation_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel_summary_metrics ENABLE ROW LEVEL SECURITY;

-- Service role has full access to cache tables
CREATE POLICY "Service role can manage entity cache"
  ON report_entity_cache
  FOR ALL
  USING (auth.role() = 'service_role');

CREATE POLICY "Service role can manage generation progress"
  ON intel_summary_generation_progress
  FOR ALL
  USING (auth.role() = 'service_role');

CREATE POLICY "Service role can manage metrics"
  ON intel_summary_metrics
  FOR ALL
  USING (auth.role() = 'service_role');

-- Authenticated users can read progress (for their UI)
CREATE POLICY "Authenticated users can view generation progress"
  ON intel_summary_generation_progress
  FOR SELECT
  USING (auth.role() = 'authenticated');

-- Add stage_timings column to intel_summaries if not exists
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'intel_summaries'
    AND column_name = 'stage_timings'
  ) THEN
    ALTER TABLE intel_summaries ADD COLUMN stage_timings JSONB;
  END IF;
END $$;
