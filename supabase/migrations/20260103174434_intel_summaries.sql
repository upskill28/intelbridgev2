-- Create intel_summaries table for AI-generated threat intelligence reports
CREATE TABLE intel_summaries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ DEFAULT now(),
  generated_by UUID REFERENCES auth.users(id),
  report_date DATE NOT NULL,

  -- Executive Summary (from orchestrator agent)
  executive_summary TEXT NOT NULL,
  key_takeaways JSONB,         -- Array of bullet point strings
  recommended_actions JSONB,   -- Array of action strings

  -- Individual Item Summaries
  media_summaries JSONB,       -- [{title, summary, sourceUrl, date, relevance}]
  threat_summaries JSONB,      -- [{title, summary, sourceUrl, date, threatActor, severity}]
  vuln_summaries JSONB,        -- [{cve, severity, summary, nvdUrl, description}]

  -- Metadata
  source_counts JSONB,         -- {media: 20, threats: 30, vulns: 15}
  token_usage JSONB,           -- {input: x, output: y, cost: z}
  generation_time_ms INTEGER,

  UNIQUE(report_date)
);

-- Enable RLS
ALTER TABLE intel_summaries ENABLE ROW LEVEL SECURITY;

-- Authenticated users can view summaries
CREATE POLICY "Authenticated users can view summaries"
  ON intel_summaries FOR SELECT
  TO authenticated
  USING (true);

-- Service role can insert (Edge Function uses service role)
CREATE POLICY "Service role can insert summaries"
  ON intel_summaries FOR INSERT
  TO service_role
  WITH CHECK (true);

-- Service role can update (for retry/regeneration)
CREATE POLICY "Service role can update summaries"
  ON intel_summaries FOR UPDATE
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Add index for faster date lookups
CREATE INDEX idx_intel_summaries_report_date ON intel_summaries(report_date DESC);

-- Add comment for documentation
COMMENT ON TABLE intel_summaries IS 'AI-generated daily threat intelligence summaries using multi-agent OpenAI architecture';
