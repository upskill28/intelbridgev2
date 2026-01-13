-- Media Report Enrichment System
-- Stores AI-generated summaries and entity suggestions for admin review

-- Queue table for pending enrichment jobs
CREATE TABLE media_enrichment_queue (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  report_id TEXT NOT NULL UNIQUE,        -- OpenCTI report ID
  report_name TEXT NOT NULL,
  original_description TEXT,
  external_url TEXT,
  source_name TEXT,
  published_date TIMESTAMPTZ,

  -- Enrichment results
  scraped_content TEXT,                  -- Raw scraped content (truncated)
  ai_summary TEXT,                       -- Generated factual summary
  suggested_entities JSONB DEFAULT '[]', -- [{type, id, name, confidence}]

  -- Status tracking
  status TEXT DEFAULT 'pending' CHECK (status IN (
    'pending',           -- Awaiting scraping/AI processing
    'enriched',          -- AI processed, awaiting human review
    'approved',          -- Human approved, ready to apply
    'applied',           -- Changes applied to OpenCTI
    'rejected',          -- Human rejected
    'failed'             -- Processing failed
  )),
  error_message TEXT,

  -- Entity selection (which entities admin approved to link)
  approved_entities JSONB DEFAULT '[]',  -- [{type, id, name}]
  edited_summary TEXT,                   -- If admin edited the summary

  -- Audit
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  reviewed_by UUID REFERENCES auth.users(id),
  reviewed_at TIMESTAMPTZ,
  applied_at TIMESTAMPTZ
);

-- History/audit trail
CREATE TABLE media_enrichment_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  queue_id UUID REFERENCES media_enrichment_queue(id) ON DELETE SET NULL,
  report_id TEXT NOT NULL,
  report_name TEXT,
  action TEXT NOT NULL,                  -- 'applied', 'rejected', 'failed'
  summary_applied TEXT,                  -- The summary that was applied
  entities_linked JSONB DEFAULT '[]',    -- [{type, id, name}]
  error_message TEXT,
  performed_by UUID REFERENCES auth.users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_media_enrichment_queue_status ON media_enrichment_queue(status);
CREATE INDEX idx_media_enrichment_queue_created ON media_enrichment_queue(created_at DESC);
CREATE INDEX idx_media_enrichment_queue_report_id ON media_enrichment_queue(report_id);
CREATE INDEX idx_media_enrichment_history_created ON media_enrichment_history(created_at DESC);

-- RLS policies (admin only)
ALTER TABLE media_enrichment_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE media_enrichment_history ENABLE ROW LEVEL SECURITY;

-- Admin-only access for queue
CREATE POLICY "Admin can view enrichment queue"
  ON media_enrichment_queue FOR SELECT
  USING (EXISTS (
    SELECT 1 FROM user_roles
    WHERE user_roles.user_id = auth.uid()
    AND user_roles.role = 'admin'
  ));

CREATE POLICY "Admin can insert to enrichment queue"
  ON media_enrichment_queue FOR INSERT
  WITH CHECK (EXISTS (
    SELECT 1 FROM user_roles
    WHERE user_roles.user_id = auth.uid()
    AND user_roles.role = 'admin'
  ));

CREATE POLICY "Admin can update enrichment queue"
  ON media_enrichment_queue FOR UPDATE
  USING (EXISTS (
    SELECT 1 FROM user_roles
    WHERE user_roles.user_id = auth.uid()
    AND user_roles.role = 'admin'
  ));

CREATE POLICY "Admin can delete from enrichment queue"
  ON media_enrichment_queue FOR DELETE
  USING (EXISTS (
    SELECT 1 FROM user_roles
    WHERE user_roles.user_id = auth.uid()
    AND user_roles.role = 'admin'
  ));

-- Admin-only access for history
CREATE POLICY "Admin can view enrichment history"
  ON media_enrichment_history FOR SELECT
  USING (EXISTS (
    SELECT 1 FROM user_roles
    WHERE user_roles.user_id = auth.uid()
    AND user_roles.role = 'admin'
  ));

CREATE POLICY "Admin can insert to enrichment history"
  ON media_enrichment_history FOR INSERT
  WITH CHECK (EXISTS (
    SELECT 1 FROM user_roles
    WHERE user_roles.user_id = auth.uid()
    AND user_roles.role = 'admin'
  ));

-- Updated_at trigger
CREATE OR REPLACE FUNCTION update_media_enrichment_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_media_enrichment_queue_updated_at
  BEFORE UPDATE ON media_enrichment_queue
  FOR EACH ROW
  EXECUTE FUNCTION update_media_enrichment_updated_at();
