-- Deduplication candidates table for storing potential duplicate intrusion sets
CREATE TABLE IF NOT EXISTS dedup_candidates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),

  -- Entity pair information
  entity1_id TEXT NOT NULL,
  entity1_name TEXT NOT NULL,
  entity2_id TEXT NOT NULL,
  entity2_name TEXT NOT NULL,

  -- Similarity metrics
  similarity_score DECIMAL(5, 4) NOT NULL,
  name_similarity DECIMAL(5, 4),
  alias_overlap INTEGER DEFAULT 0,

  -- Status tracking
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'merged')),
  reviewed_by UUID REFERENCES auth.users(id),
  reviewed_at TIMESTAMPTZ,

  -- Merge decision (which entity to keep)
  canonical_entity_id TEXT,

  -- Additional metadata
  detection_method TEXT,
  notes TEXT,

  -- Ensure unique pairs (avoid storing same pair twice)
  UNIQUE(entity1_id, entity2_id)
);

-- Deduplication history table for tracking merges
CREATE TABLE IF NOT EXISTS dedup_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ DEFAULT now(),

  -- The candidate that was processed
  candidate_id UUID REFERENCES dedup_candidates(id),

  -- Merge details
  kept_entity_id TEXT NOT NULL,
  kept_entity_name TEXT NOT NULL,
  merged_entity_id TEXT NOT NULL,
  merged_entity_name TEXT NOT NULL,

  -- Who performed the merge
  merged_by UUID REFERENCES auth.users(id),

  -- Result
  success BOOLEAN NOT NULL DEFAULT true,
  error_message TEXT,

  -- Stats about what was merged
  relationships_transferred INTEGER DEFAULT 0,
  aliases_merged INTEGER DEFAULT 0
);

-- Scan runs table for tracking when scans were performed
CREATE TABLE IF NOT EXISTS dedup_scan_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ DEFAULT now(),
  completed_at TIMESTAMPTZ,

  -- Scan parameters
  similarity_threshold DECIMAL(5, 4) NOT NULL DEFAULT 0.85,
  entity_count INTEGER,

  -- Results
  candidates_found INTEGER DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
  error_message TEXT,

  -- Who initiated
  initiated_by UUID REFERENCES auth.users(id)
);

-- Enable Row Level Security
ALTER TABLE dedup_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE dedup_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE dedup_scan_runs ENABLE ROW LEVEL SECURITY;

-- RLS Policies: Only admins can manage dedup data
CREATE POLICY "Admins can view dedup candidates"
  ON dedup_candidates FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM user_roles
      WHERE user_roles.user_id = auth.uid()
      AND user_roles.role = 'admin'
    )
  );

CREATE POLICY "Admins can insert dedup candidates"
  ON dedup_candidates FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM user_roles
      WHERE user_roles.user_id = auth.uid()
      AND user_roles.role = 'admin'
    )
  );

CREATE POLICY "Admins can update dedup candidates"
  ON dedup_candidates FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM user_roles
      WHERE user_roles.user_id = auth.uid()
      AND user_roles.role = 'admin'
    )
  );

CREATE POLICY "Admins can delete dedup candidates"
  ON dedup_candidates FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM user_roles
      WHERE user_roles.user_id = auth.uid()
      AND user_roles.role = 'admin'
    )
  );

CREATE POLICY "Admins can view dedup history"
  ON dedup_history FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM user_roles
      WHERE user_roles.user_id = auth.uid()
      AND user_roles.role = 'admin'
    )
  );

CREATE POLICY "Admins can insert dedup history"
  ON dedup_history FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM user_roles
      WHERE user_roles.user_id = auth.uid()
      AND user_roles.role = 'admin'
    )
  );

CREATE POLICY "Admins can view scan runs"
  ON dedup_scan_runs FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM user_roles
      WHERE user_roles.user_id = auth.uid()
      AND user_roles.role = 'admin'
    )
  );

CREATE POLICY "Admins can insert scan runs"
  ON dedup_scan_runs FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM user_roles
      WHERE user_roles.user_id = auth.uid()
      AND user_roles.role = 'admin'
    )
  );

CREATE POLICY "Admins can update scan runs"
  ON dedup_scan_runs FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM user_roles
      WHERE user_roles.user_id = auth.uid()
      AND user_roles.role = 'admin'
    )
  );

-- Service role policies for Edge Functions
CREATE POLICY "Service role can manage dedup candidates"
  ON dedup_candidates FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Service role can manage dedup history"
  ON dedup_history FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Service role can manage scan runs"
  ON dedup_scan_runs FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Index for faster lookups
CREATE INDEX idx_dedup_candidates_status ON dedup_candidates(status);
CREATE INDEX idx_dedup_candidates_similarity ON dedup_candidates(similarity_score DESC);
CREATE INDEX idx_dedup_history_created ON dedup_history(created_at DESC);
CREATE INDEX idx_dedup_scan_runs_created ON dedup_scan_runs(created_at DESC);
