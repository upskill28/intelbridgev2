-- Add targeting columns for sector and geography mentions in intelligence summaries
-- This migration adds fields to track which sectors and geographies are mentioned across reports

ALTER TABLE intel_summaries
ADD COLUMN IF NOT EXISTS targeting_sectors JSONB,
-- Array of targeting mentions: [{id, name, entityType, count, confidence, evidence: [{type, id, name, linkPath, date}]}]

ADD COLUMN IF NOT EXISTS targeting_geographies JSONB;
-- Array of targeting mentions: [{id, name, entityType, count, confidence, evidence: [{type, id, name, linkPath, date}]}]

-- Add comments for documentation
COMMENT ON COLUMN intel_summaries.targeting_sectors IS 'Top sectors mentioned across reports with evidence (max 5)';
COMMENT ON COLUMN intel_summaries.targeting_geographies IS 'Top geographies (countries/regions/cities) mentioned across reports with evidence (max 5)';
