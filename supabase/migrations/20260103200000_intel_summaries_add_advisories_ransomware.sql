-- Add new columns for advisories and ransomware activity
ALTER TABLE intel_summaries
ADD COLUMN IF NOT EXISTS advisory_summaries JSONB,
ADD COLUMN IF NOT EXISTS ransomware_activity JSONB;

-- Remove deprecated columns (recommended_actions and vuln_summaries)
ALTER TABLE intel_summaries
DROP COLUMN IF EXISTS recommended_actions,
DROP COLUMN IF EXISTS vuln_summaries;
