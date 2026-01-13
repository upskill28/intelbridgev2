-- Add ransomware_analysis column to intel_summaries
-- This stores AI-generated analysis of ransomware leak site activity

ALTER TABLE intel_summaries
ADD COLUMN IF NOT EXISTS ransomware_analysis JSONB;
-- {assessment: "string", total_victims: number, active_groups: [{name, victim_count, notable_victims: []}]}

-- Add comment for documentation
COMMENT ON COLUMN intel_summaries.ransomware_analysis IS 'AI-generated analysis of ransomware activity with group breakdowns';
