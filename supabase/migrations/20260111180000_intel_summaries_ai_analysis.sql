-- Add comprehensive AI analysis columns to intel_summaries
-- These fields store AI-generated assessments based on all evidence

ALTER TABLE intel_summaries
ADD COLUMN IF NOT EXISTS threat_landscape JSONB,
-- {assessment: "string", key_themes: ["string"], threat_level_rationale: "string"}

ADD COLUMN IF NOT EXISTS actor_analysis JSONB,
-- {assessment: "string", active_actors: [{name, activity_summary, ttps_used: []}]}

ADD COLUMN IF NOT EXISTS vulnerability_analysis JSONB,
-- {assessment: "string", critical_vulns: [{cve, context, urgency}]}

ADD COLUMN IF NOT EXISTS targeting_analysis JSONB;
-- {assessment: "string", sectors_at_risk: [], geographic_focus: []}

-- Add comments for documentation
COMMENT ON COLUMN intel_summaries.threat_landscape IS 'AI-generated threat landscape assessment with key themes';
COMMENT ON COLUMN intel_summaries.actor_analysis IS 'AI-generated analysis of active threat actors and their TTPs';
COMMENT ON COLUMN intel_summaries.vulnerability_analysis IS 'AI-generated analysis of critical vulnerabilities discussed';
COMMENT ON COLUMN intel_summaries.targeting_analysis IS 'AI-generated analysis of sector and geographic targeting patterns';
