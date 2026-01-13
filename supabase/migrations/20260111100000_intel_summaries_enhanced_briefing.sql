-- Add new columns for enhanced SMB-focused threat intelligence briefing
-- This migration adds TTP-to-mitigation mapping, threat posture, and evidence-backed actions

ALTER TABLE intel_summaries
ADD COLUMN IF NOT EXISTS threat_posture JSONB,
-- {level: "Elevated"|"Moderate"|"Low", rationale: "string"}

ADD COLUMN IF NOT EXISTS analyst_brief TEXT,
-- Max 4 sentences, concise SMB-focused analysis

ADD COLUMN IF NOT EXISTS org_relevance TEXT,
-- Relevance to the organization

ADD COLUMN IF NOT EXISTS key_risks JSONB,
-- Array max 3: [{risk: "string", evidence: [{type, id, name, linkPath}]}]

ADD COLUMN IF NOT EXISTS recommended_actions JSONB,
-- Array max 3: [{action: "string", confidence: "HIGH"|"MED", why: "string",
--   evidence: [{type, id, name, linkPath}], mitigates: [{ttpId, ttpName}]}]

ADD COLUMN IF NOT EXISTS ttps_observed JSONB,
-- Array: [{id, name, mitreId, source: "observed"|"inferred", evidenceIds: []}]

ADD COLUMN IF NOT EXISTS active_actors_today JSONB;
-- Array: [{id, name, linkPath, source: "report"|"ransomware"|"advisory"}]

-- Add comment for documentation
COMMENT ON COLUMN intel_summaries.threat_posture IS 'Threat posture level (Elevated/Moderate/Low) with rationale';
COMMENT ON COLUMN intel_summaries.analyst_brief IS 'Concise 4-sentence analyst brief for SMB audience';
COMMENT ON COLUMN intel_summaries.key_risks IS 'Top 3 key risks with evidence IDs for traceability';
COMMENT ON COLUMN intel_summaries.recommended_actions IS 'Top 3 evidence-backed actions from TTP-to-mitigation mapping';
COMMENT ON COLUMN intel_summaries.ttps_observed IS 'TTPs extracted from today intelligence items';
COMMENT ON COLUMN intel_summaries.active_actors_today IS 'Threat actors mentioned in today intelligence';
