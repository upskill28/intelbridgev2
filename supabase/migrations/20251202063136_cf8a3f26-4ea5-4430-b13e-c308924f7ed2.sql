-- Add entity metadata column to intelligence_summaries table
ALTER TABLE intelligence_summaries 
ADD COLUMN IF NOT EXISTS entity_metadata JSONB DEFAULT '[]'::jsonb;