-- Add columns to store entity details for expandable view
ALTER TABLE dedup_candidates
ADD COLUMN IF NOT EXISTS entity1_description TEXT,
ADD COLUMN IF NOT EXISTS entity1_aliases TEXT[],
ADD COLUMN IF NOT EXISTS entity1_relationships INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS entity2_description TEXT,
ADD COLUMN IF NOT EXISTS entity2_aliases TEXT[],
ADD COLUMN IF NOT EXISTS entity2_relationships INTEGER DEFAULT 0;
