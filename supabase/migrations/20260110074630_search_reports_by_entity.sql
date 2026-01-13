-- Simple function to search reports containing an entity ID in their data
-- This handles the OpenCTI "objects" containment that's not in relationships
CREATE OR REPLACE FUNCTION intel.search_reports_by_entity(entity_id text)
RETURNS TABLE (
  internal_id text,
  name text,
  data jsonb,
  source_created_at timestamptz
)
LANGUAGE sql
STABLE
AS $$
  SELECT internal_id, name, data, source_created_at
  FROM intel.object_current
  WHERE entity_type = 'Report'
    AND data::text LIKE '%' || entity_id || '%'
  LIMIT 50;
$$;

-- Grant access
GRANT EXECUTE ON FUNCTION intel.search_reports_by_entity(text) TO anon, authenticated, service_role;
