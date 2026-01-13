-- Create RPC function to find reports that reference a given entity ID
CREATE OR REPLACE FUNCTION intel.find_reports_for_entity(entity_id text)
RETURNS TABLE (
  internal_id text,
  name text,
  data jsonb,
  source_created_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
AS $$
  SELECT
    o.internal_id,
    o.name,
    o.data,
    o.source_created_at
  FROM intel.object_current o
  WHERE o.entity_type = 'Report'
    AND o.data::text LIKE '%' || entity_id || '%'
  LIMIT 100;
$$;

-- Grant execute permission to API roles
GRANT EXECUTE ON FUNCTION intel.find_reports_for_entity(text) TO anon, authenticated, service_role;
