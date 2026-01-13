-- Fix intel schema security: Remove anon access, require authentication
-- The intel schema contains threat intelligence data that should only be
-- accessible to authenticated users, not anonymous API requests

-- Revoke anon access from intel schema and tables
REVOKE USAGE ON SCHEMA intel FROM anon;
REVOKE SELECT ON intel.object_current FROM anon;
REVOKE SELECT ON intel.object_version FROM anon;
REVOKE SELECT ON intel.relationship_current FROM anon;
REVOKE SELECT ON intel.relationship_version FROM anon;

-- Revoke default privileges for anon on future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA intel REVOKE SELECT ON TABLES FROM anon;

-- Ensure authenticated and service_role still have access
GRANT USAGE ON SCHEMA intel TO authenticated, service_role;
GRANT SELECT ON intel.object_current TO authenticated, service_role;
GRANT SELECT ON intel.object_version TO authenticated, service_role;
GRANT SELECT ON intel.relationship_current TO authenticated, service_role;
GRANT SELECT ON intel.relationship_version TO authenticated, service_role;

-- Keep default privileges for authenticated users on future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA intel GRANT SELECT ON TABLES TO authenticated, service_role;

-- Enable RLS on intel tables (restricts even granted access to policies)
ALTER TABLE intel.object_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.object_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.relationship_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.relationship_version ENABLE ROW LEVEL SECURITY;

-- Create policies allowing authenticated users to read all intel data
CREATE POLICY "Authenticated users can view objects"
  ON intel.object_current
  FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can view object versions"
  ON intel.object_version
  FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can view relationships"
  ON intel.relationship_current
  FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can view relationship versions"
  ON intel.relationship_version
  FOR SELECT
  TO authenticated
  USING (true);

-- Service role bypasses RLS by default, but explicit policy for clarity
CREATE POLICY "Service role can manage objects"
  ON intel.object_current
  FOR ALL
  TO service_role
  USING (true);

CREATE POLICY "Service role can manage object versions"
  ON intel.object_version
  FOR ALL
  TO service_role
  USING (true);

CREATE POLICY "Service role can manage relationships"
  ON intel.relationship_current
  FOR ALL
  TO service_role
  USING (true);

CREATE POLICY "Service role can manage relationship versions"
  ON intel.relationship_version
  FOR ALL
  TO service_role
  USING (true);

-- Reload PostgREST schema cache to apply changes
NOTIFY pgrst, 'reload schema';
