-- Ensure intel schema is fully accessible via API
GRANT USAGE ON SCHEMA intel TO anon, authenticated, service_role;

-- Grant SELECT on all current tables
GRANT SELECT ON intel.object_current TO anon, authenticated, service_role;
GRANT SELECT ON intel.object_version TO anon, authenticated, service_role;
GRANT SELECT ON intel.relationship_current TO anon, authenticated, service_role;
GRANT SELECT ON intel.relationship_version TO anon, authenticated, service_role;

-- Grant for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA intel GRANT SELECT ON TABLES TO anon, authenticated, service_role;

-- Reload PostgREST schema cache
NOTIFY pgrst, 'reload schema';
