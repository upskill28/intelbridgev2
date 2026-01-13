-- Expose intel schema to PostgREST API
-- Grant usage on the schema
GRANT USAGE ON SCHEMA intel TO anon, authenticated, service_role;

-- Grant select on all tables in intel schema
GRANT SELECT ON ALL TABLES IN SCHEMA intel TO anon, authenticated, service_role;

-- Grant select on future tables in intel schema
ALTER DEFAULT PRIVILEGES IN SCHEMA intel GRANT SELECT ON TABLES TO anon, authenticated, service_role;

-- Notify PostgREST to reload schema cache
NOTIFY pgrst, 'reload config';
NOTIFY pgrst, 'reload schema';
