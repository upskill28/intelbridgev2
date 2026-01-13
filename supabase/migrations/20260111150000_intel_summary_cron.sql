-- Enable pg_cron and pg_net extensions for scheduled HTTP calls
CREATE EXTENSION IF NOT EXISTS pg_cron;
CREATE EXTENSION IF NOT EXISTS pg_net;

-- Create a config table to store the cron secret (more flexible than vault)
CREATE TABLE IF NOT EXISTS public.app_config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Only service_role can access this table
ALTER TABLE public.app_config ENABLE ROW LEVEL SECURITY;

-- No RLS policies = only service_role/postgres can access
REVOKE ALL ON public.app_config FROM anon, authenticated;
GRANT SELECT ON public.app_config TO service_role;

-- Insert placeholder for cron secret (update this value!)
INSERT INTO public.app_config (key, value)
VALUES ('cron_secret_key', 'CHANGE_ME_TO_A_SECURE_SECRET')
ON CONFLICT (key) DO NOTHING;

-- Create a function to call the intel summary edge function
CREATE OR REPLACE FUNCTION public.trigger_intel_summary_generation()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  response_id bigint;
  cron_secret text;
BEGIN
  -- Get the cron secret from config table
  SELECT value INTO cron_secret
  FROM public.app_config
  WHERE key = 'cron_secret_key';

  -- Call the edge function with the cron secret
  SELECT net.http_post(
    url := 'https://tmiuexksecybxfdyzuxz.supabase.co/functions/v1/generate-intel-summary',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'Authorization', 'Bearer ' || COALESCE(cron_secret, '')
    ),
    body := '{}'::jsonb
  ) INTO response_id;

  RAISE NOTICE 'Intel summary generation triggered, response_id: %', response_id;
END;
$$;

-- Schedule the job to run every 3 hours
-- Cron format: minute hour day-of-month month day-of-week
-- "0 */3 * * *" = at minute 0 of every 3rd hour
SELECT cron.schedule(
  'generate-intel-summary-every-3h',  -- job name
  '0 */3 * * *',                       -- every 3 hours at minute 0
  $$SELECT public.trigger_intel_summary_generation()$$
);

-- Grant execute permission on the function
GRANT EXECUTE ON FUNCTION public.trigger_intel_summary_generation() TO postgres;
GRANT EXECUTE ON FUNCTION public.trigger_intel_summary_generation() TO service_role;

-- Add a comment explaining the job
COMMENT ON FUNCTION public.trigger_intel_summary_generation() IS
  'Triggers the generate-intel-summary edge function. Called by pg_cron every 3 hours.';
