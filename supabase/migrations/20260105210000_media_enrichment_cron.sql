-- ============================================================================
-- Media Enrichment Scheduled Automation
-- ============================================================================
-- This migration sets up pg_cron to automatically run media report enrichment
-- every 30 minutes.
--
-- IMPORTANT: After running this migration, you need to add ONE secret to vault:
--   SELECT vault.create_secret('your-service-role-key', 'supabase_service_role_key');
--
-- Get your service role key from: Supabase Dashboard > Settings > API > service_role
-- ============================================================================

-- Enable pg_net extension for HTTP requests (pg_cron should already be enabled on Supabase)
CREATE EXTENSION IF NOT EXISTS pg_net;

-- Create a function to call the media-enrichment edge function
CREATE OR REPLACE FUNCTION public.trigger_media_enrichment_auto_process()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  project_url TEXT := 'https://tmiuexksecybxfdyzuxz.supabase.co';
  service_key TEXT;
  request_id BIGINT;
BEGIN
  -- Get service key from vault
  BEGIN
    SELECT decrypted_secret INTO service_key
    FROM vault.decrypted_secrets
    WHERE name = 'supabase_service_role_key'
    LIMIT 1;
  EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'Could not access vault secrets: %', SQLERRM;
    RETURN;
  END;

  -- Check if we have the service key
  IF service_key IS NULL THEN
    RAISE WARNING 'Missing vault secret. Run: SELECT vault.create_secret(''your-key'', ''supabase_service_role_key'');';
    RETURN;
  END IF;

  -- Make HTTP POST request to the edge function
  SELECT net.http_post(
    url := project_url || '/functions/v1/media-enrichment',
    body := '{"action": "auto-process"}'::jsonb,
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'Authorization', 'Bearer ' || service_key
    )
  ) INTO request_id;

  RAISE LOG 'Media enrichment auto-process triggered at %, request_id: %', NOW(), request_id;
END;
$$;

-- Grant execute permission
GRANT EXECUTE ON FUNCTION public.trigger_media_enrichment_auto_process() TO service_role;

-- Schedule the auto-process to run every 30 minutes
-- Note: Cron schedule format: minute hour day month weekday
-- */30 * * * * = every 30 minutes
DO $$
BEGIN
  -- Remove existing job if it exists
  PERFORM cron.unschedule('media-enrichment-auto-process');
EXCEPTION WHEN OTHERS THEN
  -- Job doesn't exist, that's fine
  NULL;
END $$;

SELECT cron.schedule(
  'media-enrichment-auto-process',
  '*/30 * * * *',
  $$SELECT public.trigger_media_enrichment_auto_process()$$
);

-- Add helpful comment
COMMENT ON FUNCTION public.trigger_media_enrichment_auto_process() IS
'Triggers the media-enrichment edge function with auto-process action.
Scheduled to run every 30 minutes via pg_cron.

What it does:
- Scans last 25 media reports from OpenCTI
- Checks relevance (threat intel vs generic content)
- Auto-deletes non-relevant reports from OpenCTI
- Generates AI summaries for relevant reports
- Links entities with >=90% confidence score
- Adds intel-bridge-enriched label to prevent re-processing

Requires vault secret:
- supabase_service_role_key: Service role key for auth

To set up, run in SQL Editor:
SELECT vault.create_secret(''your-service-role-key'', ''supabase_service_role_key'')';
