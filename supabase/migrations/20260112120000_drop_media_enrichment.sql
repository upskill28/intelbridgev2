-- ============================================================================
-- Drop Media Enrichment System
-- ============================================================================
-- This migration removes the media enrichment feature as it has been replaced
-- by a standalone Python script running directly on the OpenCTI server.
-- ============================================================================

-- Remove the scheduled cron job
DO $$
BEGIN
  PERFORM cron.unschedule('media-enrichment-auto-process');
EXCEPTION WHEN OTHERS THEN
  -- Job doesn't exist, that's fine
  NULL;
END $$;

-- Drop the trigger function
DROP FUNCTION IF EXISTS public.trigger_media_enrichment_auto_process();

-- Drop the updated_at trigger
DROP TRIGGER IF EXISTS update_media_enrichment_queue_updated_at ON media_enrichment_queue;

-- Drop the updated_at function
DROP FUNCTION IF EXISTS update_media_enrichment_updated_at();

-- Drop the tables (this will also drop associated policies and indexes)
DROP TABLE IF EXISTS media_enrichment_history;
DROP TABLE IF EXISTS media_enrichment_queue;
