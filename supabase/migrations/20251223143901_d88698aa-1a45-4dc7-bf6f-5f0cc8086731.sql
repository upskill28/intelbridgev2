-- Remove podcast storage bucket and related policies
DELETE FROM storage.objects WHERE bucket_id = 'podcasts';
DELETE FROM storage.buckets WHERE id = 'podcasts';

-- Drop podcast_episodes table (no longer needed)
DROP TABLE IF EXISTS public.podcast_episodes;