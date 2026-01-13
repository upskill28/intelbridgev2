-- Create podcast_episodes table for storing generated audio summaries
CREATE TABLE public.podcast_episodes (
    id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    summary_id UUID NOT NULL REFERENCES public.intelligence_summaries(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    audio_url TEXT NOT NULL,
    duration_seconds INTEGER,
    voice_name TEXT NOT NULL DEFAULT 'en-US-Neural2-D',
    period_type TEXT NOT NULL DEFAULT 'daily',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    created_by UUID NOT NULL
);

-- Enable Row Level Security
ALTER TABLE public.podcast_episodes ENABLE ROW LEVEL SECURITY;

-- Authenticated users can view podcast episodes
CREATE POLICY "Authenticated users can view podcast episodes"
ON public.podcast_episodes
FOR SELECT
USING (auth.uid() IS NOT NULL);

-- Only admins can create podcast episodes
CREATE POLICY "Admins can create podcast episodes"
ON public.podcast_episodes
FOR INSERT
WITH CHECK (has_role(auth.uid(), 'admin'::app_role));

-- Only admins can delete podcast episodes
CREATE POLICY "Admins can delete podcast episodes"
ON public.podcast_episodes
FOR DELETE
USING (has_role(auth.uid(), 'admin'::app_role));

-- Create storage bucket for podcasts
INSERT INTO storage.buckets (id, name, public) VALUES ('podcasts', 'podcasts', true);

-- Storage policies for podcast audio files
CREATE POLICY "Anyone can view podcast audio"
ON storage.objects
FOR SELECT
USING (bucket_id = 'podcasts');

CREATE POLICY "Admins can upload podcast audio"
ON storage.objects
FOR INSERT
WITH CHECK (bucket_id = 'podcasts' AND has_role(auth.uid(), 'admin'::app_role));

CREATE POLICY "Admins can delete podcast audio"
ON storage.objects
FOR DELETE
USING (bucket_id = 'podcasts' AND has_role(auth.uid(), 'admin'::app_role));