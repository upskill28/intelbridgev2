-- Create media_reports table
CREATE TABLE public.media_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  guid TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  link TEXT NOT NULL,
  description TEXT,
  pub_date TIMESTAMPTZ,
  source TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.media_reports ENABLE ROW LEVEL SECURITY;

-- Allow anyone to read
CREATE POLICY "Anyone can view media reports"
  ON public.media_reports FOR SELECT
  USING (true);

-- System can insert (via edge function with service role)
CREATE POLICY "System can insert media reports"
  ON public.media_reports FOR INSERT
  WITH CHECK (true);

-- Create media_source_blacklist table
CREATE TABLE public.media_source_blacklist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ DEFAULT now(),
  created_by UUID REFERENCES auth.users(id)
);

-- Enable RLS
ALTER TABLE public.media_source_blacklist ENABLE ROW LEVEL SECURITY;

-- Anyone can view blacklist
CREATE POLICY "Anyone can view media source blacklist"
  ON public.media_source_blacklist FOR SELECT
  USING (true);

-- Admins can insert
CREATE POLICY "Admins can insert media sources"
  ON public.media_source_blacklist FOR INSERT
  WITH CHECK (has_role(auth.uid(), 'admin'::app_role));

-- Admins can delete
CREATE POLICY "Admins can delete media sources"
  ON public.media_source_blacklist FOR DELETE
  USING (has_role(auth.uid(), 'admin'::app_role));

-- Create indexes for performance
CREATE INDEX idx_media_reports_pub_date ON public.media_reports(pub_date DESC);
CREATE INDEX idx_media_reports_source ON public.media_reports(source);
CREATE INDEX idx_media_reports_guid ON public.media_reports(guid);