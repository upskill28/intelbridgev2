-- Create ransomware_victims table for caching OpenCTI data
CREATE TABLE IF NOT EXISTS public.ransomware_victims (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  opencti_id text NOT NULL UNIQUE,
  name text NOT NULL,
  description text,
  published_date timestamp with time zone NOT NULL,
  sector text,
  country text,
  threat_group text,
  victim_organization text,
  labels jsonb DEFAULT '[]'::jsonb,
  markings jsonb DEFAULT '[]'::jsonb,
  raw_data jsonb,
  created_at timestamp with time zone DEFAULT now() NOT NULL,
  updated_at timestamp with time zone DEFAULT now() NOT NULL
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_ransomware_victims_published_date ON public.ransomware_victims(published_date DESC);
CREATE INDEX IF NOT EXISTS idx_ransomware_victims_opencti_id ON public.ransomware_victims(opencti_id);
CREATE INDEX IF NOT EXISTS idx_ransomware_victims_threat_group ON public.ransomware_victims(threat_group);
CREATE INDEX IF NOT EXISTS idx_ransomware_victims_sector ON public.ransomware_victims(sector);

-- Enable RLS
ALTER TABLE public.ransomware_victims ENABLE ROW LEVEL SECURITY;

-- Allow authenticated users to read
CREATE POLICY "Authenticated users can view ransomware victims"
  ON public.ransomware_victims
  FOR SELECT
  TO authenticated
  USING (true);

-- Allow service role to insert/update (for edge function)
CREATE POLICY "Service role can manage ransomware victims"
  ON public.ransomware_victims
  FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Create trigger for updated_at
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_updated_at
  BEFORE UPDATE ON public.ransomware_victims
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_updated_at();

-- Enable pg_cron extension for scheduled jobs
CREATE EXTENSION IF NOT EXISTS pg_cron WITH SCHEMA extensions;

-- Enable pg_net extension for HTTP requests
CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;