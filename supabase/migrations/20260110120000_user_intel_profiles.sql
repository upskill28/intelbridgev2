-- Create user_intel_profiles table to store personalized intel preferences
CREATE TABLE IF NOT EXISTS public.user_intel_profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,

  -- Selected sectors (array of sector internal_ids from intel.object_current)
  sectors TEXT[] DEFAULT '{}',

  -- Selected countries (array of country internal_ids)
  countries TEXT[] DEFAULT '{}',

  -- Selected regions (array of region internal_ids)
  regions TEXT[] DEFAULT '{}',

  -- Watchlist: specific threat actors to track (array of intrusion-set internal_ids)
  threat_actors TEXT[] DEFAULT '{}',

  -- Keywords to watch for in reports
  keywords TEXT[] DEFAULT '{}',

  -- Alert preferences
  alert_threshold TEXT DEFAULT 'high' CHECK (alert_threshold IN ('critical', 'high', 'medium', 'all')),

  -- Summary preferences
  summary_frequency TEXT DEFAULT 'daily' CHECK (summary_frequency IN ('realtime', 'daily', 'weekly')),

  -- UI preferences
  show_global_threats BOOLEAN DEFAULT true,

  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),

  -- Ensure one profile per user
  UNIQUE(user_id)
);

-- Enable RLS
ALTER TABLE public.user_intel_profiles ENABLE ROW LEVEL SECURITY;

-- Users can only see and modify their own profile
CREATE POLICY "Users can view own profile"
  ON public.user_intel_profiles
  FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own profile"
  ON public.user_intel_profiles
  FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own profile"
  ON public.user_intel_profiles
  FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own profile"
  ON public.user_intel_profiles
  FOR DELETE
  USING (auth.uid() = user_id);

-- Create updated_at trigger
CREATE OR REPLACE FUNCTION public.update_user_intel_profile_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_user_intel_profiles_updated_at
  BEFORE UPDATE ON public.user_intel_profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.update_user_intel_profile_updated_at();

-- Create index for faster lookups
CREATE INDEX idx_user_intel_profiles_user_id ON public.user_intel_profiles(user_id);
