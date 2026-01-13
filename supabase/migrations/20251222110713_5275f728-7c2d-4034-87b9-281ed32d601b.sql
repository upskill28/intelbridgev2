-- Fix PUBLIC_DATA_EXPOSURE: Restrict intelligence_summaries to authenticated users only
DROP POLICY IF EXISTS "Anyone can view intelligence summaries" ON public.intelligence_summaries;
CREATE POLICY "Authenticated users can view intelligence summaries" 
  ON public.intelligence_summaries 
  FOR SELECT 
  USING (auth.uid() IS NOT NULL);

-- Fix PUBLIC_DATA_EXPOSURE: Restrict media_reports to authenticated users only
DROP POLICY IF EXISTS "Anyone can view media reports" ON public.media_reports;
CREATE POLICY "Authenticated users can view media reports" 
  ON public.media_reports 
  FOR SELECT 
  USING (auth.uid() IS NOT NULL);

-- Fix DEFINER_OR_RPC_BYPASS: Remove overly permissive INSERT policy on media_reports
-- Service role will bypass RLS and can still insert data
DROP POLICY IF EXISTS "System can insert media reports" ON public.media_reports;