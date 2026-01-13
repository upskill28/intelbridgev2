-- Fix media_source_blacklist: require authentication to view
DROP POLICY IF EXISTS "Anyone can view media source blacklist" ON public.media_source_blacklist;
CREATE POLICY "Authenticated users can view media source blacklist" 
ON public.media_source_blacklist 
FOR SELECT 
USING (auth.uid() IS NOT NULL);

-- Fix lifetime_access_slots: require authentication to view
DROP POLICY IF EXISTS "Anyone can view lifetime slots" ON public.lifetime_access_slots;
CREATE POLICY "Authenticated users can view lifetime slots" 
ON public.lifetime_access_slots 
FOR SELECT 
USING (auth.uid() IS NOT NULL);

-- Fix domain_blacklist: require authentication to view (same pattern)
DROP POLICY IF EXISTS "Anyone can view domain blacklist" ON public.domain_blacklist;
CREATE POLICY "Authenticated users can view domain blacklist" 
ON public.domain_blacklist 
FOR SELECT 
USING (auth.uid() IS NOT NULL);