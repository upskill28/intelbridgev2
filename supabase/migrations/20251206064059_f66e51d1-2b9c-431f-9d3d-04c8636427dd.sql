-- Priority Intelligence Requirements table
CREATE TABLE public.priority_intelligence_requirements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('critical', 'high', 'medium', 'low')),
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- PIR Entity Links table (which entities a PIR tracks)
CREATE TABLE public.pir_entity_links (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pir_id UUID NOT NULL REFERENCES public.priority_intelligence_requirements(id) ON DELETE CASCADE,
  entity_type TEXT NOT NULL, -- e.g., 'intrusion-set', 'malware', 'tool', 'vulnerability', 'sector', 'country', 'ransomware-victim', 'media-report', 'advisory'
  entity_id TEXT NOT NULL, -- OpenCTI entity ID
  entity_name TEXT NOT NULL, -- Cached name for display
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(pir_id, entity_type, entity_id)
);

-- Enable RLS
ALTER TABLE public.priority_intelligence_requirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.pir_entity_links ENABLE ROW LEVEL SECURITY;

-- PIR policies - admin-only for now
CREATE POLICY "Admins can manage PIRs" 
ON public.priority_intelligence_requirements 
FOR ALL 
USING (has_role(auth.uid(), 'admin'))
WITH CHECK (has_role(auth.uid(), 'admin'));

-- PIR Entity Links policies - admin-only
CREATE POLICY "Admins can manage PIR entity links" 
ON public.pir_entity_links 
FOR ALL 
USING (
  EXISTS (
    SELECT 1 FROM public.priority_intelligence_requirements pir 
    WHERE pir.id = pir_id AND has_role(auth.uid(), 'admin')
  )
)
WITH CHECK (
  EXISTS (
    SELECT 1 FROM public.priority_intelligence_requirements pir 
    WHERE pir.id = pir_id AND has_role(auth.uid(), 'admin')
  )
);

-- Trigger for updated_at
CREATE TRIGGER update_pir_updated_at
BEFORE UPDATE ON public.priority_intelligence_requirements
FOR EACH ROW
EXECUTE FUNCTION public.handle_updated_at();