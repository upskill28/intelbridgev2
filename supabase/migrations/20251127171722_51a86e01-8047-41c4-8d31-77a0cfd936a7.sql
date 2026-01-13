-- Create domain blacklist table
CREATE TABLE public.domain_blacklist (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  domain TEXT NOT NULL UNIQUE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  created_by UUID REFERENCES auth.users(id)
);

-- Enable RLS
ALTER TABLE public.domain_blacklist ENABLE ROW LEVEL SECURITY;

-- Anyone can read the blacklist (needed to filter on frontend)
CREATE POLICY "Anyone can view domain blacklist"
ON public.domain_blacklist
FOR SELECT
USING (true);

-- Only admins can manage the blacklist
CREATE POLICY "Admins can insert domains"
ON public.domain_blacklist
FOR INSERT
WITH CHECK (has_role(auth.uid(), 'admin'::app_role));

CREATE POLICY "Admins can delete domains"
ON public.domain_blacklist
FOR DELETE
USING (has_role(auth.uid(), 'admin'::app_role));

-- Insert the first blacklisted domain
INSERT INTO public.domain_blacklist (domain) VALUES ('otx.alienvault.com');