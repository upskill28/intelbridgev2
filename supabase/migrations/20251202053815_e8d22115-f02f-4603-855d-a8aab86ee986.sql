-- Create intelligence_summaries table
CREATE TABLE public.intelligence_summaries (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  period_start TIMESTAMP WITH TIME ZONE NOT NULL,
  period_end TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  created_by UUID NOT NULL
);

-- Enable Row Level Security
ALTER TABLE public.intelligence_summaries ENABLE ROW LEVEL SECURITY;

-- Create policies
CREATE POLICY "Anyone can view intelligence summaries"
ON public.intelligence_summaries
FOR SELECT
USING (true);

CREATE POLICY "Admins can create intelligence summaries"
ON public.intelligence_summaries
FOR INSERT
WITH CHECK (has_role(auth.uid(), 'admin'::app_role));

CREATE POLICY "Admins can delete intelligence summaries"
ON public.intelligence_summaries
FOR DELETE
USING (has_role(auth.uid(), 'admin'::app_role));

-- Create index for better performance
CREATE INDEX idx_intelligence_summaries_created_at ON public.intelligence_summaries(created_at DESC);