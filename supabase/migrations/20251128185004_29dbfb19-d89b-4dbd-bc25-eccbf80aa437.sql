-- Create media_reports table for storing RSS feed articles with AI summaries
CREATE TABLE public.media_reports (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  title TEXT NOT NULL,
  link TEXT NOT NULL UNIQUE,
  published_at TIMESTAMP WITH TIME ZONE NOT NULL,
  source TEXT NOT NULL DEFAULT 'Threatable',
  summary TEXT,
  original_description TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable Row Level Security
ALTER TABLE public.media_reports ENABLE ROW LEVEL SECURITY;

-- Create policy for public read access (anyone can view media reports)
CREATE POLICY "Anyone can view media reports" 
ON public.media_reports 
FOR SELECT 
USING (true);

-- Create policy for service role to insert/update (edge functions use service role)
CREATE POLICY "Service role can manage media reports"
ON public.media_reports
FOR ALL
USING (true)
WITH CHECK (true);

-- Create index for faster queries by published date
CREATE INDEX idx_media_reports_published_at ON public.media_reports (published_at DESC);

-- Create trigger for automatic timestamp updates
CREATE TRIGGER update_media_reports_updated_at
BEFORE UPDATE ON public.media_reports
FOR EACH ROW
EXECUTE FUNCTION public.handle_updated_at();