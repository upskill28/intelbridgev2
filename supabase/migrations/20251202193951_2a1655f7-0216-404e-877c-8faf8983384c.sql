-- Add summary column to media_reports table
ALTER TABLE public.media_reports 
ADD COLUMN summary TEXT;