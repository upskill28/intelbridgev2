-- Create table for manually granted lifetime access
CREATE TABLE public.lifetime_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE,
  granted_by uuid,
  granted_at timestamp with time zone NOT NULL DEFAULT now(),
  notes text
);

-- Enable RLS
ALTER TABLE public.lifetime_grants ENABLE ROW LEVEL SECURITY;

-- Policy: Users can view their own grant
CREATE POLICY "Users can view their own lifetime grant"
ON public.lifetime_grants
FOR SELECT
USING (auth.uid() = user_id);

-- Policy: Admins can manage all grants
CREATE POLICY "Admins can manage lifetime grants"
ON public.lifetime_grants
FOR ALL
USING (has_role(auth.uid(), 'admin'::app_role));

-- Grant lifetime access to all existing users
INSERT INTO public.lifetime_grants (user_id, notes)
VALUES 
  ('a4694286-304d-4317-aa00-ebb4c238dc0f', 'Founding user - info@intelbridge.co.uk'),
  ('28bc2108-81c5-45fe-bb2b-f873bbbb78fc', 'Founding user - markfrost.mf@gmail.com'),
  ('47ebf130-d2df-405e-a476-14b48e82af65', 'Founding user - jonfleet@hotmail.co.uk'),
  ('9db06d31-60c6-43ae-9e46-30e0731ed2f9', 'Founding user - glenn.mcauley@cadentgas.com'),
  ('3895b572-f57e-4c8a-bf72-471137b8598d', 'Founding user - an6791168@gmail.com');