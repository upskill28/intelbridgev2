-- Create lifetime_access_slots table
CREATE TABLE IF NOT EXISTS lifetime_access_slots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  plan_id uuid REFERENCES subscription_plans(id),
  max_slots integer NOT NULL DEFAULT 25,
  slots_used integer NOT NULL DEFAULT 0,
  created_at timestamptz DEFAULT now()
);

-- Enable RLS on lifetime_access_slots
ALTER TABLE lifetime_access_slots ENABLE ROW LEVEL SECURITY;

-- Anyone can view lifetime access slots
CREATE POLICY "Anyone can view lifetime slots"
ON lifetime_access_slots
FOR SELECT
USING (true);

-- Only admins can manage slots
CREATE POLICY "Admins can manage lifetime slots"
ON lifetime_access_slots
FOR ALL
USING (has_role(auth.uid(), 'admin'::app_role));

-- Seed lifetime_access_slots for the Lifetime plan
INSERT INTO lifetime_access_slots (plan_id, max_slots, slots_used)
SELECT id, 25, 0 FROM subscription_plans WHERE name = 'Lifetime Access'
AND NOT EXISTS (SELECT 1 FROM lifetime_access_slots WHERE plan_id = (SELECT id FROM subscription_plans WHERE name = 'Lifetime Access'));