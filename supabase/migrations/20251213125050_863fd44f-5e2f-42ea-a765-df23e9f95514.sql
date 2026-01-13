-- Add trial_days column
ALTER TABLE subscription_plans ADD COLUMN IF NOT EXISTS trial_days integer DEFAULT 0;