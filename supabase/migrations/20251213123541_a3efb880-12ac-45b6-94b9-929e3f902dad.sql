-- First make monthly_tokens nullable, then drop it
ALTER TABLE subscription_plans ALTER COLUMN monthly_tokens DROP NOT NULL;
ALTER TABLE subscription_plans DROP COLUMN monthly_tokens;