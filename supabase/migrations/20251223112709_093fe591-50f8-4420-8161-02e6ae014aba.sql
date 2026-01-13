-- Update subscription plans to flat rate pricing
-- Monthly: £24.99, Annual: £249.90 (10 months = 2 months free)
UPDATE subscription_plans 
SET price_monthly = 24.99, price_annual = 249.90
WHERE is_active = true;