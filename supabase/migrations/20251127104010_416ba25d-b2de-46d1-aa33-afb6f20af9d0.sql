-- Create enum for transaction types
CREATE TYPE public.token_transaction_type AS ENUM (
  'ai_query',
  'subscription_grant',
  'admin_grant',
  'package_purchase',
  'refund',
  'signup_bonus'
);

-- Create enum for subscription billing period
CREATE TYPE public.billing_period AS ENUM ('monthly', 'annual');

-- Create enum for subscription status
CREATE TYPE public.subscription_status AS ENUM ('active', 'cancelled', 'expired');

-- Create user_tokens table
CREATE TABLE public.user_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE,
  token_balance INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create token_transactions table for audit trail
CREATE TABLE public.token_transactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  amount INTEGER NOT NULL,
  transaction_type token_transaction_type NOT NULL,
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create subscription_plans table
CREATE TABLE public.subscription_plans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  monthly_tokens INTEGER NOT NULL,
  price_monthly DECIMAL(10, 2) NOT NULL,
  price_annual DECIMAL(10, 2) NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create user_subscriptions table
CREATE TABLE public.user_subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  plan_id UUID REFERENCES public.subscription_plans(id) ON DELETE SET NULL,
  billing_period billing_period NOT NULL,
  status subscription_status NOT NULL DEFAULT 'active',
  current_period_start TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  current_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
  tokens_granted_this_period INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create token_packages table for bolt-ons
CREATE TABLE public.token_packages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  token_amount INTEGER NOT NULL,
  price DECIMAL(10, 2) NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS on all tables
ALTER TABLE public.user_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.token_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscription_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.token_packages ENABLE ROW LEVEL SECURITY;

-- RLS Policies for user_tokens
CREATE POLICY "Users can view their own tokens"
ON public.user_tokens FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Admins can view all tokens"
ON public.user_tokens FOR SELECT
USING (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Admins can update all tokens"
ON public.user_tokens FOR UPDATE
USING (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "System can insert tokens"
ON public.user_tokens FOR INSERT
WITH CHECK (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin'));

-- RLS Policies for token_transactions
CREATE POLICY "Users can view their own transactions"
ON public.token_transactions FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Admins can view all transactions"
ON public.token_transactions FOR SELECT
USING (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Admins can insert transactions"
ON public.token_transactions FOR INSERT
WITH CHECK (public.has_role(auth.uid(), 'admin'));

-- RLS Policies for subscription_plans (public read)
CREATE POLICY "Anyone can view active plans"
ON public.subscription_plans FOR SELECT
USING (is_active = true);

CREATE POLICY "Admins can manage plans"
ON public.subscription_plans FOR ALL
USING (public.has_role(auth.uid(), 'admin'));

-- RLS Policies for user_subscriptions
CREATE POLICY "Users can view their own subscriptions"
ON public.user_subscriptions FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Admins can manage all subscriptions"
ON public.user_subscriptions FOR ALL
USING (public.has_role(auth.uid(), 'admin'));

-- RLS Policies for token_packages (public read)
CREATE POLICY "Anyone can view active packages"
ON public.token_packages FOR SELECT
USING (is_active = true);

CREATE POLICY "Admins can manage packages"
ON public.token_packages FOR ALL
USING (public.has_role(auth.uid(), 'admin'));

-- Create function to deduct tokens (SECURITY DEFINER)
CREATE OR REPLACE FUNCTION public.deduct_token(p_user_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  current_balance INTEGER;
BEGIN
  -- Get current balance with row lock
  SELECT token_balance INTO current_balance
  FROM public.user_tokens
  WHERE user_id = p_user_id
  FOR UPDATE;
  
  -- Check if user has tokens
  IF current_balance IS NULL OR current_balance < 1 THEN
    RETURN FALSE;
  END IF;
  
  -- Deduct token
  UPDATE public.user_tokens
  SET token_balance = token_balance - 1,
      updated_at = now()
  WHERE user_id = p_user_id;
  
  -- Log transaction
  INSERT INTO public.token_transactions (user_id, amount, transaction_type, description)
  VALUES (p_user_id, -1, 'ai_query', 'AI search query');
  
  RETURN TRUE;
END;
$$;

-- Create function to grant tokens (admin only, SECURITY DEFINER)
CREATE OR REPLACE FUNCTION public.grant_tokens(p_user_id UUID, p_amount INTEGER, p_reason TEXT DEFAULT 'Admin grant')
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Ensure user has a token record
  INSERT INTO public.user_tokens (user_id, token_balance)
  VALUES (p_user_id, 0)
  ON CONFLICT (user_id) DO NOTHING;
  
  -- Add tokens
  UPDATE public.user_tokens
  SET token_balance = token_balance + p_amount,
      updated_at = now()
  WHERE user_id = p_user_id;
  
  -- Log transaction
  INSERT INTO public.token_transactions (user_id, amount, transaction_type, description)
  VALUES (p_user_id, p_amount, 'admin_grant', p_reason);
  
  RETURN TRUE;
END;
$$;

-- Create function to get user token balance
CREATE OR REPLACE FUNCTION public.get_token_balance(p_user_id UUID)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  balance INTEGER;
BEGIN
  SELECT token_balance INTO balance
  FROM public.user_tokens
  WHERE user_id = p_user_id;
  
  RETURN COALESCE(balance, 0);
END;
$$;

-- Create trigger for updated_at on user_tokens
CREATE TRIGGER update_user_tokens_updated_at
BEFORE UPDATE ON public.user_tokens
FOR EACH ROW
EXECUTE FUNCTION public.handle_updated_at();

-- Create trigger for updated_at on user_subscriptions
CREATE TRIGGER update_user_subscriptions_updated_at
BEFORE UPDATE ON public.user_subscriptions
FOR EACH ROW
EXECUTE FUNCTION public.handle_updated_at();

-- Insert default subscription plans
INSERT INTO public.subscription_plans (name, monthly_tokens, price_monthly, price_annual) VALUES
('Starter', 50, 9.99, 99.99),
('Professional', 200, 29.99, 299.99),
('Enterprise', 1000, 99.99, 999.99);

-- Insert default token packages
INSERT INTO public.token_packages (name, token_amount, price) VALUES
('50 Token Pack', 50, 4.99),
('150 Token Pack', 150, 12.99),
('500 Token Pack', 500, 39.99);