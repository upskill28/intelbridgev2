-- Fix token management functions with proper authorization checks

-- Update deduct_token to only allow users to deduct their own tokens
CREATE OR REPLACE FUNCTION public.deduct_token(p_user_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  current_balance INTEGER;
BEGIN
  -- Only allow users to deduct their own tokens
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Unauthorized: Authentication required';
  END IF;
  
  IF auth.uid() != p_user_id THEN
    RAISE EXCEPTION 'Unauthorized: Can only deduct your own tokens';
  END IF;

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

-- Update grant_tokens to only allow admins
CREATE OR REPLACE FUNCTION public.grant_tokens(p_user_id uuid, p_amount integer, p_reason text DEFAULT 'Admin grant'::text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Only admins can grant tokens
  IF NOT public.has_role(auth.uid(), 'admin') THEN
    RAISE EXCEPTION 'Unauthorized: Admin privileges required';
  END IF;

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

-- Update get_token_balance to only allow own balance or admin access
CREATE OR REPLACE FUNCTION public.get_token_balance(p_user_id uuid)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  balance INTEGER;
BEGIN
  -- Only allow users to view their own balance or admins to view any
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Unauthorized: Authentication required';
  END IF;
  
  IF auth.uid() != p_user_id AND NOT public.has_role(auth.uid(), 'admin') THEN
    RAISE EXCEPTION 'Unauthorized: Can only view your own balance';
  END IF;

  SELECT token_balance INTO balance
  FROM public.user_tokens
  WHERE user_id = p_user_id;
  
  RETURN COALESCE(balance, 0);
END;
$$;