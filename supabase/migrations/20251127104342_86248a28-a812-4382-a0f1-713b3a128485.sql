-- Create trigger function to auto-create user token record on signup
CREATE OR REPLACE FUNCTION public.handle_new_user_tokens()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.user_tokens (user_id, token_balance)
  VALUES (NEW.id, 5); -- Give new users 5 free tokens to try
  
  -- Log the signup bonus
  INSERT INTO public.token_transactions (user_id, amount, transaction_type, description)
  VALUES (NEW.id, 5, 'signup_bonus', 'Welcome bonus tokens');
  
  RETURN NEW;
END;
$$;

-- Create trigger on auth.users
CREATE TRIGGER on_auth_user_created_tokens
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user_tokens();