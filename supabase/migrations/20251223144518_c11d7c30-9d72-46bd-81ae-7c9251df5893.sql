-- Drop the trigger on auth.users for new user tokens
DROP TRIGGER IF EXISTS on_auth_user_created_tokens ON auth.users;

-- Drop token-related functions
DROP FUNCTION IF EXISTS public.handle_new_user_tokens();
DROP FUNCTION IF EXISTS public.deduct_token(uuid);
DROP FUNCTION IF EXISTS public.grant_tokens(uuid, integer, text);
DROP FUNCTION IF EXISTS public.get_token_balance(uuid);

-- Drop token-related tables
DROP TABLE IF EXISTS public.token_transactions;
DROP TABLE IF EXISTS public.user_tokens;
DROP TABLE IF EXISTS public.token_packages;