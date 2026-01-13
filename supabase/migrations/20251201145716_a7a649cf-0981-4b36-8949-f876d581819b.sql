-- Add CASCADE delete to user_tokens (drop existing constraint first)
ALTER TABLE public.user_tokens DROP CONSTRAINT IF EXISTS user_tokens_user_id_fkey;

ALTER TABLE public.user_tokens 
ADD CONSTRAINT user_tokens_user_id_fkey 
FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;

-- Add CASCADE delete to user_roles
ALTER TABLE public.user_roles DROP CONSTRAINT IF EXISTS user_roles_user_id_fkey;

ALTER TABLE public.user_roles 
ADD CONSTRAINT user_roles_user_id_fkey 
FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE