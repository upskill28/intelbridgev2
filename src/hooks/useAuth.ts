import { useEffect, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { supabase } from "@/integrations/supabase/client";

// Mock session for development/testing when auth is disabled
const mockSession: Session = {
  access_token: "mock-access-token",
  refresh_token: "mock-refresh-token",
  expires_in: 3600,
  expires_at: Math.floor(Date.now() / 1000) + 3600,
  token_type: "bearer",
  user: {
    id: "dev-user-id",
    email: "dev@intelbridge.app",
    aud: "authenticated",
    role: "authenticated",
    app_metadata: {},
    user_metadata: { name: "Dev User" },
    created_at: new Date().toISOString(),
  },
};

export const useAuth = () => {
  const [session, setSession] = useState<Session | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Check if auth is disabled (for development/testing)
  const isAuthDisabled = import.meta.env.VITE_AUTH_DISABLED === "true";

  useEffect(() => {
    // If auth is disabled, use mock session
    if (isAuthDisabled) {
      setSession(mockSession);
      setIsLoading(false);
      return;
    }

    // Normal auth flow
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setIsLoading(false);
    });

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
    });

    return () => subscription.unsubscribe();
  }, [isAuthDisabled]);

  const signOut = async () => {
    if (isAuthDisabled) {
      // No-op in dev mode
      return;
    }
    await supabase.auth.signOut();
  };

  return {
    session,
    isLoading,
    isAuthenticated: !!session,
    user: session?.user ?? null,
    signOut,
  };
};
