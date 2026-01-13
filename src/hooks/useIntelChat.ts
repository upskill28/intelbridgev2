import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "./useAuth";
import { toast } from "sonner";

export interface ChatSession {
  id: string;
  created_at: string;
  updated_at: string;
  user_id: string;
  title: string | null;
  is_archived: boolean;
}

export interface ToolCall {
  name: string;
  params: Record<string, unknown>;
}

export interface ChatMessage {
  id: string;
  created_at: string;
  session_id: string;
  role: "user" | "assistant";
  content: string;
  sources?: { type: string; id: string; name: string }[];
  token_usage?: { input: number; output: number };
  query_context?: { searchTerms?: string[]; entitiesFound?: number; toolCalls?: ToolCall[] };
}

export const useIntelChat = () => {
  const { session } = useAuth();
  const queryClient = useQueryClient();
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);

  const functionName = "intel-chat-mcp";

  // Fetch chat sessions
  const sessionsQuery = useQuery({
    queryKey: ["intel-chat-sessions"],
    queryFn: async () => {
      if (!session?.access_token) return [];

      const { data, error } = await supabase.functions.invoke(functionName, {
        body: { action: "list-sessions" },
        headers: { Authorization: `Bearer ${session.access_token}` },
      });

      if (error) throw error;
      if (data.error) throw new Error(data.error);

      return data.sessions as ChatSession[];
    },
    enabled: !!session,
  });

  // Fetch messages for active session
  const messagesQuery = useQuery({
    queryKey: ["intel-chat-messages", activeSessionId],
    queryFn: async () => {
      if (!session?.access_token || !activeSessionId) return [];

      const { data, error } = await supabase.functions.invoke(functionName, {
        body: { action: "get-messages", sessionId: activeSessionId },
        headers: { Authorization: `Bearer ${session.access_token}` },
      });

      if (error) throw error;
      if (data.error) throw new Error(data.error);

      return data.messages as ChatMessage[];
    },
    enabled: !!session && !!activeSessionId,
  });

  // Create new session
  const createSessionMutation = useMutation({
    mutationFn: async () => {
      if (!session?.access_token) throw new Error("Not authenticated");

      const { data, error } = await supabase.functions.invoke(functionName, {
        body: { action: "create-session" },
        headers: { Authorization: `Bearer ${session.access_token}` },
      });

      if (error) throw error;
      if (data.error) throw new Error(data.error);

      return data.session as ChatSession;
    },
    onSuccess: (newSession) => {
      queryClient.invalidateQueries({ queryKey: ["intel-chat-sessions"] });
      setActiveSessionId(newSession.id);
    },
    onError: (error) => {
      toast.error(error instanceof Error ? error.message : "Failed to create chat");
    },
  });

  // Delete session
  const deleteSessionMutation = useMutation({
    mutationFn: async (sessionId: string) => {
      if (!session?.access_token) throw new Error("Not authenticated");

      const { data, error } = await supabase.functions.invoke(functionName, {
        body: { action: "delete-session", sessionId },
        headers: { Authorization: `Bearer ${session.access_token}` },
      });

      if (error) throw error;
      if (data.error) throw new Error(data.error);

      return sessionId;
    },
    onSuccess: (deletedId) => {
      queryClient.invalidateQueries({ queryKey: ["intel-chat-sessions"] });
      if (activeSessionId === deletedId) {
        setActiveSessionId(null);
      }
      toast.success("Chat deleted");
    },
    onError: (error) => {
      toast.error(error instanceof Error ? error.message : "Failed to delete chat");
    },
  });

  // Send message
  const sendMessageMutation = useMutation({
    mutationFn: async ({ sessionId, message }: { sessionId: string; message: string }) => {
      if (!session?.access_token) throw new Error("Not authenticated");

      // Get current messages for context
      const currentMessages = messagesQuery.data || [];

      const { data, error } = await supabase.functions.invoke(functionName, {
        body: {
          action: "chat",
          sessionId,
          message,
          messages: currentMessages.map((m) => ({ role: m.role, content: m.content })),
        },
        headers: { Authorization: `Bearer ${session.access_token}` },
      });

      if (error) throw error;
      if (data.error) throw new Error(data.error);

      return data;
    },
    onMutate: async ({ sessionId, message }) => {
      // Cancel outgoing queries
      await queryClient.cancelQueries({ queryKey: ["intel-chat-messages", sessionId] });

      // Snapshot previous messages
      const previousMessages = queryClient.getQueryData<ChatMessage[]>(["intel-chat-messages", sessionId]);

      // Optimistically add user message
      const optimisticUserMessage: ChatMessage = {
        id: `temp-${Date.now()}`,
        created_at: new Date().toISOString(),
        session_id: sessionId,
        role: "user",
        content: message,
      };

      queryClient.setQueryData<ChatMessage[]>(
        ["intel-chat-messages", sessionId],
        (old) => [...(old || []), optimisticUserMessage]
      );

      return { previousMessages };
    },
    onSuccess: (_data, { sessionId }) => {
      // Refetch to get the actual saved messages
      queryClient.invalidateQueries({ queryKey: ["intel-chat-messages", sessionId] });
      queryClient.invalidateQueries({ queryKey: ["intel-chat-sessions"] });
    },
    onError: (error, { sessionId }, context) => {
      // Rollback on error
      if (context?.previousMessages) {
        queryClient.setQueryData(["intel-chat-messages", sessionId], context.previousMessages);
      }
      toast.error(error instanceof Error ? error.message : "Failed to send message");
    },
  });

  // Helper to start a new chat and send first message
  const startNewChat = useCallback(
    async (initialMessage?: string) => {
      const newSession = await createSessionMutation.mutateAsync();
      if (initialMessage) {
        await sendMessageMutation.mutateAsync({
          sessionId: newSession.id,
          message: initialMessage,
        });
      }
      return newSession;
    },
    [createSessionMutation, sendMessageMutation]
  );

  return {
    // Sessions
    sessions: sessionsQuery.data || [],
    isSessionsLoading: sessionsQuery.isLoading,

    // Active session
    activeSessionId,
    setActiveSessionId,

    // Messages
    messages: messagesQuery.data || [],
    isMessagesLoading: messagesQuery.isLoading,

    // Actions
    createSession: createSessionMutation.mutate,
    isCreatingSession: createSessionMutation.isPending,

    deleteSession: deleteSessionMutation.mutate,
    isDeletingSession: deleteSessionMutation.isPending,

    sendMessage: (message: string) => {
      if (!activeSessionId) return;
      sendMessageMutation.mutate({ sessionId: activeSessionId, message });
    },
    isSendingMessage: sendMessageMutation.isPending,

    startNewChat,

    // Refetch
    refetchSessions: sessionsQuery.refetch,
    refetchMessages: messagesQuery.refetch,
  };
};
