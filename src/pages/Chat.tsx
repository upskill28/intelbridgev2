import { useState, useRef, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { AppLayout } from "@/components/layout/AppLayout";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import {
  MessageSquare,
  Plus,
  Send,
  Trash2,
  Loader2,
  Bot,
  User,
  Sparkles,
  PanelLeftClose,
  PanelLeft,
} from "lucide-react";
import { useIntelChat } from "@/hooks/useIntelChat";
import type { ChatMessage } from "@/hooks/useIntelChat";
import { format } from "date-fns";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { cn } from "@/lib/utils";

// Message Bubble Component
function MessageBubble({ message }: { message: ChatMessage }) {
  const isUser = message.role === "user";

  return (
    <div className={cn("flex items-start gap-3", isUser && "flex-row-reverse")}>
      <div
        className={cn(
          "w-8 h-8 rounded-full flex items-center justify-center shrink-0",
          isUser ? "bg-primary text-primary-foreground" : "bg-primary/10"
        )}
      >
        {isUser ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4 text-primary" />}
      </div>
      <div
        className={cn(
          "flex-1 rounded-lg p-4 max-w-[85%]",
          isUser ? "bg-primary text-primary-foreground ml-auto" : "bg-muted"
        )}
      >
        {isUser ? (
          <p className="whitespace-pre-wrap">{message.content}</p>
        ) : (
          <div className="prose prose-sm dark:prose-invert max-w-none">
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                a: ({ href, children }) => (
                  <a
                    href={href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline"
                  >
                    {children}
                  </a>
                ),
                table: ({ children }) => (
                  <div className="my-3 overflow-x-auto">
                    <table className="min-w-full border-collapse text-sm">
                      {children}
                    </table>
                  </div>
                ),
                thead: ({ children }) => (
                  <thead className="bg-muted/50">{children}</thead>
                ),
                th: ({ children }) => (
                  <th className="border border-border px-3 py-2 text-left font-semibold">
                    {children}
                  </th>
                ),
                td: ({ children }) => (
                  <td className="border border-border px-3 py-2">{children}</td>
                ),
                tr: ({ children }) => (
                  <tr className="hover:bg-muted/30">{children}</tr>
                ),
                hr: () => <hr className="my-4 border-border" />,
              }}
            >
              {message.content}
            </ReactMarkdown>
          </div>
        )}
      </div>
    </div>
  );
}

// Suggested Questions
const suggestedQuestions = [
  "Who are the most active threat actors this month?",
  "Show me critical vulnerabilities being exploited",
  "What TTPs does APT29 use?",
  "What are the latest ransomware attacks?",
];

export function Chat() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [inputValue, setInputValue] = useState("");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const {
    sessions,
    isSessionsLoading,
    activeSessionId,
    setActiveSessionId,
    messages,
    isMessagesLoading,
    deleteSession,
    isDeletingSession,
    sendMessage,
    isSendingMessage,
    startNewChat,
  } = useIntelChat();

  // Sync session ID from URL on mount
  useEffect(() => {
    const sessionFromUrl = searchParams.get("session");
    if (sessionFromUrl && sessionFromUrl !== activeSessionId) {
      setActiveSessionId(sessionFromUrl);
    }
  }, [searchParams, setActiveSessionId, activeSessionId]);

  // Update URL when active session changes
  useEffect(() => {
    const currentSessionInUrl = searchParams.get("session");
    if (activeSessionId && activeSessionId !== currentSessionInUrl) {
      setSearchParams({ session: activeSessionId }, { replace: true });
    } else if (!activeSessionId && currentSessionInUrl) {
      setSearchParams({}, { replace: true });
    }
  }, [activeSessionId, searchParams, setSearchParams]);

  // Scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Focus input when session changes
  useEffect(() => {
    if (activeSessionId) {
      inputRef.current?.focus();
    }
  }, [activeSessionId]);

  const handleSend = async () => {
    if (!inputValue.trim() || isSendingMessage) return;

    const message = inputValue.trim();
    setInputValue("");

    if (!activeSessionId) {
      await startNewChat(message);
    } else {
      sendMessage(message);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleNewChat = () => {
    setActiveSessionId(null);
    setSearchParams({}, { replace: true });
    setInputValue("");
    inputRef.current?.focus();
  };

  return (
    <AppLayout>
      <div className="flex h-[calc(100vh-3rem)] -m-6">
        {/* Sidebar - Chat Sessions */}
        <div
          className={cn(
            "border-r bg-muted/30 flex flex-col transition-all duration-300",
            sidebarCollapsed ? "w-0 overflow-hidden" : "w-72"
          )}
        >
          <div className="p-3 border-b flex items-center justify-between">
            <h2 className="font-medium text-sm text-muted-foreground">History</h2>
            <div className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="sm"
                className="h-7 w-7 p-0"
                onClick={handleNewChat}
              >
                <Plus className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 w-7 p-0"
                onClick={() => setSidebarCollapsed(true)}
              >
                <PanelLeftClose className="h-4 w-4" />
              </Button>
            </div>
          </div>
          <ScrollArea className="flex-1">
            {isSessionsLoading ? (
              <div className="p-3 space-y-2">
                <Skeleton className="h-14 w-full" />
                <Skeleton className="h-14 w-full" />
                <Skeleton className="h-14 w-full" />
              </div>
            ) : sessions.length === 0 ? (
              <div className="p-4 text-center text-sm text-muted-foreground">
                No conversations yet.
                <br />
                Start a new chat!
              </div>
            ) : (
              <div className="p-2 space-y-1">
                {sessions.map((chatSession) => (
                  <div
                    key={chatSession.id}
                    className={cn(
                      "group flex items-start gap-2 p-3 rounded-lg cursor-pointer hover:bg-muted transition-colors",
                      activeSessionId === chatSession.id && "bg-muted"
                    )}
                    onClick={() => setActiveSessionId(chatSession.id)}
                  >
                    <MessageSquare className="h-4 w-4 text-muted-foreground shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm break-words line-clamp-2">
                        {chatSession.title || "New conversation"}
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {format(new Date(chatSession.updated_at), "MMM d, h:mm a")}
                      </p>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 w-6 p-0 shrink-0 opacity-0 group-hover:opacity-100 hover:bg-destructive/10"
                      onClick={(e) => {
                        e.stopPropagation();
                        if (confirm("Delete this conversation?")) {
                          deleteSession(chatSession.id);
                        }
                      }}
                      disabled={isDeletingSession}
                    >
                      <Trash2 className="h-3 w-3 text-destructive" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </ScrollArea>
        </div>

        {/* Sidebar Toggle Button (when collapsed) */}
        {sidebarCollapsed && (
          <Button
            variant="ghost"
            size="sm"
            className="absolute left-2 top-20 z-10 h-8 w-8 p-0"
            onClick={() => setSidebarCollapsed(false)}
          >
            <PanelLeft className="h-4 w-4" />
          </Button>
        )}

        {/* Chat Area */}
        <div className="flex-1 flex flex-col">
          {/* Header */}
          <div className="border-b p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center">
                <Sparkles className="w-4 h-4 text-primary" />
              </div>
              <div>
                <h1 className="font-semibold">Intel Chat</h1>
                <p className="text-xs text-muted-foreground">
                  Ask questions about threats, actors, and vulnerabilities
                </p>
              </div>
            </div>
            <Button variant="outline" size="sm" onClick={handleNewChat}>
              <Plus className="h-4 w-4 mr-2" />
              New Chat
            </Button>
          </div>

          {/* Messages */}
          <ScrollArea className="flex-1 p-4">
            {!activeSessionId && messages.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center max-w-lg mx-auto">
                <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mb-4">
                  <Sparkles className="h-8 w-8 text-primary" />
                </div>
                <h2 className="text-xl font-semibold mb-2">Intel Chat</h2>
                <p className="text-muted-foreground mb-6">
                  Ask questions about threat actors, malware, vulnerabilities, and cyber
                  threats. I'll search the intelligence database and provide insights.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 w-full">
                  {suggestedQuestions.map((suggestion) => (
                    <Button
                      key={suggestion}
                      variant="outline"
                      className="justify-start text-left h-auto py-3 px-4"
                      onClick={() => {
                        setInputValue(suggestion);
                        inputRef.current?.focus();
                      }}
                    >
                      <MessageSquare className="h-4 w-4 mr-2 shrink-0" />
                      <span className="truncate text-sm">{suggestion}</span>
                    </Button>
                  ))}
                </div>
              </div>
            ) : isMessagesLoading ? (
              <div className="space-y-4 max-w-3xl mx-auto">
                <Skeleton className="h-20 w-3/4" />
                <Skeleton className="h-32 w-3/4 ml-auto" />
              </div>
            ) : (
              <div className="space-y-4 max-w-3xl mx-auto">
                {messages.map((msg) => (
                  <MessageBubble key={msg.id} message={msg} />
                ))}
                {isSendingMessage && (
                  <div className="flex items-start gap-3">
                    <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center shrink-0">
                      <Bot className="h-4 w-4 text-primary" />
                    </div>
                    <div className="flex-1 bg-muted rounded-lg p-4">
                      <div className="flex items-center gap-2 text-muted-foreground">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        <span className="text-sm">Querying intelligence database...</span>
                      </div>
                    </div>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>
            )}
          </ScrollArea>

          {/* Input Area */}
          <div className="border-t p-4 bg-background">
            <div className="max-w-3xl mx-auto flex gap-2">
              <Input
                ref={inputRef}
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about threat actors, malware, vulnerabilities..."
                className="flex-1 h-11"
                disabled={isSendingMessage}
              />
              <Button
                onClick={handleSend}
                disabled={!inputValue.trim() || isSendingMessage}
                className="h-11"
              >
                {isSendingMessage ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Send className="h-4 w-4" />
                )}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground text-center mt-2">
              Intel Chat searches your threat intelligence database to provide contextual
              answers.
            </p>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
