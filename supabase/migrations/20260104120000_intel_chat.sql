-- Intel Chat: Conversational AI interface for threat intelligence queries

-- Chat sessions table
CREATE TABLE IF NOT EXISTS intel_chat_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  title TEXT, -- Auto-generated from first message or user can rename
  is_archived BOOLEAN DEFAULT false
);

-- Chat messages table
CREATE TABLE IF NOT EXISTS intel_chat_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ DEFAULT now(),
  session_id UUID REFERENCES intel_chat_sessions(id) ON DELETE CASCADE NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
  content TEXT NOT NULL,
  sources JSONB, -- Array of {type, id, name, url} for citations
  token_usage JSONB, -- {input, output} token counts
  query_context JSONB -- What OpenCTI data was fetched for this response
);

-- Enable Row Level Security
ALTER TABLE intel_chat_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel_chat_messages ENABLE ROW LEVEL SECURITY;

-- RLS Policies: Users can only access their own chats
CREATE POLICY "Users can view their own chat sessions"
  ON intel_chat_sessions FOR SELECT
  TO authenticated
  USING (user_id = auth.uid());

CREATE POLICY "Users can create their own chat sessions"
  ON intel_chat_sessions FOR INSERT
  TO authenticated
  WITH CHECK (user_id = auth.uid());

CREATE POLICY "Users can update their own chat sessions"
  ON intel_chat_sessions FOR UPDATE
  TO authenticated
  USING (user_id = auth.uid());

CREATE POLICY "Users can delete their own chat sessions"
  ON intel_chat_sessions FOR DELETE
  TO authenticated
  USING (user_id = auth.uid());

CREATE POLICY "Users can view messages in their sessions"
  ON intel_chat_messages FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM intel_chat_sessions
      WHERE intel_chat_sessions.id = intel_chat_messages.session_id
      AND intel_chat_sessions.user_id = auth.uid()
    )
  );

CREATE POLICY "Users can insert messages in their sessions"
  ON intel_chat_messages FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM intel_chat_sessions
      WHERE intel_chat_sessions.id = intel_chat_messages.session_id
      AND intel_chat_sessions.user_id = auth.uid()
    )
  );

-- Service role policies for Edge Functions
CREATE POLICY "Service role can manage chat sessions"
  ON intel_chat_sessions FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Service role can manage chat messages"
  ON intel_chat_messages FOR ALL
  TO service_role
  USING (true)
  WITH CHECK (true);

-- Indexes for performance
CREATE INDEX idx_chat_sessions_user ON intel_chat_sessions(user_id);
CREATE INDEX idx_chat_sessions_updated ON intel_chat_sessions(updated_at DESC);
CREATE INDEX idx_chat_messages_session ON intel_chat_messages(session_id);
CREATE INDEX idx_chat_messages_created ON intel_chat_messages(created_at ASC);

-- Function to update session timestamp when messages are added
CREATE OR REPLACE FUNCTION update_chat_session_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  UPDATE intel_chat_sessions
  SET updated_at = now()
  WHERE id = NEW.session_id;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER on_chat_message_insert
  AFTER INSERT ON intel_chat_messages
  FOR EACH ROW
  EXECUTE FUNCTION update_chat_session_timestamp();
