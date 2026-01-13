import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'npm:@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      throw new Error('No authorization header');
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

    // Create client with user's auth to verify they're an admin
    const supabaseUser = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } }
    });

    const { data: { user }, error: authError } = await supabaseUser.auth.getUser();
    if (authError || !user) {
      throw new Error('Not authenticated');
    }

    // Verify the user is an admin using service role client
    const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey);
    
    const { data: roleData, error: roleError } = await supabaseAdmin
      .from('user_roles')
      .select('role')
      .eq('user_id', user.id)
      .eq('role', 'admin')
      .single();

    if (roleError || !roleData) {
      throw new Error('Access denied: Admin privileges required');
    }

    const { action, targetUserId } = await req.json();

    if (!targetUserId) {
      throw new Error('Target user ID is required');
    }

    // Prevent self-deletion or self-demotion
    if (targetUserId === user.id && (action === 'delete' || action === 'remove-admin')) {
      throw new Error('Cannot modify your own admin status or delete yourself');
    }

    if (action === 'delete') {
      // Try to delete user from auth
      const { error: deleteError } = await supabaseAdmin.auth.admin.deleteUser(targetUserId);
      
      // If user not found in auth, clean up any orphaned records
      if (deleteError) {
        if (deleteError.code === 'user_not_found' || deleteError.message.includes('not found')) {
          console.log(`User ${targetUserId} not found in auth, cleaning up orphaned records`);
          
          // Clean up orphaned user_roles
          await supabaseAdmin.from('user_roles').delete().eq('user_id', targetUserId);
          // Clean up orphaned profiles if exists
          await supabaseAdmin.from('profiles').delete().eq('user_id', targetUserId);
          
          return new Response(JSON.stringify({ 
            success: true, 
            message: 'User records cleaned up successfully' 
          }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }
        
        console.error('Delete user error:', deleteError);
        throw new Error(`Failed to delete user: ${deleteError.message}`);
      }

      console.log(`User ${targetUserId} deleted by admin ${user.id}`);
      
      return new Response(JSON.stringify({ 
        success: true, 
        message: 'User deleted successfully' 
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (action === 'make-admin') {
      // Check if user already has admin role
      const { data: existingRole } = await supabaseAdmin
        .from('user_roles')
        .select('id')
        .eq('user_id', targetUserId)
        .eq('role', 'admin')
        .single();

      if (existingRole) {
        return new Response(JSON.stringify({ 
          success: true, 
          message: 'User is already an admin' 
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // Add admin role
      const { error: insertError } = await supabaseAdmin
        .from('user_roles')
        .insert({ user_id: targetUserId, role: 'admin' });

      if (insertError) {
        console.error('Make admin error:', insertError);
        throw new Error(`Failed to make user admin: ${insertError.message}`);
      }

      console.log(`User ${targetUserId} promoted to admin by ${user.id}`);

      return new Response(JSON.stringify({ 
        success: true, 
        message: 'User promoted to admin successfully' 
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (action === 'remove-admin') {
      // Remove admin role
      const { error: deleteError } = await supabaseAdmin
        .from('user_roles')
        .delete()
        .eq('user_id', targetUserId)
        .eq('role', 'admin');

      if (deleteError) {
        console.error('Remove admin error:', deleteError);
        throw new Error(`Failed to remove admin role: ${deleteError.message}`);
      }

      console.log(`Admin role removed from user ${targetUserId} by ${user.id}`);

      return new Response(JSON.stringify({
        success: true,
        message: 'Admin role removed successfully'
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (action === 'grant-lifetime') {
      // Check if user already has lifetime access
      const { data: existingGrant } = await supabaseAdmin
        .from('lifetime_grants')
        .select('id')
        .eq('user_id', targetUserId)
        .single();

      if (existingGrant) {
        return new Response(JSON.stringify({
          success: true,
          message: 'User already has lifetime access'
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // Grant lifetime access
      const { error: insertError } = await supabaseAdmin
        .from('lifetime_grants')
        .insert({
          user_id: targetUserId,
          granted_by: user.id,
          notes: 'Granted via admin panel'
        });

      if (insertError) {
        console.error('Grant lifetime error:', insertError);
        throw new Error(`Failed to grant lifetime access: ${insertError.message}`);
      }

      console.log(`Lifetime access granted to ${targetUserId} by admin ${user.id}`);

      return new Response(JSON.stringify({
        success: true,
        message: 'Lifetime access granted successfully'
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (action === 'revoke-lifetime') {
      // Remove lifetime access
      const { error: deleteError } = await supabaseAdmin
        .from('lifetime_grants')
        .delete()
        .eq('user_id', targetUserId);

      if (deleteError) {
        console.error('Revoke lifetime error:', deleteError);
        throw new Error(`Failed to revoke lifetime access: ${deleteError.message}`);
      }

      console.log(`Lifetime access revoked from ${targetUserId} by admin ${user.id}`);

      return new Response(JSON.stringify({
        success: true,
        message: 'Lifetime access revoked successfully'
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (action === 'list-lifetime-grants') {
      // Return list of all lifetime grants
      const { data: grants, error: listError } = await supabaseAdmin
        .from('lifetime_grants')
        .select('user_id, granted_at, notes');

      if (listError) {
        console.error('List lifetime grants error:', listError);
        throw new Error(`Failed to list lifetime grants: ${listError.message}`);
      }

      return new Response(JSON.stringify({
        success: true,
        grants: grants || []
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (action === 'list-chat-sessions') {
      // Return all Intel Chat sessions with their messages
      const { data: sessions, error: sessionsError } = await supabaseAdmin
        .from('intel_chat_sessions')
        .select(`
          id,
          user_id,
          title,
          created_at,
          updated_at
        `)
        .order('updated_at', { ascending: false })
        .limit(100);

      if (sessionsError) {
        console.error('List chat sessions error:', sessionsError);
        throw new Error(`Failed to list chat sessions: ${sessionsError.message}`);
      }

      // Get messages for each session (just count and last message)
      const sessionsWithStats = await Promise.all((sessions || []).map(async (session: any) => {
        const { data: messages, error: messagesError } = await supabaseAdmin
          .from('intel_chat_messages')
          .select('id, role, content, created_at')
          .eq('session_id', session.id)
          .order('created_at', { ascending: true });

        if (messagesError) {
          return { ...session, messageCount: 0, messages: [] };
        }

        return {
          ...session,
          messageCount: messages?.length || 0,
          messages: messages || []
        };
      }));

      return new Response(JSON.stringify({
        success: true,
        sessions: sessionsWithStats
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    throw new Error(`Unknown action: ${action}`);

  } catch (error) {
    console.error('Admin users error:', error);
    return new Response(JSON.stringify({ 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
