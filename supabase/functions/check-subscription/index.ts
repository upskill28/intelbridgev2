import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import Stripe from "npm:stripe@18.5.0";
import { createClient } from "npm:@supabase/supabase-js@2.57.2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// Product IDs for different plans
const PRODUCT_IDS = {
  pro_monthly: "prod_TerS6GMYupH2G8",
  pro_annual: "prod_TerS1mNPK8pMcC",
  lifetime: "prod_TerSN1DxdekELD",
};

const logStep = (step: string, details?: any) => {
  const detailsStr = details ? ` - ${JSON.stringify(details)}` : '';
  console.log(`[CHECK-SUBSCRIPTION] ${step}${detailsStr}`);
};

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  const supabaseClient = createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    { auth: { persistSession: false } }
  );

  try {
    logStep("Function started");

    const stripeKey = Deno.env.get("STRIPE_SECRET_KEY");
    if (!stripeKey) throw new Error("STRIPE_SECRET_KEY is not set");
    logStep("Stripe key verified");

    const authHeader = req.headers.get("Authorization");
    if (!authHeader) throw new Error("No authorization header provided");
    logStep("Authorization header found");

    const token = authHeader.replace("Bearer ", "");
    const { data: userData, error: userError } = await supabaseClient.auth.getUser(token);
    if (userError) throw new Error(`Authentication error: ${userError.message}`);
    const user = userData.user;
    if (!user?.email) throw new Error("User not authenticated or email not available");
    logStep("User authenticated", { userId: user.id, email: user.email });

    // First, check if user is an admin (admins get lifetime access)
    const { data: userRole } = await supabaseClient
      .from("user_roles")
      .select("role")
      .eq("user_id", user.id)
      .maybeSingle();

    if (userRole?.role === "admin") {
      logStep("User is admin, granting lifetime access");
      return new Response(JSON.stringify({
        subscribed: true,
        plan: "lifetime",
        subscription_end: null,
        is_lifetime: true,
      }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    // Check for manually granted lifetime access in the database
    const { data: lifetimeGrant, error: grantError } = await supabaseClient
      .from("lifetime_grants")
      .select("*")
      .eq("user_id", user.id)
      .maybeSingle();

    if (lifetimeGrant) {
      logStep("Found manually granted lifetime access", { grantedAt: lifetimeGrant.granted_at });
      return new Response(JSON.stringify({
        subscribed: true,
        plan: "lifetime",
        subscription_end: null,
        is_lifetime: true,
      }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    // If no manual grant, check Stripe
    const stripe = new Stripe(stripeKey, { apiVersion: "2025-08-27.basil" });
    const customers = await stripe.customers.list({ email: user.email, limit: 1 });

    if (customers.data.length === 0) {
      logStep("No customer found, returning unsubscribed state");
      return new Response(JSON.stringify({ 
        subscribed: false, 
        plan: null,
        subscription_end: null,
        is_lifetime: false 
      }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    const customerId = customers.data[0].id;
    logStep("Found Stripe customer", { customerId });

    // Check for active or trialing subscriptions
    const subscriptions = await stripe.subscriptions.list({
      customer: customerId,
      status: "all",
      limit: 10,
    });

    // Filter for active or trialing subscriptions
    const validSubscriptions = subscriptions.data.filter(
      (sub: { status: string }) => sub.status === "active" || sub.status === "trialing"
    );

    let hasActiveSub = false;
    let plan = null;
    let subscriptionEnd = null;
    let isLifetime = false;

    if (validSubscriptions.length > 0) {
      hasActiveSub = true;
      const subscription = validSubscriptions[0];
      
      // Handle current_period_end - validate before converting
      const periodEnd = subscription.current_period_end || 
                       subscription.items?.data?.[0]?.current_period_end;
      
      logStep("Period end value", { 
        periodEnd, 
        type: typeof periodEnd,
        subscriptionStatus: subscription.status 
      });
      
      // Only convert if periodEnd is a valid number
      const periodEndNum = Number(periodEnd);
      if (Number.isFinite(periodEndNum) && periodEndNum > 0) {
        subscriptionEnd = new Date(periodEndNum * 1000).toISOString();
      } else {
        logStep("Invalid period end, skipping date conversion", { periodEnd });
      }
      
      const productId = subscription.items.data[0].price.product as string;
      
      if (productId === PRODUCT_IDS.pro_monthly) {
        plan = "pro_monthly";
      } else if (productId === PRODUCT_IDS.pro_annual) {
        plan = "pro_annual";
      }
      logStep("Active/trialing subscription found", { plan, subscriptionEnd, status: subscription.status });
    }

    // Check for lifetime purchase (one-time payment)
    if (!hasActiveSub) {
      // Check checkout sessions for lifetime purchases
      const sessions = await stripe.checkout.sessions.list({
        customer: customerId,
        limit: 100,
      });

      for (const session of sessions.data) {
        if (session.payment_status === "paid" && session.mode === "payment") {
          // Check if this was a lifetime purchase by looking at the line items
          const lineItems = await stripe.checkout.sessions.listLineItems(session.id);
          for (const item of lineItems.data) {
            if (item.price?.product === PRODUCT_IDS.lifetime) {
              hasActiveSub = true;
              isLifetime = true;
              plan = "lifetime";
              logStep("Lifetime purchase found", { sessionId: session.id });
              break;
            }
          }
        }
        if (isLifetime) break;
      }
    }

    logStep("Returning subscription status", { subscribed: hasActiveSub, plan, isLifetime });

    return new Response(JSON.stringify({
      subscribed: hasActiveSub,
      plan,
      subscription_end: subscriptionEnd,
      is_lifetime: isLifetime,
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 200,
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logStep("ERROR", { message: errorMessage });
    return new Response(JSON.stringify({ error: errorMessage }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 500,
    });
  }
});
