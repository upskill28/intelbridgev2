import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { createClient } from "npm:@supabase/supabase-js@2.57.2";
import OpenAI from "npm:openai@4.70.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface UserProfile {
  sectors: string[];
  regions: string[];
  countries: string[];
  threat_actors: string[];
  keywords: string[];
  show_global_threats: boolean;
}

interface BriefingRequest {
  profile: UserProfile;
  timeRange: string; // "24h", "7d", "30d"
}

const log = (step: string, details?: unknown) => {
  console.log(`[PERSONALIZED-BRIEFING] ${step}`, details ? JSON.stringify(details) : "");
};

// Query intel schema for recent data
async function fetchIntelData(
  supabase: ReturnType<typeof createClient>,
  profile: UserProfile,
  timeRange: string
) {
  const now = new Date();
  const startDate = new Date();

  switch (timeRange) {
    case "24h":
      startDate.setHours(startDate.getHours() - 24);
      break;
    case "7d":
      startDate.setDate(startDate.getDate() - 7);
      break;
    case "30d":
      startDate.setDate(startDate.getDate() - 30);
      break;
    default:
      startDate.setDate(startDate.getDate() - 7);
  }

  const startISO = startDate.toISOString();
  log("Fetching data", { startDate: startISO, timeRange });

  // Fetch threat reports
  const { data: threatReports } = await supabase
    .from("intel_stix_objects")
    .select("id, name, description, created, stix_data")
    .eq("type", "report")
    .contains("stix_data", { report_types: ["threat-report"] })
    .gte("created", startISO)
    .order("created", { ascending: false })
    .limit(25);

  // Fetch media reports
  const { data: mediaReports } = await supabase
    .from("intel_stix_objects")
    .select("id, name, description, created, stix_data")
    .eq("type", "report")
    .contains("stix_data", { report_types: ["media-report"] })
    .gte("created", startISO)
    .order("created", { ascending: false })
    .limit(20);

  // Fetch advisories
  const { data: advisories } = await supabase
    .from("intel_stix_objects")
    .select("id, name, description, created, stix_data")
    .eq("type", "report")
    .contains("stix_data", { report_types: ["advisory"] })
    .gte("created", startISO)
    .order("created", { ascending: false })
    .limit(15);

  // Fetch ransomware victims
  const { data: ransomwareVictims } = await supabase
    .from("intel_stix_objects")
    .select("id, name, created, stix_data")
    .eq("type", "identity")
    .contains("stix_data", { identity_class: "organization", x_opencti_type: "Victim" })
    .gte("created", startISO)
    .order("created", { ascending: false })
    .limit(50);

  // Fetch vulnerabilities linked to reports (same approach as overview)
  const recentReportIds = [
    ...(threatReports || []).map(r => r.id),
    ...(mediaReports || []).map(r => r.id),
  ].slice(0, 50);

  let vulnerabilities: Array<{
    id: string;
    name: string;
    created: string;
    stix_data: Record<string, unknown>;
  }> = [];

  if (recentReportIds.length > 0) {
    // Get relationships from reports to vulnerabilities
    const { data: relationships } = await supabase
      .from("intel_stix_objects")
      .select("stix_data")
      .eq("type", "relationship")
      .in("stix_data->>source_ref", recentReportIds);

    if (relationships) {
      const vulnIds = relationships
        .map(r => r.stix_data?.target_ref)
        .filter((ref): ref is string =>
          typeof ref === "string" && ref.startsWith("vulnerability--")
        );

      if (vulnIds.length > 0) {
        const { data: vulns } = await supabase
          .from("intel_stix_objects")
          .select("id, name, created, stix_data")
          .eq("type", "vulnerability")
          .in("id", vulnIds);

        vulnerabilities = vulns || [];
      }
    }
  }

  return {
    threatReports: threatReports || [],
    mediaReports: mediaReports || [],
    advisories: advisories || [],
    ransomwareVictims: ransomwareVictims || [],
    vulnerabilities,
  };
}

// Filter data based on user profile
function filterByProfile(
  data: Awaited<ReturnType<typeof fetchIntelData>>,
  profile: UserProfile
) {
  const hasFilters =
    profile.sectors.length > 0 ||
    profile.regions.length > 0 ||
    profile.countries.length > 0 ||
    profile.threat_actors.length > 0 ||
    profile.keywords.length > 0;

  // If no filters or show_global_threats is true, return all data
  if (!hasFilters || profile.show_global_threats) {
    return data;
  }

  const matchesProfile = (item: { name: string; description?: string; stix_data?: Record<string, unknown> }) => {
    const text = `${item.name} ${item.description || ""} ${JSON.stringify(item.stix_data || {})}`.toLowerCase();

    // Check keywords
    if (profile.keywords.some(kw => text.includes(kw.toLowerCase()))) {
      return true;
    }

    // Check sectors in stix_data labels
    const labels = (item.stix_data?.labels as string[]) || [];
    if (profile.sectors.some(s => labels.some(l => l.toLowerCase().includes(s.toLowerCase())))) {
      return true;
    }

    // Check countries/regions in text
    if (profile.countries.some(c => text.includes(c.toLowerCase()))) {
      return true;
    }

    if (profile.regions.some(r => text.includes(r.toLowerCase()))) {
      return true;
    }

    return false;
  };

  return {
    threatReports: data.threatReports.filter(matchesProfile),
    mediaReports: data.mediaReports.filter(matchesProfile),
    advisories: data.advisories.filter(matchesProfile),
    ransomwareVictims: data.ransomwareVictims,
    vulnerabilities: data.vulnerabilities,
  };
}

// Generate the AI briefing
async function generateBriefing(
  openai: OpenAI,
  data: Awaited<ReturnType<typeof fetchIntelData>>,
  profile: UserProfile,
  timeRange: string
) {
  const timeLabel = timeRange === "24h" ? "24 hours" : timeRange === "7d" ? "7 days" : "30 days";

  // Build context about user's profile
  const profileContext = [];
  if (profile.sectors.length > 0) {
    profileContext.push(`Sectors: ${profile.sectors.join(", ")}`);
  }
  if (profile.regions.length > 0) {
    profileContext.push(`Regions: ${profile.regions.join(", ")}`);
  }
  if (profile.countries.length > 0) {
    profileContext.push(`Countries: ${profile.countries.join(", ")}`);
  }
  if (profile.threat_actors.length > 0) {
    profileContext.push(`Watched threat actors: ${profile.threat_actors.join(", ")}`);
  }
  if (profile.keywords.length > 0) {
    profileContext.push(`Keywords of interest: ${profile.keywords.join(", ")}`);
  }

  // Summarize the data
  const threatSummary = data.threatReports.slice(0, 10).map(r => ({
    title: r.name,
    description: (r.description || "").substring(0, 500),
  }));

  const mediaSummary = data.mediaReports.slice(0, 10).map(r => ({
    title: r.name,
    description: (r.description || "").substring(0, 300),
  }));

  const advisorySummary = data.advisories.slice(0, 10).map(a => ({
    title: a.name,
    description: (a.description || "").substring(0, 300),
  }));

  // Process ransomware activity
  const ransomwareByGroup: Record<string, string[]> = {};
  for (const victim of data.ransomwareVictims) {
    const labels = (victim.stix_data?.labels as string[]) || [];
    const threatGroup = labels.find(l => !["victim", "ransomware"].includes(l.toLowerCase())) || "Unknown";
    if (!ransomwareByGroup[threatGroup]) {
      ransomwareByGroup[threatGroup] = [];
    }
    // Extract victim name from the naming pattern
    const victimName = victim.name.includes(":")
      ? victim.name.split(":").slice(1).join(":").trim()
      : victim.name;
    ransomwareByGroup[threatGroup].push(victimName);
  }

  // Process vulnerabilities
  const vulnSummary = data.vulnerabilities.slice(0, 10).map(v => {
    const cvss = v.stix_data?.x_opencti_cvss_base_severity || "Unknown";
    const score = v.stix_data?.x_opencti_cvss_base_score;
    const kev = v.stix_data?.x_opencti_cisa_kev;
    return {
      cve: v.name,
      severity: cvss,
      score,
      kev,
    };
  });

  const prompt = `You are a senior threat intelligence analyst preparing a personalized executive briefing.

${profileContext.length > 0 ? `## User Profile
${profileContext.join("\n")}
` : ""}
## Time Period
Last ${timeLabel}

## Threat Reports (${data.threatReports.length} total)
${threatSummary.length > 0 ? threatSummary.map(t => `- ${t.title}: ${t.description}`).join("\n") : "No threat reports in this period."}

## Media Coverage (${data.mediaReports.length} total)
${mediaSummary.length > 0 ? mediaSummary.map(m => `- ${m.title}: ${m.description}`).join("\n") : "No media reports in this period."}

## Security Advisories (${data.advisories.length} total)
${advisorySummary.length > 0 ? advisorySummary.map(a => `- ${a.title}: ${a.description}`).join("\n") : "No advisories in this period."}

## Ransomware Activity (${data.ransomwareVictims.length} victims)
${Object.keys(ransomwareByGroup).length > 0
    ? Object.entries(ransomwareByGroup)
        .map(([group, victims]) => `- ${group}: ${victims.length} victim(s)`)
        .join("\n")
    : "No ransomware activity in this period."}

## Vulnerabilities Discussed (${data.vulnerabilities.length} total)
${vulnSummary.length > 0
    ? vulnSummary.map(v => `- ${v.cve} (${v.severity}${v.score ? `, ${v.score}` : ""}${v.kev ? ", CISA KEV" : ""})`).join("\n")
    : "No notable vulnerabilities in this period."}

Generate a personalized threat briefing in this exact JSON format:
{
  "executive_summary": "Write 2-3 paragraphs providing an executive overview of the threat landscape. Highlight items most relevant to the user's profile (sectors, regions, keywords). Be specific about threats, actors, and recommended actions.",
  "key_priorities": ["List exactly 5 specific, actionable items ordered by priority. Reference specific CVEs, threat actors, or incidents. If the user has a profile, prioritize items relevant to their sectors/regions."],
  "statistics": {
    "threatReports": ${data.threatReports.length},
    "mediaReports": ${data.mediaReports.length},
    "advisories": ${data.advisories.length},
    "ransomwareVictims": ${data.ransomwareVictims.length},
    "vulnerabilities": ${data.vulnerabilities.length}
  },
  "recommended_actions": ["List 3-4 specific recommended actions based on the intelligence"]
}

Important: Make the briefing actionable and specific. Reference actual threats, CVEs, and actors from the data.`;

  log("Generating briefing", {
    promptLength: prompt.length,
    threatReports: data.threatReports.length,
    mediaReports: data.mediaReports.length,
  });

  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      {
        role: "system",
        content: "You are a senior threat intelligence analyst. Provide concise, actionable briefings. Always respond with valid JSON.",
      },
      {
        role: "user",
        content: prompt,
      },
    ],
    temperature: 0.4,
    max_tokens: 2000,
    response_format: { type: "json_object" },
  });

  try {
    const content = completion.choices[0].message.content || "{}";
    const result = JSON.parse(content);

    return {
      executive_summary: result.executive_summary || "Unable to generate summary.",
      key_priorities: result.key_priorities || [],
      statistics: result.statistics || {
        threatReports: data.threatReports.length,
        mediaReports: data.mediaReports.length,
        advisories: data.advisories.length,
        ransomwareVictims: data.ransomwareVictims.length,
        vulnerabilities: data.vulnerabilities.length,
      },
      recommended_actions: result.recommended_actions || [],
      generated_at: new Date().toISOString(),
    };
  } catch (error) {
    log("Parse error", { error: String(error) });
    throw new Error("Failed to parse AI response");
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  const startTime = Date.now();

  const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
  const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  const openaiKey = Deno.env.get("OPENAI_API_KEY") ?? "";

  const supabase = createClient(supabaseUrl, supabaseServiceKey, {
    auth: { persistSession: false },
  });

  try {
    log("Function started");

    // 1. Verify authentication
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      throw new Error("No authorization header");
    }

    const token = authHeader.replace("Bearer ", "");
    const { data: userData, error: userError } = await supabase.auth.getUser(token);
    if (userError || !userData.user) {
      throw new Error("Invalid authentication");
    }

    const userId = userData.user.id;
    log("User authenticated", { userId });

    // 2. Parse request body
    const body = await req.json() as BriefingRequest;
    const profile = body.profile || {
      sectors: [],
      regions: [],
      countries: [],
      threat_actors: [],
      keywords: [],
      show_global_threats: true,
    };
    const timeRange = body.timeRange || "7d";

    log("Request params", { timeRange, hasProfile: Object.values(profile).some(v => Array.isArray(v) && v.length > 0) });

    // 3. Validate OpenAI key
    if (!openaiKey) {
      throw new Error("OPENAI_API_KEY not configured");
    }

    const openai = new OpenAI({ apiKey: openaiKey });

    // 4. Fetch intel data from database
    const rawData = await fetchIntelData(supabase, profile, timeRange);
    log("Data fetched", {
      threatReports: rawData.threatReports.length,
      mediaReports: rawData.mediaReports.length,
      advisories: rawData.advisories.length,
      ransomwareVictims: rawData.ransomwareVictims.length,
      vulnerabilities: rawData.vulnerabilities.length,
    });

    // 5. Filter by profile (optional)
    const filteredData = filterByProfile(rawData, profile);
    log("Data filtered", {
      threatReports: filteredData.threatReports.length,
      mediaReports: filteredData.mediaReports.length,
      advisories: filteredData.advisories.length,
    });

    // 6. Generate AI briefing
    const briefing = await generateBriefing(openai, filteredData, profile, timeRange);

    const generationTime = Date.now() - startTime;
    log("Briefing generated", { time_ms: generationTime });

    return new Response(JSON.stringify({
      success: true,
      briefing,
      generation_time_ms: generationTime,
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 200,
    });

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    log("ERROR", { message: errorMessage });

    return new Response(JSON.stringify({ error: errorMessage }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 500,
    });
  }
});
