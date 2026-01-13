import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// ============================================================================
// INTEL SCHEMA REST API HELPERS
// ============================================================================

interface IntelQueryOptions {
  select?: string;
  filters?: string[];
  order?: string;
  limit?: number;
  single?: boolean;
}

async function queryIntelSchema(
  supabaseUrl: string,
  serviceKey: string,
  table: string,
  options: IntelQueryOptions = {}
): Promise<{ data: any; error: any; count?: number }> {
  const { select = '*', filters = [], order, limit, single } = options;

  // Build query string directly to preserve JSONB path syntax (->)
  // URLSearchParams would encode -> as -%3E which breaks PostgREST
  const queryParts: string[] = [];
  queryParts.push(`select=${select}`);

  for (const filter of filters) {
    queryParts.push(filter);
  }

  if (order) {
    queryParts.push(`order=${order}`);
  }

  if (limit) {
    queryParts.push(`limit=${limit}`);
  }

  const url = `${supabaseUrl}/rest/v1/${table}?${queryParts.join('&')}`;

  try {
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${serviceKey}`,
      'apikey': serviceKey,
      'Accept-Profile': 'intel',
      'Content-Type': 'application/json',
    };

    // For count queries
    if (options.select?.includes('count')) {
      headers['Prefer'] = 'count=exact';
    }

    const response = await fetch(url, {
      method: 'GET',
      headers,
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Intel query error: ${response.status}`, errorText);
      return { data: null, error: new Error(`Query failed: ${response.status}`) };
    }

    const data = await response.json();

    // Get count from headers if available
    const contentRange = response.headers.get('content-range');
    let count: number | undefined;
    if (contentRange) {
      const match = contentRange.match(/\/(\d+|\*)/);
      if (match && match[1] !== '*') {
        count = parseInt(match[1], 10);
      }
    }

    if (single) {
      return { data: data?.[0] || null, error: null };
    }

    return { data, error: null, count };
  } catch (error) {
    console.error('Intel query exception:', error);
    return { data: null, error };
  }
}

// Helper to build PostgREST filter strings
// Note: Values should NOT be URL-encoded as we build the query string directly
function buildFilter(column: string, operator: string, value: any): string {
  switch (operator) {
    case 'eq':
      return `${column}=eq.${value}`;
    case 'neq':
      return `${column}=neq.${value}`;
    case 'ilike':
      return `${column}=ilike.${value}`;
    case 'gte':
      return `${column}=gte.${value}`;
    case 'lte':
      return `${column}=lte.${value}`;
    case 'in':
      return `${column}=in.(${value.join(',')})`;
    case 'cs':
      // Contains for JSONB arrays - format: column=cs.["value"]
      return `${column}=cs.${JSON.stringify(value)}`;
    case 'or':
      return `or=(${value})`;
    default:
      return `${column}=${operator}.${value}`;
  }
}

// ============================================================================
// MCP TOOLS DEFINITIONS
// ============================================================================

const MCP_TOOLS = [
  {
    type: "function",
    function: {
      name: "search_threat_actors",
      description: "Search for threat actors, APT groups, or intrusion sets by name. Use this when the user asks about a specific threat actor, APT group, nation-state actor, or hacking group.",
      parameters: {
        type: "object",
        properties: {
          search_term: {
            type: "string",
            description: "The name or alias of the threat actor to search for (e.g., 'APT29', 'Lazarus', 'Fancy Bear', 'LockBit')"
          }
        },
        required: ["search_term"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "search_malware",
      description: "Search for malware families, ransomware, or malicious tools by name. Use this when the user asks about specific malware, ransomware strains, or malicious software.",
      parameters: {
        type: "object",
        properties: {
          search_term: {
            type: "string",
            description: "The name of the malware to search for (e.g., 'Cobalt Strike', 'Emotet', 'TrickBot')"
          }
        },
        required: ["search_term"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_ransomware_victims",
      description: "Get ransomware victims for a specific time period. IMPORTANT: Set days_back=0 for 'today', days_back=7 for 'last week', days_back=30 for 'last month'. Default is 7 days.",
      parameters: {
        type: "object",
        properties: {
          days_back: {
            type: "integer",
            description: "Number of days to look back. Use 0 for today only, 7 for last week, 30 for last month. Default: 7",
            default: 7
          },
          threat_group: {
            type: "string",
            description: "Optional: Filter by specific ransomware group (e.g., 'LockBit', 'BlackCat', 'Cl0p')"
          },
          limit: {
            type: "integer",
            description: "Maximum number of results to return (default: 20)",
            default: 20
          }
        }
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_ransomware_statistics",
      description: "Get victim count statistics for today, last 7 days, and last 30 days. Use this when users ask 'how many' victims or want quick counts without detailed victim info.",
      parameters: {
        type: "object",
        properties: {}
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_vulnerabilities",
      description: "Get recent vulnerabilities (CVEs) with optional severity filtering. IMPORTANT: Set days_back=0 for 'today', days_back=7 for 'last week'. Default is 14 days.",
      parameters: {
        type: "object",
        properties: {
          days_back: {
            type: "integer",
            description: "Number of days to look back. Use 0 for today only, 7 for last week, 14 for last 2 weeks. Default: 14",
            default: 14
          },
          severity: {
            type: "string",
            enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            description: "Filter by CVSS severity level"
          },
          limit: {
            type: "integer",
            description: "Maximum number of results (default: 20)",
            default: 20
          }
        }
      }
    }
  },
  {
    type: "function",
    function: {
      name: "search_vulnerabilities",
      description: "Search for a specific vulnerability by CVE ID. Use this when the user mentions a specific CVE like 'CVE-2024-1234'.",
      parameters: {
        type: "object",
        properties: {
          cve_id: {
            type: "string",
            description: "The CVE identifier (e.g., 'CVE-2024-1234')"
          }
        },
        required: ["cve_id"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_attack_patterns",
      description: "Get recently used/modified TTPs (Tactics, Techniques, and Procedures) and MITRE ATT&CK patterns. Set days_back=0 for today, 7 for last week.",
      parameters: {
        type: "object",
        properties: {
          days_back: {
            type: "integer",
            description: "Number of days to look back. Use 0 for today, 7 for last week, 30 for last month. Default: 7",
            default: 7
          },
          limit: {
            type: "integer",
            description: "Maximum number of results (default: 25)",
            default: 25
          }
        }
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_ttps_for_actor",
      description: "Get the TTPs (Tactics, Techniques, and Procedures) used by a specific threat actor. Use this when users ask what techniques or methods a threat actor uses.",
      parameters: {
        type: "object",
        properties: {
          actor_name: {
            type: "string",
            description: "Name of the threat actor (e.g., 'APT29', 'Lazarus Group')"
          }
        },
        required: ["actor_name"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_threat_actor_profile",
      description: "Get detailed profile information about a specific threat actor, including their targets, malware, TTPs, and activity timeline.",
      parameters: {
        type: "object",
        properties: {
          actor_name: {
            type: "string",
            description: "Name of the threat actor (e.g., 'APT29', 'Lazarus Group', 'Fancy Bear')"
          }
        },
        required: ["actor_name"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_malware_profile",
      description: "Get detailed profile information about a specific malware family, including capabilities, used by actors, and indicators.",
      parameters: {
        type: "object",
        properties: {
          malware_name: {
            type: "string",
            description: "Name of the malware (e.g., 'Cobalt Strike', 'Emotet', 'TrickBot')"
          }
        },
        required: ["malware_name"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_vulnerability_profile",
      description: "Get detailed information about a specific CVE including severity, affected products, and related threat intelligence.",
      parameters: {
        type: "object",
        properties: {
          cve_id: {
            type: "string",
            description: "The CVE identifier (e.g., 'CVE-2024-1234')"
          }
        },
        required: ["cve_id"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_advisories",
      description: "Get recent security advisories from sources like CISA, NHS, etc. Set days_back=0 for today, 7 for last week.",
      parameters: {
        type: "object",
        properties: {
          days_back: {
            type: "integer",
            description: "Number of days to look back. Use 0 for today, 7 for last week, 30 for last month. Default: 7",
            default: 7
          },
          limit: {
            type: "integer",
            description: "Maximum number of results (default: 15)",
            default: 15
          }
        }
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_media_reports",
      description: "Get recent cybersecurity news and media reports. Set days_back=0 for today, 7 for last week.",
      parameters: {
        type: "object",
        properties: {
          days_back: {
            type: "integer",
            description: "Number of days to look back. Use 0 for today, 7 for last week. Default: 7",
            default: 7
          },
          limit: {
            type: "integer",
            description: "Maximum number of results (default: 15)",
            default: 15
          }
        }
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_threat_reports",
      description: "Get recent threat intelligence reports. These are detailed analysis reports about threats, campaigns, or incidents.",
      parameters: {
        type: "object",
        properties: {
          days_back: {
            type: "integer",
            description: "Number of days to look back. Default: 14",
            default: 14
          },
          limit: {
            type: "integer",
            description: "Maximum number of results (default: 15)",
            default: 15
          }
        }
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_actors_targeting_sector",
      description: "Find threat actors that target a specific industry sector.",
      parameters: {
        type: "object",
        properties: {
          sector: {
            type: "string",
            description: "The industry sector (e.g., 'Healthcare', 'Finance', 'Government', 'Energy')"
          },
          limit: {
            type: "integer",
            description: "Maximum number of results (default: 10)",
            default: 10
          }
        },
        required: ["sector"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_malware_of_actor",
      description: "Get the malware tools and families used by a specific threat actor.",
      parameters: {
        type: "object",
        properties: {
          actor_name: {
            type: "string",
            description: "Name of the threat actor"
          }
        },
        required: ["actor_name"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_campaigns",
      description: "Get recent threat campaigns. Campaigns are coordinated threat activities with specific objectives.",
      parameters: {
        type: "object",
        properties: {
          days_back: {
            type: "integer",
            description: "Number of days to look back. Default: 30",
            default: 30
          },
          limit: {
            type: "integer",
            description: "Maximum number of results (default: 15)",
            default: 15
          }
        }
      }
    }
  },
  {
    type: "function",
    function: {
      name: "general_search",
      description: "Perform a general search across all intelligence entities. Use this as a fallback when other specific tools don't match.",
      parameters: {
        type: "object",
        properties: {
          search_query: {
            type: "string",
            description: "The search query"
          },
          limit: {
            type: "integer",
            description: "Maximum number of results (default: 20)",
            default: 20
          }
        },
        required: ["search_query"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "search_indicators",
      description: "Search for indicators of compromise (IOCs) like IP addresses, domains, file hashes, or URLs.",
      parameters: {
        type: "object",
        properties: {
          search_term: {
            type: "string",
            description: "The indicator value or pattern to search for"
          },
          indicator_type: {
            type: "string",
            enum: ["ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "email-addr"],
            description: "Optional: Filter by indicator type"
          },
          limit: {
            type: "integer",
            description: "Maximum number of results (default: 20)",
            default: 20
          }
        },
        required: ["search_term"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_indicator_detail",
      description: "Get detailed information about a specific indicator including related threats and context.",
      parameters: {
        type: "object",
        properties: {
          indicator_value: {
            type: "string",
            description: "The indicator value (IP, domain, hash, etc.)"
          }
        },
        required: ["indicator_value"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "search_tools",
      description: "Search for legitimate tools that are abused by threat actors (e.g., 'PsExec', 'Mimikatz', 'PowerShell Empire').",
      parameters: {
        type: "object",
        properties: {
          search_term: {
            type: "string",
            description: "Name of the tool to search for"
          },
          limit: {
            type: "integer",
            description: "Maximum number of results (default: 10)",
            default: 10
          }
        },
        required: ["search_term"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_tool_profile",
      description: "Get detailed information about a specific tool, including who uses it and how.",
      parameters: {
        type: "object",
        properties: {
          tool_name: {
            type: "string",
            description: "Name of the tool (e.g., 'Mimikatz', 'Cobalt Strike')"
          }
        },
        required: ["tool_name"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_report_detail",
      description: "Get detailed information about a specific threat report by its ID.",
      parameters: {
        type: "object",
        properties: {
          report_id: {
            type: "string",
            description: "The report ID"
          }
        },
        required: ["report_id"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "search_mitigations",
      description: "Search for security mitigations and countermeasures (MITRE ATT&CK mitigations, courses of action).",
      parameters: {
        type: "object",
        properties: {
          search_term: {
            type: "string",
            description: "Search term for mitigations (e.g., 'phishing', 'credential theft', 'lateral movement')"
          },
          limit: {
            type: "integer",
            description: "Maximum number of results (default: 15)",
            default: 15
          }
        },
        required: ["search_term"]
      }
    }
  }
];

// ============================================================================
// RELATIONSHIP HELPER FUNCTIONS
// ============================================================================

interface IntelContext {
  supabaseUrl: string;
  serviceKey: string;
}

async function fetchRelatedEntities(
  ctx: IntelContext,
  entityId: string,
  relationshipType: string = 'object-ref'
): Promise<{ sectors: any[]; countries: any[]; threatActors: any[]; malware: any[]; vulnerabilities: any[]; attackPatterns: any[] }> {
  const result = {
    sectors: [] as any[],
    countries: [] as any[],
    threatActors: [] as any[],
    malware: [] as any[],
    vulnerabilities: [] as any[],
    attackPatterns: [] as any[],
  };

  try {
    // Fetch relationships FROM this entity using source_id column
    const { data: rels } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'relationship_current', {
      select: 'target_id,relationship_type',
      filters: [
        buildFilter('relationship_type', 'eq', relationshipType),
        buildFilter('source_id', 'eq', entityId),
      ],
    });

    if (!rels || rels.length === 0) return result;

    const targetIds = rels.map((r: any) => r.target_id).filter(Boolean);
    if (targetIds.length === 0) return result;

    const { data: entities } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
      select: 'internal_id,name,entity_type,data',
      filters: [buildFilter('internal_id', 'in', targetIds)],
    });

    for (const entity of entities || []) {
      const item = { id: entity.internal_id, name: entity.name, linkPath: '' };
      switch (entity.entity_type) {
        case 'Sector':
          item.linkPath = `/sectors/${entity.internal_id}`;
          result.sectors.push(item);
          break;
        case 'Country':
          item.linkPath = `/countries/${entity.internal_id}`;
          result.countries.push(item);
          break;
        case 'Intrusion-Set':
          item.linkPath = `/intrusion-sets/${entity.internal_id}`;
          result.threatActors.push(item);
          break;
        case 'Malware':
          item.linkPath = `/malware/${entity.internal_id}`;
          result.malware.push(item);
          break;
        case 'Vulnerability':
          item.linkPath = `/vulnerabilities/${entity.internal_id}`;
          result.vulnerabilities.push(item);
          break;
        case 'Attack-Pattern':
          item.linkPath = `/attack-patterns/${entity.internal_id}`;
          result.attackPatterns.push(item);
          break;
      }
    }
  } catch (error) {
    console.error('fetchRelatedEntities error:', error);
  }

  return result;
}

async function fetchReverseRelatedEntities(
  ctx: IntelContext,
  entityId: string,
  relationshipTypes: string[] = ['uses', 'targets']
): Promise<{ usedBy: any[]; targetedBy: any[] }> {
  const result = { usedBy: [] as any[], targetedBy: [] as any[] };

  try {
    // Build OR filter for relationship types
    const typeFilters = relationshipTypes.map(t => `relationship_type.eq.${t}`).join(',');

    // Fetch relationships where this entity is the TARGET (reverse lookup)
    const { data: rels } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'relationship_current', {
      select: 'source_id,relationship_type',
      filters: [
        `or=(${typeFilters})`,
        buildFilter('target_id', 'eq', entityId),
      ],
    });

    if (!rels || rels.length === 0) return result;

    const sourceIds = rels.map((r: any) => r.source_id).filter(Boolean);
    if (sourceIds.length === 0) return result;

    const { data: entities } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
      select: 'internal_id,name,entity_type',
      filters: [buildFilter('internal_id', 'in', sourceIds)],
    });

    const entityMap = new Map((entities || []).map((e: any) => [e.internal_id, e]));

    for (const rel of rels) {
      const entity = entityMap.get(rel.source_id);
      if (!entity) continue;

      const item = {
        id: entity.internal_id,
        name: entity.name,
        type: entity.entity_type,
        linkPath: `/${entity.entity_type.toLowerCase().replace('-', '-')}s/${entity.internal_id}`,
      };

      if (rel.relationship_type === 'uses') {
        result.usedBy.push(item);
      } else if (rel.relationship_type === 'targets') {
        result.targetedBy.push(item);
      }
    }
  } catch (error) {
    console.error('fetchReverseRelatedEntities error:', error);
  }

  return result;
}

// ============================================================================
// TOOL IMPLEMENTATIONS (Using Direct REST API)
// ============================================================================

async function tool_search_threat_actors(ctx: IntelContext, params: any) {
  const { search_term } = params;

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_updated_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Intrusion-Set'),
      `or=(name.ilike.*${search_term}*,data->>aliases.ilike.*${search_term}*)`,
    ],
    order: 'source_updated_at.desc',
    limit: 10,
  });

  if (error) throw error;

  const results = [];
  for (const row of data || []) {
    const d = row.data || {};
    const related = await fetchRelatedEntities(ctx, row.internal_id, 'targets');

    results.push({
      id: row.internal_id,
      name: row.name,
      description: d.description || '',
      aliases: d.aliases || [],
      motivation: d.primary_motivation || '',
      resourceLevel: d.resource_level || '',
      goals: d.goals || [],
      labels: (d.labels || []).map((l: any) => typeof l === 'string' ? l : l.value),
      targetedCountries: related.countries.map((c: any) => c.name),
      targetedSectors: related.sectors.map((s: any) => s.name),
      modified: row.source_updated_at,
      linkPath: `/intrusion-sets/${row.internal_id}`,
    });
  }

  return results;
}

async function tool_search_malware(ctx: IntelContext, params: any) {
  const { search_term } = params;

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_updated_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Malware'),
      `or=(name.ilike.*${search_term}*,data->>aliases.ilike.*${search_term}*)`,
    ],
    order: 'source_updated_at.desc',
    limit: 10,
  });

  if (error) throw error;

  const results = [];
  for (const row of data || []) {
    const d = row.data || {};
    const { usedBy } = await fetchReverseRelatedEntities(ctx, row.internal_id, ['uses']);

    results.push({
      id: row.internal_id,
      name: row.name,
      description: d.description || '',
      aliases: d.aliases || [],
      types: d.malware_types || [],
      isFamily: d.is_family || false,
      labels: (d.labels || []).map((l: any) => typeof l === 'string' ? l : l.value),
      usedBy: usedBy.filter((u: any) => u.type === 'Intrusion-Set').slice(0, 5),
      modified: row.source_updated_at,
      linkPath: `/malware/${row.internal_id}`,
    });
  }

  return results;
}

async function tool_get_ransomware_victims(ctx: IntelContext, params: any) {
  const { days_back = 7, threat_group, limit = 20 } = params;

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days_back);
  startDate.setHours(0, 0, 0, 0);

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Report'),
      buildFilter('data->report_types', 'cs', ['Ransomware-report']),
      buildFilter('source_created_at', 'gte', startDate.toISOString()),
    ],
    order: 'source_created_at.desc',
    limit,
  });

  if (error) throw error;

  let victims = [];
  for (const row of data || []) {
    const d = row.data || {};
    const related = await fetchRelatedEntities(ctx, row.internal_id, 'object-ref');

    // Parse victim name from report name
    let victimName = row.name;
    const colonIndex = row.name.indexOf(':');
    if (colonIndex > -1) {
      victimName = row.name.substring(colonIndex + 1).trim();
    }

    victims.push({
      id: row.internal_id,
      name: victimName,
      fullName: row.name,
      description: d.description || '',
      published: d.published || row.source_created_at,
      threatGroups: related.threatActors,
      countries: related.countries,
      sectors: related.sectors,
      linkPath: `/ransomware-victims/${row.internal_id}`,
    });
  }

  // Filter by threat group if specified
  if (threat_group) {
    const groupLower = threat_group.toLowerCase();
    victims = victims.filter((v: any) =>
      v.threatGroups.some((g: any) => g.name.toLowerCase().includes(groupLower)) ||
      v.fullName.toLowerCase().includes(groupLower)
    );
  }

  return {
    totalCount: victims.length,
    daysBack: days_back,
    victims,
  };
}

async function tool_get_ransomware_statistics(ctx: IntelContext, _params: any) {
  const getCount = async (daysBack: number) => {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - daysBack);
    startDate.setHours(0, 0, 0, 0);

    const { data } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
      select: 'internal_id',
      filters: [
        buildFilter('entity_type', 'eq', 'Report'),
        buildFilter('data->report_types', 'cs', ['Ransomware-report']),
        buildFilter('source_created_at', 'gte', startDate.toISOString()),
      ],
    });

    return data?.length || 0;
  };

  const [today, last7Days, last30Days] = await Promise.all([
    getCount(0),
    getCount(7),
    getCount(30),
  ]);

  return { today, last7Days, last30Days };
}

async function tool_get_vulnerabilities(ctx: IntelContext, params: any) {
  const { days_back = 14, severity, limit = 20 } = params;

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days_back);
  startDate.setHours(0, 0, 0, 0);

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Vulnerability'),
      buildFilter('source_created_at', 'gte', startDate.toISOString()),
    ],
    order: 'source_created_at.desc',
    limit,
  });

  if (error) throw error;

  let results = (data || []).map((row: any) => {
    const d = row.data || {};
    return {
      id: row.internal_id,
      cve: row.name,
      description: d.description || '',
      created: row.source_created_at,
      cvssScore: d.x_opencti_cvss_base_score || d.cvss_base_score || null,
      severity: d.x_opencti_cvss_base_severity || d.cvss_base_severity || null,
      linkPath: `/vulnerabilities/${row.internal_id}`,
    };
  });

  // Filter by severity if specified
  if (severity) {
    results = results.filter((v: any) =>
      v.severity?.toUpperCase() === severity.toUpperCase()
    );
  }

  return results;
}

async function tool_search_vulnerabilities(ctx: IntelContext, params: any) {
  const { cve_id } = params;

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Vulnerability'),
      buildFilter('name', 'ilike', `*${cve_id}*`),
    ],
    limit: 5,
  });

  if (error) throw error;

  return (data || []).map((row: any) => {
    const d = row.data || {};
    return {
      id: row.internal_id,
      cve: row.name,
      description: d.description || '',
      created: row.source_created_at,
      cvssScore: d.x_opencti_cvss_base_score || d.cvss_base_score || null,
      severity: d.x_opencti_cvss_base_severity || d.cvss_base_severity || null,
      linkPath: `/vulnerabilities/${row.internal_id}`,
    };
  });
}

async function tool_get_attack_patterns(ctx: IntelContext, params: any) {
  const { days_back = 7, limit = 25 } = params;

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days_back);
  startDate.setHours(0, 0, 0, 0);

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_updated_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Attack-Pattern'),
      buildFilter('source_updated_at', 'gte', startDate.toISOString()),
    ],
    order: 'source_updated_at.desc',
    limit,
  });

  if (error) throw error;

  return (data || []).map((row: any) => {
    const d = row.data || {};
    return {
      id: row.internal_id,
      name: row.name,
      description: d.description || '',
      mitreId: d.x_mitre_id || '',
      platforms: d.x_mitre_platforms || [],
      killChainPhases: (d.kill_chain_phases || []).map((p: any) => p.phase_name),
      modified: row.source_updated_at,
      linkPath: `/attack-patterns/${row.internal_id}`,
    };
  });
}

async function tool_get_ttps_for_actor(ctx: IntelContext, params: any) {
  const { actor_name } = params;

  // First find the actor
  const { data: actors } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name',
    filters: [
      buildFilter('entity_type', 'eq', 'Intrusion-Set'),
      buildFilter('name', 'ilike', `*${actor_name}*`),
    ],
    limit: 1,
  });

  if (!actors || actors.length === 0) {
    return { error: `No threat actor found matching "${actor_name}"` };
  }

  const actor = actors[0];

  // Find TTPs via 'uses' relationships (actor uses attack pattern)
  const { data: rels } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'relationship_current', {
    select: 'target_id',
    filters: [
      buildFilter('relationship_type', 'eq', 'uses'),
      buildFilter('source_id', 'eq', actor.internal_id),
    ],
  });

  if (!rels || rels.length === 0) {
    return { actor: actor.name, ttps: [] };
  }

  const ttpIds = rels
    .map((r: any) => r.target_id)
    .filter(Boolean);

  const { data: ttps } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data',
    filters: [
      buildFilter('entity_type', 'eq', 'Attack-Pattern'),
      buildFilter('internal_id', 'in', ttpIds),
    ],
  });

  return {
    actor: actor.name,
    ttps: (ttps || []).map((row: any) => ({
      id: row.internal_id,
      name: row.name,
      mitreId: row.data?.x_mitre_id || '',
      description: row.data?.description?.substring(0, 200) || '',
      linkPath: `/attack-patterns/${row.internal_id}`,
    })),
  };
}

async function tool_get_threat_actor_profile(ctx: IntelContext, params: any) {
  const { actor_name } = params;

  const { data: actors } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at,source_updated_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Intrusion-Set'),
      buildFilter('name', 'ilike', `*${actor_name}*`),
    ],
    limit: 1,
  });

  if (!actors || actors.length === 0) {
    return { error: `No threat actor found matching "${actor_name}"` };
  }

  const actor = actors[0];
  const d = actor.data || {};

  // Fetch related entities
  const targetedEntities = await fetchRelatedEntities(ctx, actor.internal_id, 'targets');
  const usesEntities = await fetchRelatedEntities(ctx, actor.internal_id, 'uses');

  // Get malware and tools via 'uses' relationship
  const { data: usesRels } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'relationship_current', {
    select: 'target_id',
    filters: [
      buildFilter('relationship_type', 'eq', 'uses'),
      buildFilter('source_id', 'eq', actor.internal_id),
    ],
  });

  const usedIds = (usesRels || []).map((r: any) => r.target_id).filter(Boolean);

  let malwareUsed: any[] = [];
  let toolsUsed: any[] = [];

  if (usedIds.length > 0) {
    const { data: usedEntities } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
      select: 'internal_id,name,entity_type,data',
      filters: [buildFilter('internal_id', 'in', usedIds)],
    });

    for (const entity of usedEntities || []) {
      if (entity.entity_type === 'Malware') {
        malwareUsed.push({
          id: entity.internal_id,
          name: entity.name,
          types: entity.data?.malware_types || [],
          linkPath: `/malware/${entity.internal_id}`,
        });
      } else if (entity.entity_type === 'Tool') {
        toolsUsed.push({
          id: entity.internal_id,
          name: entity.name,
          linkPath: `/tools/${entity.internal_id}`,
        });
      }
    }
  }

  return {
    id: actor.internal_id,
    name: actor.name,
    description: d.description || '',
    aliases: d.aliases || [],
    motivation: d.primary_motivation || '',
    secondaryMotivations: d.secondary_motivations || [],
    resourceLevel: d.resource_level || '',
    goals: d.goals || [],
    firstSeen: d.first_seen || actor.source_created_at,
    lastSeen: d.last_seen || actor.source_updated_at,
    labels: (d.labels || []).map((l: any) => typeof l === 'string' ? l : l.value),
    targetedCountries: targetedEntities.countries,
    targetedSectors: targetedEntities.sectors,
    malwareUsed,
    toolsUsed,
    ttps: usesEntities.attackPatterns,
    linkPath: `/intrusion-sets/${actor.internal_id}`,
  };
}

async function tool_get_malware_profile(ctx: IntelContext, params: any) {
  const { malware_name } = params;

  const { data: malwares } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at,source_updated_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Malware'),
      buildFilter('name', 'ilike', `*${malware_name}*`),
    ],
    limit: 1,
  });

  if (!malwares || malwares.length === 0) {
    return { error: `No malware found matching "${malware_name}"` };
  }

  const malware = malwares[0];
  const d = malware.data || {};

  // Get actors that use this malware
  const { usedBy } = await fetchReverseRelatedEntities(ctx, malware.internal_id, ['uses']);
  const actors = usedBy.filter((u: any) => u.type === 'Intrusion-Set');

  return {
    id: malware.internal_id,
    name: malware.name,
    description: d.description || '',
    aliases: d.aliases || [],
    types: d.malware_types || [],
    isFamily: d.is_family || false,
    capabilities: d.capabilities || [],
    firstSeen: d.first_seen || malware.source_created_at,
    lastSeen: d.last_seen || malware.source_updated_at,
    labels: (d.labels || []).map((l: any) => typeof l === 'string' ? l : l.value),
    usedByActors: actors,
    linkPath: `/malware/${malware.internal_id}`,
  };
}

async function tool_get_vulnerability_profile(ctx: IntelContext, params: any) {
  const { cve_id } = params;

  const { data: vulns } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Vulnerability'),
      buildFilter('name', 'ilike', `*${cve_id}*`),
    ],
    limit: 1,
  });

  if (!vulns || vulns.length === 0) {
    return { error: `No vulnerability found matching "${cve_id}"` };
  }

  const vuln = vulns[0];
  const d = vuln.data || {};

  // Get entities that target/exploit this vulnerability
  const { targetedBy } = await fetchReverseRelatedEntities(ctx, vuln.internal_id, ['targets']);

  return {
    id: vuln.internal_id,
    cve: vuln.name,
    description: d.description || '',
    cvssScore: d.x_opencti_cvss_base_score || d.cvss_base_score || null,
    severity: d.x_opencti_cvss_base_severity || d.cvss_base_severity || null,
    created: vuln.source_created_at,
    exploitedBy: targetedBy,
    labels: (d.labels || []).map((l: any) => typeof l === 'string' ? l : l.value),
    linkPath: `/vulnerabilities/${vuln.internal_id}`,
  };
}

async function tool_get_advisories(ctx: IntelContext, params: any) {
  const { days_back = 7, limit = 15 } = params;

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days_back);
  startDate.setHours(0, 0, 0, 0);

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Report'),
      buildFilter('data->report_types', 'cs', ['threat-advisory']),
      buildFilter('source_created_at', 'gte', startDate.toISOString()),
    ],
    order: 'source_created_at.desc',
    limit,
  });

  if (error) throw error;

  return (data || []).map((row: any) => {
    const d = row.data || {};
    return {
      id: row.internal_id,
      name: row.name,
      description: d.description?.substring(0, 300) || '',
      published: d.published || row.source_created_at,
      source: d.createdBy?.name || 'Unknown',
      linkPath: `/advisories/${row.internal_id}`,
    };
  });
}

async function tool_get_media_reports(ctx: IntelContext, params: any) {
  const { days_back = 7, limit = 15 } = params;

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days_back);
  startDate.setHours(0, 0, 0, 0);

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Report'),
      buildFilter('data->report_types', 'cs', ['media-report']),
      buildFilter('source_created_at', 'gte', startDate.toISOString()),
    ],
    order: 'source_created_at.desc',
    limit,
  });

  if (error) throw error;

  return (data || []).map((row: any) => {
    const d = row.data || {};

    // Extract source from name pattern "Title - Original Site: source"
    let source = d.createdBy?.name || '';
    if (row.name.includes('Original Site:')) {
      source = row.name.split('Original Site:')[1]?.trim() || source;
    }

    // Clean title
    const title = row.name.split(' - Original Site:')[0].trim();

    return {
      id: row.internal_id,
      name: title,
      description: d.description?.substring(0, 300) || '',
      published: d.published || row.source_created_at,
      source,
      linkPath: `/threat-reports/${row.internal_id}`,
    };
  });
}

async function tool_get_threat_reports(ctx: IntelContext, params: any) {
  const { days_back = 14, limit = 15 } = params;

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days_back);
  startDate.setHours(0, 0, 0, 0);

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Report'),
      buildFilter('data->report_types', 'cs', ['threat-report']),
      buildFilter('source_created_at', 'gte', startDate.toISOString()),
    ],
    order: 'source_created_at.desc',
    limit,
  });

  if (error) throw error;

  const results = [];
  for (const row of data || []) {
    const d = row.data || {};
    const related = await fetchRelatedEntities(ctx, row.internal_id, 'object-ref');

    results.push({
      id: row.internal_id,
      name: row.name,
      description: d.description?.substring(0, 300) || '',
      published: d.published || row.source_created_at,
      source: d.createdBy?.name || 'Unknown',
      threatActors: related.threatActors.map((a: any) => a.name),
      malware: related.malware.map((m: any) => m.name),
      vulnerabilities: related.vulnerabilities.map((v: any) => v.name),
      linkPath: `/threat-reports/${row.internal_id}`,
    });
  }

  return results;
}

async function tool_get_actors_targeting_sector(ctx: IntelContext, params: any) {
  const { sector, limit = 10 } = params;

  // First find the sector
  const { data: sectors } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name',
    filters: [
      buildFilter('entity_type', 'eq', 'Sector'),
      buildFilter('name', 'ilike', `*${sector}*`),
    ],
    limit: 1,
  });

  if (!sectors || sectors.length === 0) {
    return { error: `No sector found matching "${sector}"` };
  }

  const sectorEntity = sectors[0];

  // Find actors that target this sector (sector is the target)
  const { data: rels } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'relationship_current', {
    select: 'source_id',
    filters: [
      buildFilter('relationship_type', 'eq', 'targets'),
      buildFilter('target_id', 'eq', sectorEntity.internal_id),
    ],
  });

  if (!rels || rels.length === 0) {
    return { sector: sectorEntity.name, actors: [] };
  }

  const actorIds = rels.map((r: any) => r.source_id).filter(Boolean);

  const { data: actors } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data',
    filters: [
      buildFilter('entity_type', 'eq', 'Intrusion-Set'),
      buildFilter('internal_id', 'in', actorIds),
    ],
    limit,
  });

  return {
    sector: sectorEntity.name,
    actors: (actors || []).map((row: any) => ({
      id: row.internal_id,
      name: row.name,
      motivation: row.data?.primary_motivation || '',
      aliases: (row.data?.aliases || []).slice(0, 3),
      linkPath: `/intrusion-sets/${row.internal_id}`,
    })),
  };
}

async function tool_get_malware_of_actor(ctx: IntelContext, params: any) {
  const { actor_name } = params;

  // First find the actor
  const { data: actors } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name',
    filters: [
      buildFilter('entity_type', 'eq', 'Intrusion-Set'),
      buildFilter('name', 'ilike', `*${actor_name}*`),
    ],
    limit: 1,
  });

  if (!actors || actors.length === 0) {
    return { error: `No threat actor found matching "${actor_name}"` };
  }

  const actor = actors[0];

  // Find malware via 'uses' relationships (actor uses malware)
  const { data: rels } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'relationship_current', {
    select: 'target_id',
    filters: [
      buildFilter('relationship_type', 'eq', 'uses'),
      buildFilter('source_id', 'eq', actor.internal_id),
    ],
  });

  if (!rels || rels.length === 0) {
    return { actor: actor.name, malware: [] };
  }

  const malwareIds = rels.map((r: any) => r.target_id).filter(Boolean);

  const { data: malware } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data',
    filters: [
      buildFilter('entity_type', 'eq', 'Malware'),
      buildFilter('internal_id', 'in', malwareIds),
    ],
  });

  return {
    actor: actor.name,
    malware: (malware || []).map((row: any) => ({
      id: row.internal_id,
      name: row.name,
      types: row.data?.malware_types || [],
      description: row.data?.description?.substring(0, 200) || '',
      linkPath: `/malware/${row.internal_id}`,
    })),
  };
}

async function tool_get_campaigns(ctx: IntelContext, params: any) {
  const { days_back = 30, limit = 15 } = params;

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days_back);
  startDate.setHours(0, 0, 0, 0);

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at,source_updated_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Campaign'),
      buildFilter('source_updated_at', 'gte', startDate.toISOString()),
    ],
    order: 'source_updated_at.desc',
    limit,
  });

  if (error) throw error;

  const results = [];
  for (const row of data || []) {
    const d = row.data || {};
    const { usedBy } = await fetchReverseRelatedEntities(ctx, row.internal_id, ['attributed-to']);

    results.push({
      id: row.internal_id,
      name: row.name,
      description: d.description?.substring(0, 300) || '',
      firstSeen: d.first_seen || row.source_created_at,
      lastSeen: d.last_seen || row.source_updated_at,
      attributedTo: usedBy.filter((u: any) => u.type === 'Intrusion-Set').map((a: any) => a.name),
      linkPath: `/campaigns/${row.internal_id}`,
    });
  }

  return results;
}

async function tool_general_search(ctx: IntelContext, params: any) {
  const { search_query, limit = 20 } = params;

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,entity_type,data,source_updated_at',
    filters: [
      `or=(name.ilike.*${search_query}*,data->>description.ilike.*${search_query}*)`,
      `entity_type=in.(Intrusion-Set,Malware,Vulnerability,Report,Attack-Pattern,Campaign,Tool,Indicator)`,
    ],
    order: 'source_updated_at.desc',
    limit,
  });

  if (error) throw error;

  const typeRoutes: Record<string, string> = {
    'Intrusion-Set': 'intrusion-sets',
    'Malware': 'malware',
    'Vulnerability': 'vulnerabilities',
    'Report': 'threat-reports',
    'Attack-Pattern': 'attack-patterns',
    'Campaign': 'campaigns',
    'Tool': 'tools',
    'Indicator': 'indicators',
  };

  return (data || []).map((row: any) => ({
    id: row.internal_id,
    name: row.name,
    type: row.entity_type,
    description: row.data?.description?.substring(0, 200) || '',
    modified: row.source_updated_at,
    linkPath: `/${typeRoutes[row.entity_type] || 'entities'}/${row.internal_id}`,
  }));
}

async function tool_search_indicators(ctx: IntelContext, params: any) {
  const { search_term, indicator_type, limit = 20 } = params;

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Indicator'),
      `or=(name.ilike.*${search_term}*,data->>pattern.ilike.*${search_term}*)`,
    ],
    order: 'source_created_at.desc',
    limit,
  });

  if (error) throw error;

  let results = (data || []).map((row: any) => {
    const d = row.data || {};
    return {
      id: row.internal_id,
      name: row.name,
      pattern: d.pattern || '',
      patternType: d.pattern_type || '',
      validFrom: d.valid_from || row.source_created_at,
      score: d.x_opencti_score || null,
      labels: (d.labels || []).map((l: any) => typeof l === 'string' ? l : l.value),
      linkPath: `/indicators/${row.internal_id}`,
    };
  });

  // Filter by indicator type if specified
  if (indicator_type) {
    results = results.filter((i: any) =>
      i.pattern.toLowerCase().includes(indicator_type.toLowerCase())
    );
  }

  return results;
}

async function tool_get_indicator_detail(ctx: IntelContext, params: any) {
  const { indicator_value } = params;

  const { data } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Indicator'),
      `or=(name.ilike.*${indicator_value}*,data->>pattern.ilike.*${indicator_value}*)`,
    ],
    limit: 1,
  });

  if (!data || data.length === 0) {
    return { error: `No indicator found matching "${indicator_value}"` };
  }

  const indicator = data[0];
  const d = indicator.data || {};

  // Get related entities
  const related = await fetchRelatedEntities(ctx, indicator.internal_id, 'indicates');

  return {
    id: indicator.internal_id,
    name: indicator.name,
    pattern: d.pattern || '',
    patternType: d.pattern_type || '',
    validFrom: d.valid_from || indicator.source_created_at,
    validUntil: d.valid_until || null,
    score: d.x_opencti_score || null,
    labels: (d.labels || []).map((l: any) => typeof l === 'string' ? l : l.value),
    indicatesThreats: [...related.threatActors, ...related.malware],
    linkPath: `/indicators/${indicator.internal_id}`,
  };
}

async function tool_search_tools(ctx: IntelContext, params: any) {
  const { search_term, limit = 10 } = params;

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_updated_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Tool'),
      buildFilter('name', 'ilike', `*${search_term}*`),
    ],
    order: 'source_updated_at.desc',
    limit,
  });

  if (error) throw error;

  return (data || []).map((row: any) => {
    const d = row.data || {};
    return {
      id: row.internal_id,
      name: row.name,
      description: d.description?.substring(0, 200) || '',
      toolTypes: d.tool_types || [],
      labels: (d.labels || []).map((l: any) => typeof l === 'string' ? l : l.value),
      linkPath: `/tools/${row.internal_id}`,
    };
  });
}

async function tool_get_tool_profile(ctx: IntelContext, params: any) {
  const { tool_name } = params;

  const { data: tools } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at,source_updated_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Tool'),
      buildFilter('name', 'ilike', `*${tool_name}*`),
    ],
    limit: 1,
  });

  if (!tools || tools.length === 0) {
    return { error: `No tool found matching "${tool_name}"` };
  }

  const tool = tools[0];
  const d = tool.data || {};

  // Get actors that use this tool
  const { usedBy } = await fetchReverseRelatedEntities(ctx, tool.internal_id, ['uses']);
  const actors = usedBy.filter((u: any) => u.type === 'Intrusion-Set');

  return {
    id: tool.internal_id,
    name: tool.name,
    description: d.description || '',
    toolTypes: d.tool_types || [],
    aliases: d.aliases || [],
    labels: (d.labels || []).map((l: any) => typeof l === 'string' ? l : l.value),
    usedByActors: actors,
    linkPath: `/tools/${tool.internal_id}`,
  };
}

async function tool_get_report_detail(ctx: IntelContext, params: any) {
  const { report_id } = params;

  const { data } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_created_at',
    filters: [buildFilter('internal_id', 'eq', report_id)],
    single: true,
  });

  if (!data) {
    return { error: `No report found with ID "${report_id}"` };
  }

  const d = data.data || {};
  const related = await fetchRelatedEntities(ctx, data.internal_id, 'object-ref');

  // Get external references
  const externalRefs = (d.externalReferences?.edges || []).map((edge: any) => ({
    url: edge.node?.url || '',
    sourceName: edge.node?.source_name || '',
  })).filter((ref: any) => ref.url);

  return {
    id: data.internal_id,
    name: data.name,
    description: d.description || '',
    published: d.published || data.source_created_at,
    reportTypes: d.report_types || [],
    source: d.createdBy?.name || 'Unknown',
    externalReferences: externalRefs,
    threatActors: related.threatActors,
    malware: related.malware,
    vulnerabilities: related.vulnerabilities,
    attackPatterns: related.attackPatterns,
    linkPath: `/threat-reports/${data.internal_id}`,
  };
}

async function tool_search_mitigations(ctx: IntelContext, params: any) {
  const { search_term, limit = 15 } = params;

  const { data, error } = await queryIntelSchema(ctx.supabaseUrl, ctx.serviceKey, 'object_current', {
    select: 'internal_id,name,data,source_updated_at',
    filters: [
      buildFilter('entity_type', 'eq', 'Course-Of-Action'),
      `or=(name.ilike.*${search_term}*,data->>description.ilike.*${search_term}*)`,
    ],
    order: 'source_updated_at.desc',
    limit,
  });

  if (error) throw error;

  return (data || []).map((row: any) => {
    const d = row.data || {};
    return {
      id: row.internal_id,
      name: row.name,
      description: d.description?.substring(0, 300) || '',
      mitreId: d.x_mitre_id || '',
      labels: (d.labels || []).map((l: any) => typeof l === 'string' ? l : l.value),
      linkPath: `/courses-of-action/${row.internal_id}`,
    };
  });
}

// ============================================================================
// TOOL EXECUTION DISPATCHER
// ============================================================================

async function executeTool(
  toolName: string,
  params: any,
  ctx: IntelContext
): Promise<any> {
  switch (toolName) {
    case "search_threat_actors":
      return tool_search_threat_actors(ctx, params);
    case "search_malware":
      return tool_search_malware(ctx, params);
    case "get_ransomware_victims":
      return tool_get_ransomware_victims(ctx, params);
    case "get_ransomware_statistics":
      return tool_get_ransomware_statistics(ctx, params);
    case "get_vulnerabilities":
      return tool_get_vulnerabilities(ctx, params);
    case "search_vulnerabilities":
      return tool_search_vulnerabilities(ctx, params);
    case "get_attack_patterns":
      return tool_get_attack_patterns(ctx, params);
    case "get_ttps_for_actor":
      return tool_get_ttps_for_actor(ctx, params);
    case "get_threat_actor_profile":
      return tool_get_threat_actor_profile(ctx, params);
    case "get_malware_profile":
      return tool_get_malware_profile(ctx, params);
    case "get_vulnerability_profile":
      return tool_get_vulnerability_profile(ctx, params);
    case "get_advisories":
      return tool_get_advisories(ctx, params);
    case "get_media_reports":
      return tool_get_media_reports(ctx, params);
    case "get_threat_reports":
      return tool_get_threat_reports(ctx, params);
    case "get_actors_targeting_sector":
      return tool_get_actors_targeting_sector(ctx, params);
    case "get_malware_of_actor":
      return tool_get_malware_of_actor(ctx, params);
    case "get_campaigns":
      return tool_get_campaigns(ctx, params);
    case "general_search":
      return tool_general_search(ctx, params);
    case "search_indicators":
      return tool_search_indicators(ctx, params);
    case "get_indicator_detail":
      return tool_get_indicator_detail(ctx, params);
    case "search_tools":
      return tool_search_tools(ctx, params);
    case "get_tool_profile":
      return tool_get_tool_profile(ctx, params);
    case "get_report_detail":
      return tool_get_report_detail(ctx, params);
    case "search_mitigations":
      return tool_search_mitigations(ctx, params);
    default:
      throw new Error(`Unknown tool: ${toolName}`);
  }
}

// ============================================================================
// MCP CHAT ORCHESTRATION
// ============================================================================

const SYSTEM_PROMPT = `You are an expert threat intelligence analyst assistant for an internal threat intelligence platform. You have access to a comprehensive threat intelligence database containing information about:
- Threat actors (APT groups, nation-state actors, cybercriminal groups)
- Malware families and strains
- Ransomware groups and their victims
- Vulnerabilities (CVEs)
- TTPs (Tactics, Techniques, and Procedures)
- Security advisories
- Threat reports and news
- Indicators of compromise (IOCs)
- Campaigns
- Tools used by threat actors

When users ask questions, use the appropriate tools to search the database and provide accurate, up-to-date information.

CRITICAL LINKING RULES:
- ONLY use the linkPath values returned by tools to create links (e.g., [APT29](/intrusion-sets/abc123))
- NEVER create external links to MITRE, Wikipedia, or any other external websites
- NEVER generate URLs - only use the exact linkPath values from tool results
- The mitreId field (e.g., T1566) is just a reference identifier - do NOT turn it into a link

IMPORTANT GUIDELINES:
1. Always use tools to fetch data - don't make up information
2. When mentioning entities, create markdown links using their linkPath: [Entity Name](linkPath)
3. Format responses clearly with bullet points or sections when appropriate
4. If a search returns no results, suggest alternative search terms
5. For time-based queries, use the correct days_back parameter (0=today, 7=last week, 30=last month)
6. Provide context and analysis alongside raw data when helpful

When presenting results:
- For threat actors: mention their motivation, targets, and associated malware
- For malware: mention who uses it and what it does
- For vulnerabilities: mention severity and any known exploitation
- For ransomware: mention the threat group and victim details`;

async function runMCPChat(
  message: string,
  historyMessages: any[],
  ctx: IntelContext,
  openaiKey: string
): Promise<{ content: string; usage: any; toolCalls: string[] }> {
  const toolCallsLog: string[] = [];

  // Build messages array
  const messages: any[] = [
    { role: "system", content: SYSTEM_PROMPT },
  ];

  // Add history (last 10 messages for context)
  for (const msg of (historyMessages || []).slice(-10)) {
    messages.push({
      role: msg.role,
      content: msg.content,
    });
  }

  // Add current message
  messages.push({ role: "user", content: message });

  // First API call with tools
  let response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${openaiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages,
      tools: MCP_TOOLS,
      tool_choice: "auto",
      temperature: 0.3,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`OpenAI API error: ${response.status} - ${errorText}`);
  }

  let data = await response.json();
  let assistantMessage = data.choices[0].message;
  let totalUsage = data.usage;

  // Process tool calls in a loop (max 5 iterations to prevent infinite loops)
  let iterations = 0;
  while (assistantMessage.tool_calls && iterations < 5) {
    iterations++;

    // Add assistant message with tool calls
    messages.push(assistantMessage);

    // Execute each tool call
    for (const toolCall of assistantMessage.tool_calls) {
      const toolName = toolCall.function.name;
      const toolParams = JSON.parse(toolCall.function.arguments || "{}");

      console.log(`Executing tool: ${toolName}`, toolParams);
      toolCallsLog.push(toolName);

      try {
        const result = await executeTool(toolName, toolParams, ctx);

        // Add tool result
        messages.push({
          role: "tool",
          tool_call_id: toolCall.id,
          content: JSON.stringify(result, null, 2),
        });
      } catch (error) {
        console.error(`Tool error: ${toolName}`, error);
        messages.push({
          role: "tool",
          tool_call_id: toolCall.id,
          content: JSON.stringify({ error: `Tool execution failed: ${error}` }),
        });
      }
    }

    // Call API again with tool results
    response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${openaiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages,
        tools: MCP_TOOLS,
        tool_choice: "auto",
        temperature: 0.3,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`OpenAI API error: ${response.status} - ${errorText}`);
    }

    data = await response.json();
    assistantMessage = data.choices[0].message;

    // Accumulate usage
    if (data.usage) {
      totalUsage.prompt_tokens += data.usage.prompt_tokens;
      totalUsage.completion_tokens += data.usage.completion_tokens;
      totalUsage.total_tokens += data.usage.total_tokens;
    }
  }

  return {
    content: assistantMessage.content || "I apologize, but I was unable to generate a response.",
    usage: totalUsage,
    toolCalls: toolCallsLog,
  };
}

// ============================================================================
// MAIN HANDLER
// ============================================================================

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { action, sessionId, message, messages: historyMessages } = await req.json();

    // Verify authentication
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
    const openaiKey = Deno.env.get('OPENAI_API_KEY');

    if (!openaiKey) {
      return new Response(JSON.stringify({ error: 'OpenAI not configured' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Verify user
    const supabaseAuth = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } }
    });

    const { data: { user }, error: authError } = await supabaseAuth.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Invalid token' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Create intel context for direct REST queries
    const ctx: IntelContext = {
      supabaseUrl,
      serviceKey: supabaseServiceKey,
    };

    // Create supabase client for public schema operations
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    // Handle different actions
    if (action === 'create-session') {
      const { data: session, error } = await supabase
        .from('intel_chat_sessions')
        .insert({ user_id: user.id })
        .select()
        .single();

      if (error) throw error;

      return new Response(JSON.stringify({ session }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (action === 'list-sessions') {
      const { data: sessions, error } = await supabase
        .from('intel_chat_sessions')
        .select('*')
        .eq('user_id', user.id)
        .eq('is_archived', false)
        .order('updated_at', { ascending: false })
        .limit(20);

      if (error) throw error;

      return new Response(JSON.stringify({ sessions }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (action === 'get-messages') {
      if (!sessionId) {
        return new Response(JSON.stringify({ error: 'Missing sessionId' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      const { data: messages, error } = await supabase
        .from('intel_chat_messages')
        .select('*')
        .eq('session_id', sessionId)
        .order('created_at', { ascending: true });

      if (error) throw error;

      return new Response(JSON.stringify({ messages }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (action === 'delete-session') {
      if (!sessionId) {
        return new Response(JSON.stringify({ error: 'Missing sessionId' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      const { error } = await supabase
        .from('intel_chat_sessions')
        .delete()
        .eq('id', sessionId)
        .eq('user_id', user.id);

      if (error) throw error;

      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (action === 'chat') {
      if (!sessionId || !message) {
        return new Response(JSON.stringify({ error: 'Missing sessionId or message' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // Save user message
      await supabase
        .from('intel_chat_messages')
        .insert({
          session_id: sessionId,
          role: 'user',
          content: message,
        });

      // Run MCP chat with tool calling
      console.log('MCP Chat: Starting...');
      const mcpResponse = await runMCPChat(
        message,
        historyMessages,
        ctx,
        openaiKey
      );
      console.log('MCP Chat: Complete. Tool calls:', mcpResponse.toolCalls);

      // Save assistant message
      const { data: assistantMessage, error: saveError } = await supabase
        .from('intel_chat_messages')
        .insert({
          session_id: sessionId,
          role: 'assistant',
          content: mcpResponse.content,
          token_usage: mcpResponse.usage,
          query_context: { mode: 'mcp', toolCalls: mcpResponse.toolCalls },
        })
        .select()
        .single();

      if (saveError) throw saveError;

      // Update session title if this is the first message
      const { count } = await supabase
        .from('intel_chat_messages')
        .select('*', { count: 'exact', head: true })
        .eq('session_id', sessionId);

      if (count === 2) {
        // Generate title from first message
        let title = message;

        const aptMatch = message.match(/APT\d+|APT-\d+/i);
        const threatActorMatch = message.match(/(?:Lazarus|Kimsuky|Cozy Bear|Fancy Bear|APT\d+|LockBit|BlackCat|ALPHV|Conti|REvil|Cl0p)/i);
        const cveMatch = message.match(/CVE-\d{4}-\d+/i);

        if (aptMatch || threatActorMatch) {
          const actor = aptMatch?.[0] || threatActorMatch?.[0];
          title = `${actor} inquiry`;
        } else if (cveMatch) {
          title = `${cveMatch[0]} lookup`;
        } else if (message.toLowerCase().includes('ransomware')) {
          title = 'Ransomware query';
        } else if (message.toLowerCase().includes('victim')) {
          title = 'Victim inquiry';
        } else if (message.toLowerCase().includes('malware')) {
          title = 'Malware query';
        } else {
          const words = message.split(/\s+/).slice(0, 5);
          title = words.join(' ');
          if (message.split(/\s+/).length > 5) title += '...';
        }

        if (title.length > 50) {
          title = title.substring(0, 47) + '...';
        }

        await supabase
          .from('intel_chat_sessions')
          .update({ title })
          .eq('id', sessionId);
      }

      return new Response(JSON.stringify({
        message: assistantMessage,
        usage: mcpResponse.usage,
        toolCalls: mcpResponse.toolCalls,
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ error: 'Unknown action' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Error:', error);
    return new Response(JSON.stringify({ error: String(error) }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
