import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// Similarity threshold for detecting potential duplicates
const SIMILARITY_THRESHOLD = 0.85;
const NAME_SIMILARITY_THRESHOLD = 0.8;

interface IntrusionSet {
  id: string;
  name: string;
  description?: string;
  aliases?: string[];
  created?: string;
  modified?: string;
  relationshipCount?: number;
}

interface DuplicateCandidate {
  entity1_id: string;
  entity1_name: string;
  entity1_description?: string;
  entity1_aliases?: string[];
  entity1_relationships?: number;
  entity2_id: string;
  entity2_name: string;
  entity2_description?: string;
  entity2_aliases?: string[];
  entity2_relationships?: number;
  similarity_score: number;
  name_similarity: number;
  alias_overlap: number;
  detection_method: string;
}

// Compute Levenshtein distance for name similarity
function levenshteinDistance(s1: string, s2: string): number {
  const len1 = s1.length;
  const len2 = s2.length;
  const dp: number[][] = Array(len1 + 1).fill(null).map(() => Array(len2 + 1).fill(0));

  for (let i = 0; i <= len1; i++) dp[i][0] = i;
  for (let j = 0; j <= len2; j++) dp[0][j] = j;

  for (let i = 1; i <= len1; i++) {
    for (let j = 1; j <= len2; j++) {
      const cost = s1[i - 1].toLowerCase() === s2[j - 1].toLowerCase() ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[len1][len2];
}

// Calculate name similarity score (0-1)
function calculateNameSimilarity(name1: string, name2: string): number {
  const maxLen = Math.max(name1.length, name2.length);
  if (maxLen === 0) return 1;
  const distance = levenshteinDistance(name1, name2);
  return 1 - (distance / maxLen);
}

// Normalize a name for comparison
function normalizeName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '')
    .trim();
}

// Check for alias overlap between two entities
function countAliasOverlap(aliases1: string[], aliases2: string[]): number {
  if (!aliases1.length || !aliases2.length) return 0;

  const normalized1 = new Set(aliases1.map(normalizeName));
  const normalized2 = new Set(aliases2.map(normalizeName));

  let overlap = 0;
  for (const alias of normalized1) {
    if (normalized2.has(alias)) overlap++;
  }
  return overlap;
}

// Compute cosine similarity between two embedding vectors
function cosineSimilarity(a: number[], b: number[]): number {
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }

  const magnitude = Math.sqrt(normA) * Math.sqrt(normB);
  return magnitude === 0 ? 0 : dotProduct / magnitude;
}

// Get OpenAI embeddings for a batch of texts
async function getEmbeddings(texts: string[], openaiKey: string): Promise<number[][]> {
  const response = await fetch('https://api.openai.com/v1/embeddings', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${openaiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'text-embedding-3-small',
      input: texts,
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`OpenAI embeddings API error: ${error}`);
  }

  const data = await response.json();
  return data.data.map((item: { embedding: number[] }) => item.embedding);
}

// Fetch intrusion sets from OpenCTI
async function fetchIntrusionSets(
  openctiUrl: string,
  openctiToken: string,
  maxEntities: number = 2000
): Promise<IntrusionSet[]> {
  const allEntities: IntrusionSet[] = [];
  let cursor: string | null = null;
  const batchSize = 500;

  do {
    const query = {
      query: `query IntrusionSetsPaginationQuery($count: Int!, $cursor: ID) {
        intrusionSets(first: $count, after: $cursor, orderBy: name, orderMode: asc) {
          edges {
            node {
              id
              name
              description
              aliases
              created
              modified
              stixCoreRelationships {
                pageInfo {
                  globalCount
                }
              }
            }
            cursor
          }
          pageInfo {
            hasNextPage
            endCursor
          }
        }
      }`,
      variables: {
        count: batchSize,
        cursor: cursor,
      },
    };

    const response = await fetch(openctiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${openctiToken}`,
      },
      body: JSON.stringify(query),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`OpenCTI API error: ${errorText}`);
    }

    const data = await response.json();

    if (data.errors) {
      throw new Error(`OpenCTI GraphQL error: ${JSON.stringify(data.errors)}`);
    }

    const edges = data.data?.intrusionSets?.edges || [];
    for (const edge of edges) {
      allEntities.push({
        id: edge.node.id,
        name: edge.node.name,
        description: edge.node.description || '',
        aliases: edge.node.aliases || [],
        created: edge.node.created,
        modified: edge.node.modified,
        relationshipCount: edge.node.stixCoreRelationships?.pageInfo?.globalCount || 0,
      });
    }

    const pageInfo = data.data?.intrusionSets?.pageInfo;
    cursor = pageInfo?.hasNextPage ? pageInfo.endCursor : null;

    console.log(`Fetched ${allEntities.length} intrusion sets...`);

    // Stop if we've hit the limit
    if (allEntities.length >= maxEntities) {
      console.log(`Reached max entities limit (${maxEntities})`);
      break;
    }
  } while (cursor);

  return allEntities;
}

// Main deduplication scanning logic (optimized for Edge Function limits)
async function scanForDuplicates(
  entities: IntrusionSet[]
): Promise<DuplicateCandidate[]> {
  const candidates: DuplicateCandidate[] = [];
  const seenPairs = new Set<string>();
  const MAX_CANDIDATES = 500; // Limit candidates per scan

  console.log(`Scanning ${entities.length} entities for duplicates...`);

  // Quick name-based matching only
  for (let i = 0; i < entities.length && candidates.length < MAX_CANDIDATES; i++) {
    for (let j = i + 1; j < entities.length && candidates.length < MAX_CANDIDATES; j++) {
      const e1 = entities[i];
      const e2 = entities[j];

      const pairKey = [e1.id, e2.id].sort().join('|');
      if (seenPairs.has(pairKey)) continue;

      // Check normalized name match
      const norm1 = normalizeName(e1.name);
      const norm2 = normalizeName(e2.name);

      // Helper to build candidate with full entity details
      const buildCandidate = (score: number, nameSim: number, aliasOvlp: number, method: string): DuplicateCandidate => ({
        entity1_id: e1.id,
        entity1_name: e1.name,
        entity1_description: e1.description,
        entity1_aliases: e1.aliases,
        entity1_relationships: e1.relationshipCount,
        entity2_id: e2.id,
        entity2_name: e2.name,
        entity2_description: e2.description,
        entity2_aliases: e2.aliases,
        entity2_relationships: e2.relationshipCount,
        similarity_score: score,
        name_similarity: nameSim,
        alias_overlap: aliasOvlp,
        detection_method: method,
      });

      if (norm1 === norm2 && norm1.length > 0) {
        seenPairs.add(pairKey);
        candidates.push(buildCandidate(1.0, 1.0, countAliasOverlap(e1.aliases || [], e2.aliases || []), 'exact_name_match'));
        continue;
      }

      // Check name similarity
      const nameSim = calculateNameSimilarity(e1.name, e2.name);
      if (nameSim >= NAME_SIMILARITY_THRESHOLD) {
        seenPairs.add(pairKey);
        candidates.push(buildCandidate(nameSim, nameSim, countAliasOverlap(e1.aliases || [], e2.aliases || []), 'name_similarity'));
        continue;
      }

      // Check alias overlap
      const aliasOverlap = countAliasOverlap(e1.aliases || [], e2.aliases || []);
      if (aliasOverlap >= 2) {
        seenPairs.add(pairKey);
        candidates.push(buildCandidate(0.9, nameSim, aliasOverlap, 'alias_overlap'));
        continue;
      }

      // Check if name appears in other's aliases
      const name1InAliases2 = (e2.aliases || []).some(a =>
        normalizeName(a) === norm1 || calculateNameSimilarity(a, e1.name) > 0.9
      );
      const name2InAliases1 = (e1.aliases || []).some(a =>
        normalizeName(a) === norm2 || calculateNameSimilarity(a, e2.name) > 0.9
      );

      if (name1InAliases2 || name2InAliases1) {
        seenPairs.add(pairKey);
        candidates.push(buildCandidate(0.95, nameSim, aliasOverlap, 'name_in_alias'));
      }
    }
  }

  console.log(`Found ${candidates.length} candidates from name-based matching`);

  // Skip semantic similarity for now to avoid CPU timeout
  // TODO: Add back in a separate batch process if needed

  // Sort by similarity score descending
  candidates.sort((a, b) => b.similarity_score - a.similarity_score);

  return candidates;
}

serve(async (req) => {
  console.log('Dedup scanner request received:', req.method);

  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Parse body first to get action
    let body;
    try {
      body = await req.json();
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
    const { action } = body;
    console.log('Action:', action);

    // Verify authentication
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Unauthorized: No auth header' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL');
    const supabaseServiceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
    const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY');

    if (!supabaseUrl || !supabaseServiceKey || !supabaseAnonKey) {
      console.error('Missing Supabase env vars');
      return new Response(JSON.stringify({ error: 'Server configuration error' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Verify user is authenticated
    const supabaseAuth = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } }
    });

    const { data: { user }, error: authError } = await supabaseAuth.auth.getUser();
    if (authError || !user) {
      console.error('Auth error:', authError?.message);
      return new Response(JSON.stringify({ error: 'Unauthorized: Invalid token' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
    console.log('User authenticated:', user.id);

    // Use service role client for database operations
    const supabase = createClient(supabaseUrl, supabaseServiceKey);

    // Verify user is admin (use service role to bypass RLS)
    const { data: roleData, error: roleError } = await supabase
      .from('user_roles')
      .select('role')
      .eq('user_id', user.id)
      .single();

    console.log('Role check:', roleData?.role, roleError?.message);

    if (roleData?.role !== 'admin') {
      return new Response(JSON.stringify({ error: 'Admin access required' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Get OpenCTI credentials
    const openctiUrl = Deno.env.get('OPENCTI_URL');
    const openctiToken = Deno.env.get('OPENCTI_API_TOKEN');
    const openaiKey = Deno.env.get('OPENAI_API_KEY');

    if (!openctiUrl || !openctiToken) {
      console.error('OpenCTI not configured:', { openctiUrl: !!openctiUrl, openctiToken: !!openctiToken });
      return new Response(JSON.stringify({ error: 'OpenCTI not configured' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    console.log('OpenCTI URL:', openctiUrl);

    if (action === 'scan') {
      // Create a scan run record
      const { data: scanRun, error: scanError } = await supabase
        .from('dedup_scan_runs')
        .insert({
          similarity_threshold: SIMILARITY_THRESHOLD,
          initiated_by: user.id,
        })
        .select()
        .single();

      if (scanError) {
        throw new Error(`Failed to create scan run: ${scanError.message}`);
      }

      try {
        // Fetch all intrusion sets from OpenCTI
        console.log('Fetching intrusion sets from OpenCTI...');
        const entities = await fetchIntrusionSets(openctiUrl, openctiToken);

        // Update scan run with entity count
        await supabase
          .from('dedup_scan_runs')
          .update({ entity_count: entities.length })
          .eq('id', scanRun.id);

        // Scan for duplicates
        console.log('Scanning for duplicates...');
        const candidates = await scanForDuplicates(entities);

        // Fetch existing rejected/merged pairs to skip them
        const { data: existingPairs } = await supabase
          .from('dedup_candidates')
          .select('entity1_id, entity2_id, status')
          .in('status', ['rejected', 'merged']);

        // Create a set of rejected/merged pair keys for fast lookup
        const skipPairs = new Set<string>();
        for (const pair of existingPairs || []) {
          // Store both orderings to catch either direction
          skipPairs.add(`${pair.entity1_id}|${pair.entity2_id}`);
          skipPairs.add(`${pair.entity2_id}|${pair.entity1_id}`);
        }
        console.log(`Skipping ${skipPairs.size / 2} already processed pairs`);

        // Store new candidates (skip rejected/merged pairs)
        let newCandidates = 0;
        for (const candidate of candidates) {
          // Sort IDs for consistent storage
          const [sortedId1, sortedId2] = [candidate.entity1_id, candidate.entity2_id].sort();
          const pairKey = `${sortedId1}|${sortedId2}`;

          // Skip if this pair was already rejected or merged
          if (skipPairs.has(pairKey)) {
            console.log(`Skipping already processed pair: ${candidate.entity1_name} / ${candidate.entity2_name}`);
            continue;
          }

          // Ensure consistent ordering (smaller ID first)
          const isSwapped = candidate.entity1_id > candidate.entity2_id;

          const { error: insertError } = await supabase
            .from('dedup_candidates')
            .upsert({
              entity1_id: isSwapped ? candidate.entity2_id : candidate.entity1_id,
              entity1_name: isSwapped ? candidate.entity2_name : candidate.entity1_name,
              entity1_description: isSwapped ? candidate.entity2_description : candidate.entity1_description || null,
              entity1_aliases: isSwapped ? candidate.entity2_aliases : candidate.entity1_aliases || [],
              entity1_relationships: isSwapped ? candidate.entity2_relationships : candidate.entity1_relationships || 0,
              entity2_id: isSwapped ? candidate.entity1_id : candidate.entity2_id,
              entity2_name: isSwapped ? candidate.entity1_name : candidate.entity2_name,
              entity2_description: isSwapped ? candidate.entity1_description : candidate.entity2_description || null,
              entity2_aliases: isSwapped ? candidate.entity1_aliases : candidate.entity2_aliases || [],
              entity2_relationships: isSwapped ? candidate.entity1_relationships : candidate.entity2_relationships || 0,
              similarity_score: candidate.similarity_score,
              name_similarity: candidate.name_similarity,
              alias_overlap: candidate.alias_overlap,
              detection_method: candidate.detection_method,
              status: 'pending',
            }, {
              onConflict: 'entity1_id,entity2_id',
              ignoreDuplicates: true,
            });

          if (!insertError) newCandidates++;
        }

        // Update scan run as completed
        await supabase
          .from('dedup_scan_runs')
          .update({
            completed_at: new Date().toISOString(),
            candidates_found: candidates.length,
            status: 'completed',
          })
          .eq('id', scanRun.id);

        return new Response(JSON.stringify({
          success: true,
          scanId: scanRun.id,
          entitiesScanned: entities.length,
          candidatesFound: candidates.length,
          newCandidates,
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        // Update scan run as failed
        await supabase
          .from('dedup_scan_runs')
          .update({
            completed_at: new Date().toISOString(),
            status: 'failed',
            error_message: err.message,
          })
          .eq('id', scanRun.id);

        throw err;
      }
    }

    if (action === 'merge') {
      const { candidateId, keepEntityId } = body;

      if (!candidateId || !keepEntityId) {
        return new Response(JSON.stringify({ error: 'Missing candidateId or keepEntityId' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // Get the candidate
      const { data: candidate, error: candError } = await supabase
        .from('dedup_candidates')
        .select('*')
        .eq('id', candidateId)
        .single();

      if (candError || !candidate) {
        return new Response(JSON.stringify({ error: 'Candidate not found' }), {
          status: 404,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // Determine which entity to merge
      const mergeEntityId = keepEntityId === candidate.entity1_id
        ? candidate.entity2_id
        : candidate.entity1_id;
      const mergeEntityName = keepEntityId === candidate.entity1_id
        ? candidate.entity2_name
        : candidate.entity1_name;
      const keepEntityName = keepEntityId === candidate.entity1_id
        ? candidate.entity1_name
        : candidate.entity2_name;

      try {
        // Execute merge in OpenCTI
        const mergeQuery = {
          query: `mutation MergeStixCoreObjects($id: ID!, $stixCoreObjectsIds: [String]!) {
            stixCoreObjectEdit(id: $id) {
              merge(stixCoreObjectsIds: $stixCoreObjectsIds) {
                id
              }
            }
          }`,
          variables: {
            id: keepEntityId,
            stixCoreObjectsIds: [mergeEntityId],
          },
        };

        const response = await fetch(openctiUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${openctiToken}`,
          },
          body: JSON.stringify(mergeQuery),
        });

        const mergeResult = await response.json();

        if (mergeResult.errors) {
          throw new Error(mergeResult.errors[0]?.message || 'Merge failed in OpenCTI');
        }

        // Record in history
        await supabase.from('dedup_history').insert({
          candidate_id: candidateId,
          kept_entity_id: keepEntityId,
          kept_entity_name: keepEntityName,
          merged_entity_id: mergeEntityId,
          merged_entity_name: mergeEntityName,
          merged_by: user.id,
          success: true,
        });

        // Update candidate status
        await supabase
          .from('dedup_candidates')
          .update({
            status: 'merged',
            reviewed_by: user.id,
            reviewed_at: new Date().toISOString(),
            canonical_entity_id: keepEntityId,
          })
          .eq('id', candidateId);

        return new Response(JSON.stringify({
          success: true,
          keptEntity: { id: keepEntityId, name: keepEntityName },
          mergedEntity: { id: mergeEntityId, name: mergeEntityName },
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        // Record failed merge in history
        await supabase.from('dedup_history').insert({
          candidate_id: candidateId,
          kept_entity_id: keepEntityId,
          kept_entity_name: keepEntityName,
          merged_entity_id: mergeEntityId,
          merged_entity_name: mergeEntityName,
          merged_by: user.id,
          success: false,
          error_message: err.message,
        });

        return new Response(JSON.stringify({ error: `Merge failed: ${err.message}` }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    if (action === 'approve' || action === 'reject') {
      const { candidateId, canonicalEntityId } = body;

      if (!candidateId) {
        return new Response(JSON.stringify({ error: 'Missing candidateId' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      await supabase
        .from('dedup_candidates')
        .update({
          status: action === 'approve' ? 'approved' : 'rejected',
          reviewed_by: user.id,
          reviewed_at: new Date().toISOString(),
          canonical_entity_id: canonicalEntityId || null,
        })
        .eq('id', candidateId);

      return new Response(JSON.stringify({ success: true, status: action === 'approve' ? 'approved' : 'rejected' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (action === 'clear-stuck') {
      // Clear any stuck "running" scans
      const { data, error } = await supabase
        .from('dedup_scan_runs')
        .update({
          status: 'failed',
          error_message: 'Cancelled - marked as stuck',
          completed_at: new Date().toISOString(),
        })
        .eq('status', 'running')
        .select();

      return new Response(JSON.stringify({ success: true, cleared: data?.length || 0 }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (action === 'clear-all') {
      // Clear all scan data (candidates, history, scan runs)
      await supabase.from('dedup_history').delete().neq('id', '00000000-0000-0000-0000-000000000000');
      await supabase.from('dedup_candidates').delete().neq('id', '00000000-0000-0000-0000-000000000000');
      await supabase.from('dedup_scan_runs').delete().neq('id', '00000000-0000-0000-0000-000000000000');

      return new Response(JSON.stringify({ success: true, message: 'All dedup data cleared' }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ error: 'Invalid action' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Error in dedup-scanner:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
