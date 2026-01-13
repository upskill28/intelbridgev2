import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "npm:@supabase/supabase-js@2";
import { z } from "https://deno.land/x/zod@v3.22.4/mod.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// ID of the ransomware bot to exclude from threat reports
const RANSOMWARE_BOT_ID = "da40d586-a70e-4023-9f68-bf6d10d54635";

// Input validation schema
const OpenCTIProxySchema = z.object({
  queryType: z.enum([
    'ransomware-victims',
    'advisories', 
    'threat-reports',
    'report-detail',
    'indicators',
    'indicator-detail',
    'intrusion-sets',
    'intrusion-set-detail',
    'malware',
    'malware-detail',
    'vulnerabilities',
    'reports-vulnerabilities',
    'vulnerability-detail',
    'tools',
    'tool-detail',
    'attack-patterns',
    'attack-pattern-detail',
    'course-of-action-detail',
    'courses-of-action',
    'campaigns',
    'campaign-detail',
    'darkweb-forums',
    'country-details',
    'country-detail',
    'countries',
    'sector-details',
    'sector-detail',
    'sectors',
    'region-details',
    'region-detail',
    'regions',
    'mitigations',
    'entity-counts',
    'media-reports',
    'activity-ticker'
  ]),
  limit: z.number().int().min(1).max(1000).optional().default(100),
  id: z.string().max(500).optional(),
  cursor: z.string().max(500).nullable().optional(),
  year: z.string().regex(/^\d{4}$/).optional(),
  published_start: z.string().datetime().optional(),
  published_end: z.string().datetime().optional(),
  sector: z.string().max(200).optional(),
  threatGroup: z.string().max(200).optional(),
  country: z.string().max(200).optional(),
  reportType: z.string().max(100).optional(),
  source: z.string().max(200).optional(),
  search: z.string().max(500).optional(),
});

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Verify authentication
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'Unauthorized: Missing authorization header' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } }
    });

    const { data: { user }, error: authError } = await supabase.auth.getUser();
    if (authError || !user) {
      console.error('Authentication failed:', authError?.message);
      return new Response(JSON.stringify({ error: 'Unauthorized: Invalid authentication' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    console.log('Authenticated user:', user.id);

    // Parse and validate input
    const rawBody = await req.json();
    const parseResult = OpenCTIProxySchema.safeParse(rawBody);
    
    if (!parseResult.success) {
      console.error('Input validation failed:', parseResult.error.errors);
      return new Response(JSON.stringify({ 
        error: 'Invalid input parameters',
        details: parseResult.error.errors.map(e => `${e.path.join('.')}: ${e.message}`)
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const { queryType, limit, id, cursor, year, published_start, published_end, sector, threatGroup, country, reportType, source, search } = parseResult.data;
    
    const openctiUrl = Deno.env.get('OPENCTI_URL');
    const openctiToken = Deno.env.get('OPENCTI_API_TOKEN');

    if (!openctiUrl || !openctiToken) {
      throw new Error('OpenCTI credentials not configured');
    }

    console.log('Fetching data from OpenCTI:', { queryType, limit, cursor, year, published_start, published_end, sector, threatGroup, country, reportType, source, search, url: openctiUrl });

    if (queryType === 'ransomware-victims') {
      // Build date filter if year or explicit dates are provided
      const dateFilterGroups: any[] = [];
      
      if (published_start || published_end || year) {
        const dateFilters: any[] = [];
        
        if (published_start) {
          dateFilters.push({
            key: "published",
            operator: "gte",
            values: [published_start],
            mode: "or"
          });
        }
        
        if (published_end) {
          dateFilters.push({
            key: "published",
            operator: "lte",
            values: [published_end],
            mode: "or"
          });
        }
        
        if (year && !published_start) {
          // If year is provided but no explicit start, use year boundaries
          dateFilters.push({
            key: "published",
            operator: "gte",
            values: [`${year}-01-01T00:00:00.000Z`],
            mode: "or"
          });
          
          if (!published_end) {
            dateFilters.push({
              key: "published",
              operator: "lte",
              values: [`${year}-12-31T23:59:59.999Z`],
              mode: "or"
            });
          }
        }
        
        if (dateFilters.length > 0) {
          dateFilterGroups.push({
            mode: "and",
            filters: dateFilters,
            filterGroups: []
          });
        }
      }
      
      const graphqlQuery = {
        query: `query ReportsLinesPaginationQuery($count: Int!, $after: ID, $orderBy: ReportsOrdering, $orderMode: OrderingMode, $filters: FilterGroup, $search: String) {
          reports(first: $count, after: $after, orderBy: $orderBy, orderMode: $orderMode, filters: $filters, search: $search) {
            edges {
              node {
                id
                name
                description
                published
                created_at
                report_types
                createdBy {
                  name
                  id
                }
                objectMarking {
                  id
                  definition
                  x_opencti_color
                }
                objectLabel {
                  id
                  value
                  color
                }
                objects {
                  edges {
                    node {
                      __typename
                      ... on Country {
                        id
                        name
                      }
                      ... on Sector {
                        id
                        name
                      }
                      ... on IntrusionSet {
                        id
                        name
                      }
                      ... on Organization {
                        id
                        name
                      }
                    }
                  }
                }
              }
            }
            pageInfo {
              hasNextPage
              endCursor
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          after: cursor || null,
          orderMode: "desc",
          orderBy: "published",
          search: search || null,
          filters: {
            mode: "and",
            filters: [
              {
                key: "entity_type",
                values: ["Report"],
                operator: "eq",
                mode: "or"
              }
            ],
            filterGroups: [
              {
                mode: "and",
                filters: [
                  {
                    key: "createdBy",
                    operator: "eq",
                    values: [RANSOMWARE_BOT_ID],
                    mode: "or"
                  }
                ],
                filterGroups: []
              },
              ...dateFilterGroups
            ]
          }
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('OpenCTI API error:', errorText);
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI response:', JSON.stringify(data, null, 2));

      if (data.errors) {
        console.error('GraphQL errors:', data.errors);
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      // Transform the data to match our table structure
      const transformedData = data.data.reports.edges.map((edge: any) => {
        const node = edge.node;
        
        // Extract data from objects.edges by __typename
        const objects = node.objects?.edges || [];
        const countries = objects.filter((e: any) => e.node.__typename === 'Country').map((e: any) => e.node);
        const sectors = objects.filter((e: any) => e.node.__typename === 'Sector').map((e: any) => e.node);
        const threatGroups = objects.filter((e: any) => e.node.__typename === 'IntrusionSet').map((e: any) => e.node);
        
        // Get the first TLP marking
        const tlpMarking = node.objectMarking?.find((m: any) => m.definition?.startsWith('TLP:'));

        return {
          id: node.id,
          name: node.name,
          description: node.description || '',
          date: node.created_at || node.published || new Date().toISOString(),
          reportTypes: node.report_types || [],
          source: node.createdBy?.name || 'Unknown',
          sourceId: node.createdBy?.id || null,
          labels: node.objectLabel?.map((label: any) => ({
            id: label.id,
            value: label.value,
            color: label.color
          })) || [],
          tlpMarking: tlpMarking ? {
            definition: tlpMarking.definition,
            color: tlpMarking.x_opencti_color
          } : null,
          threatGroups,
          sectors,
          countries,
        };
      });

      console.log('Transformed data:', transformedData.length, 'items');
      console.log('PageInfo:', data.data.reports.pageInfo);

      return new Response(JSON.stringify({ 
        data: transformedData,
        pageInfo: data.data.reports.pageInfo
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (queryType === 'advisories') {
      // Dedicated query for threat-advisory reports
      const dateFilterGroups: any[] = [];
      
      if (published_start || published_end) {
        const dateFilters: any[] = [];
        
        if (published_start) {
          dateFilters.push({
            key: "published",
            operator: "gte",
            values: [published_start],
            mode: "or"
          });
        }
        
        if (published_end) {
          dateFilters.push({
            key: "published",
            operator: "lte",
            values: [published_end],
            mode: "or"
          });
        }
        
        if (dateFilters.length > 0) {
          dateFilterGroups.push({
            mode: "and",
            filters: dateFilters,
            filterGroups: []
          });
        }
      }

      const graphqlQuery = {
        query: `query AdvisoriesPaginationQuery($count: Int!, $after: ID, $orderBy: ReportsOrdering, $orderMode: OrderingMode, $filters: FilterGroup, $search: String) {
          reports(first: $count, after: $after, orderBy: $orderBy, orderMode: $orderMode, filters: $filters, search: $search) {
            edges {
              node {
                id
                name
                description
                published
                created_at
                report_types
                createdBy {
                  __typename
                  id
                  name
                }
                objectMarking {
                  id
                  definition
                  definition_type
                  x_opencti_color
                }
                objectLabel {
                  id
                  value
                  color
                }
              }
              cursor
            }
            pageInfo {
              hasNextPage
              endCursor
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          after: cursor || null,
          orderMode: "desc",
          orderBy: "published",
          search: search || null,
          filters: {
            mode: "and",
            filters: [
              {
                key: "entity_type",
                values: ["Report"],
                operator: "eq",
                mode: "or"
              },
              // Only threat-advisory type
              {
                key: "report_types",
                operator: "eq",
                values: ["threat-advisory"],
                mode: "or"
              }
            ],
            filterGroups: [
              ...dateFilterGroups
            ]
          }
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('OpenCTI API error:', errorText);
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI advisories response received, count:', data.data?.reports?.edges?.length);

      if (data.errors) {
        console.error('GraphQL errors:', data.errors);
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      // Transform the data
      const transformedData = data.data.reports.edges.map((edge: any) => {
        const node = edge.node;
        
        // Get the first TLP marking
        const tlpMarking = node.objectMarking?.find((m: any) => m.definition_type === 'TLP');
        
        return {
          id: node.id,
          name: node.name,
          description: node.description || '',
          date: node.created_at || node.published || new Date().toISOString(),
          reportTypes: node.report_types || [],
          source: node.createdBy?.name || 'Unknown',
          sourceId: node.createdBy?.id || null,
          labels: node.objectLabel?.map((label: any) => ({
            id: label.id,
            value: label.value,
            color: label.color
          })) || [],
          tlpMarking: tlpMarking ? {
            definition: tlpMarking.definition,
            color: tlpMarking.x_opencti_color
          } : null,
        };
      });

      console.log('Transformed advisories:', transformedData.length, 'items');

      return new Response(JSON.stringify({ 
        data: transformedData,
        pageInfo: data.data.reports.pageInfo
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (queryType === 'threat-reports') {
      // Build date filter groups
      const dateFilterGroups: any[] = [];
      
      if (published_start || published_end) {
        const dateFilters: any[] = [];
        
        if (published_start) {
          dateFilters.push({
            key: "published",
            operator: "gte",
            values: [published_start],
            mode: "or"
          });
        }
        
        if (published_end) {
          dateFilters.push({
            key: "published",
            operator: "lte",
            values: [published_end],
            mode: "or"
          });
        }
        
        if (dateFilters.length > 0) {
          dateFilterGroups.push({
            mode: "and",
            filters: dateFilters,
            filterGroups: []
          });
        }
      }

      // Build report type filter if provided
      const reportTypeFilters: any[] = [];
      if (reportType) {
        reportTypeFilters.push({
          key: "report_types",
          operator: "eq",
          values: [reportType],
          mode: "or"
        });
      }

      // Build source/createdBy filter if provided
      const sourceFilterGroups: any[] = [];
      if (source) {
        // Map source names to IDs
        let sourceId = source;
        if (source === "ransomware.live") {
          sourceId = RANSOMWARE_BOT_ID;
        }
        
        sourceFilterGroups.push({
          mode: "and",
          filters: [
            {
              key: "createdBy",
              operator: "eq",
              values: [sourceId],
              mode: "or"
            }
          ],
          filterGroups: []
        });
      }

      // Use native OpenCTI search parameter for full-text search
      const graphqlQuery = {
        query: `query ThreatReportsPaginationQuery($count: Int!, $after: ID, $orderBy: ReportsOrdering, $orderMode: OrderingMode, $filters: FilterGroup, $search: String) {
          reports(first: $count, after: $after, orderBy: $orderBy, orderMode: $orderMode, filters: $filters, search: $search) {
            edges {
              node {
                id
                name
                description
                published
                created_at
                report_types
                createdBy {
                  __typename
                  id
                  name
                }
                objectMarking {
                  id
                  definition
                  definition_type
                  x_opencti_color
                }
                objectLabel {
                  id
                  value
                  color
                }
              }
              cursor
            }
            pageInfo {
              hasNextPage
              endCursor
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          after: cursor || null,
          orderMode: "desc",
          orderBy: "published",
          search: search || null,
          filters: {
            mode: "and",
            filters: [
              {
                key: "entity_type",
                values: ["Report"],
                operator: "eq",
                mode: "or"
              },
              // Exclude media-report types
              {
                key: "report_types",
                operator: "not_eq",
                values: ["media-report"],
                mode: "or"
              },
              // Exclude threat-advisory types (shown in dedicated Advisories page)
              {
                key: "report_types",
                operator: "not_eq",
                values: ["threat-advisory"],
                mode: "or"
              },
              // Exclude darkweb-forum types (shown in dedicated Deep/Dark Web Forums page)
              {
                key: "report_types",
                operator: "not_eq",
                values: ["darkweb-forum"],
                mode: "or"
              },
              ...reportTypeFilters
            ],
            filterGroups: [
              // Exclude ransomware bot reports
              {
                mode: "and",
                filters: [
                  {
                    key: "createdBy",
                    operator: "not_eq",
                    values: [RANSOMWARE_BOT_ID],
                    mode: "or"
                  }
                ],
                filterGroups: []
              },
              ...dateFilterGroups,
              ...sourceFilterGroups
            ]
          }
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('OpenCTI API error:', errorText);
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI threat reports response received, count:', data.data?.reports?.edges?.length);

      if (data.errors) {
        console.error('GraphQL errors:', data.errors);
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      // Transform the data
      const transformedData = data.data.reports.edges.map((edge: any) => {
        const node = edge.node;
        
        // Get the first TLP marking
        const tlpMarking = node.objectMarking?.find((m: any) => m.definition_type === 'TLP');
        
        return {
          id: node.id,
          name: node.name,
          description: node.description || '',
          date: node.created_at || node.published || new Date().toISOString(),
          reportTypes: node.report_types || [],
          source: node.createdBy?.name || 'Unknown',
          sourceId: node.createdBy?.id || null,
          labels: node.objectLabel?.map((label: any) => ({
            id: label.id,
            value: label.value,
            color: label.color
          })) || [],
          tlpMarking: tlpMarking ? {
            definition: tlpMarking.definition,
            color: tlpMarking.x_opencti_color
          } : null,
        };
      });

      console.log('Transformed threat reports:', transformedData.length, 'items');
      console.log('PageInfo:', data.data.reports.pageInfo);

      return new Response(JSON.stringify({ 
        data: transformedData,
        pageInfo: data.data.reports.pageInfo
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (queryType === 'darkweb-forums') {
      // Dedicated query for darkweb-forum reports
      const dateFilterGroups: any[] = [];
      
      if (published_start || published_end) {
        const dateFilters: any[] = [];
        
        if (published_start) {
          dateFilters.push({
            key: "published",
            operator: "gte",
            values: [published_start],
            mode: "or"
          });
        }
        
        if (published_end) {
          dateFilters.push({
            key: "published",
            operator: "lte",
            values: [published_end],
            mode: "or"
          });
        }
        
        if (dateFilters.length > 0) {
          dateFilterGroups.push({
            mode: "and",
            filters: dateFilters,
            filterGroups: []
          });
        }
      }

      const graphqlQuery = {
        query: `query DarkWebForumsPaginationQuery($count: Int!, $after: ID, $orderBy: ReportsOrdering, $orderMode: OrderingMode, $filters: FilterGroup, $search: String) {
          reports(first: $count, after: $after, orderBy: $orderBy, orderMode: $orderMode, filters: $filters, search: $search) {
            edges {
              node {
                id
                name
                description
                published
                created_at
                report_types
                createdBy {
                  __typename
                  id
                  name
                }
                objectMarking {
                  id
                  definition
                  definition_type
                  x_opencti_color
                }
                objectLabel {
                  id
                  value
                  color
                }
              }
              cursor
            }
            pageInfo {
              hasNextPage
              endCursor
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          after: cursor || null,
          orderMode: "desc",
          orderBy: "published",
          search: search || null,
          filters: {
            mode: "and",
            filters: [
              {
                key: "entity_type",
                values: ["Report"],
                operator: "eq",
                mode: "or"
              },
              // Only darkweb-forum type
              {
                key: "report_types",
                operator: "eq",
                values: ["darkweb-forum"],
                mode: "or"
              }
            ],
            filterGroups: [
              ...dateFilterGroups
            ]
          }
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('OpenCTI API error:', errorText);
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI darkweb-forums response received, count:', data.data?.reports?.edges?.length);

      if (data.errors) {
        console.error('GraphQL errors:', data.errors);
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      // Transform the data
      const transformedData = data.data.reports.edges.map((edge: any) => {
        const node = edge.node;
        
        // Get the first TLP marking
        const tlpMarking = node.objectMarking?.find((m: any) => m.definition_type === 'TLP');
        
        return {
          id: node.id,
          name: node.name,
          description: node.description || '',
          date: node.created_at || node.published || new Date().toISOString(),
          reportTypes: node.report_types || [],
          source: node.createdBy?.name || 'Unknown',
          sourceId: node.createdBy?.id || null,
          labels: node.objectLabel?.map((label: any) => ({
            id: label.id,
            value: label.value,
            color: label.color
          })) || [],
          tlpMarking: tlpMarking ? {
            definition: tlpMarking.definition,
            color: tlpMarking.x_opencti_color
          } : null,
        };
      });

      console.log('Transformed darkweb-forums:', transformedData.length, 'items');

      return new Response(JSON.stringify({ 
        data: transformedData,
        pageInfo: data.data.reports.pageInfo
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (queryType === 'media-reports') {
      // Build date filter groups
      const dateFilterGroups: any[] = [];
      
      if (published_start || published_end) {
        const dateFilters: any[] = [];
        
        if (published_start) {
          dateFilters.push({
            key: "published",
            operator: "gte",
            values: [published_start],
            mode: "or"
          });
        }
        
        if (published_end) {
          dateFilters.push({
            key: "published",
            operator: "lte",
            values: [published_end],
            mode: "or"
          });
        }
        
        if (dateFilters.length > 0) {
          dateFilterGroups.push({
            mode: "and",
            filters: dateFilters,
            filterGroups: []
          });
        }
      }

      const graphqlQuery = {
        query: `query MediaReportsPaginationQuery($count: Int!, $after: ID, $orderBy: ReportsOrdering, $orderMode: OrderingMode, $filters: FilterGroup, $search: String) {
          reports(first: $count, after: $after, orderBy: $orderBy, orderMode: $orderMode, filters: $filters, search: $search) {
            edges {
              node {
                id
                name
                description
                published
                created_at
                report_types
                createdBy {
                  __typename
                  id
                  name
                }
                externalReferences {
                  edges {
                    node {
                      url
                      source_name
                    }
                  }
                }
                objectMarking {
                  id
                  definition
                  definition_type
                  x_opencti_color
                }
                objectLabel {
                  id
                  value
                  color
                }
              }
              cursor
            }
            pageInfo {
              hasNextPage
              endCursor
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          after: cursor || null,
          orderMode: "desc",
          orderBy: "published",
          search: search || null,
          filters: {
            mode: "and",
            filters: [
              {
                key: "entity_type",
                values: ["Report"],
                operator: "eq",
                mode: "or"
              },
              // Only include media-report types
              {
                key: "report_types",
                operator: "eq",
                values: ["media-report"],
                mode: "or"
              }
            ],
            filterGroups: [
              ...dateFilterGroups
            ]
          }
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('OpenCTI API error:', errorText);
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI media reports response received, count:', data.data?.reports?.edges?.length);

      if (data.errors) {
        console.error('GraphQL errors:', data.errors);
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      // Transform the data
      const transformedData = data.data.reports.edges.map((edge: any) => {
        const node = edge.node;

        // Get the first TLP marking
        const tlpMarking = node.objectMarking?.find((m: any) => m.definition_type === 'TLP');

        // Extract external references
        const externalRefs = node.externalReferences?.edges?.map((e: any) => ({
          url: e.node.url,
          sourceName: e.node.source_name
        })) || [];

        return {
          id: node.id,
          name: node.name,
          description: node.description || '',
          date: node.created_at || node.published || new Date().toISOString(),
          reportTypes: node.report_types || [],
          source: node.createdBy?.name || 'Unknown',
          sourceId: node.createdBy?.id || null,
          externalReferences: externalRefs,
          labels: node.objectLabel?.map((label: any) => ({
            id: label.id,
            value: label.value,
            color: label.color
          })) || [],
          tlpMarking: tlpMarking ? {
            definition: tlpMarking.definition,
            color: tlpMarking.x_opencti_color
          } : null,
        };
      });

      console.log('Transformed media reports:', transformedData.length, 'items');
      console.log('PageInfo:', data.data.reports.pageInfo);

      return new Response(JSON.stringify({ 
        data: transformedData,
        pageInfo: data.data.reports.pageInfo
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (queryType === 'report-detail') {
      if (!id) {
        throw new Error('Report ID is required');
      }

      const graphqlQuery = {
        query: `query ReportDetail($id: String!) {
          report(id: $id) {
            id
            name
            description
            published
            report_types
            createdBy {
              __typename
              id
              name
            }
            objectMarking {
              definition
              definition_type
              x_opencti_color
            }
            objectLabel {
              value
              color
            }
            externalReferences {
              edges {
                node {
                  id
                  source_name
                  description
                  url
                  external_id
                }
              }
            }
            objects {
              edges {
                node {
                  __typename
                  ... on Country {
                    id
                    countryName: name
                  }
                  ... on Sector {
                    id
                    sectorName: name
                  }
                  ... on IntrusionSet {
                    id
                    intrusionSetName: name
                  }
                  ... on Organization {
                    id
                    organizationName: name
                  }
                  ... on IPv4Addr {
                    id
                    value
                  }
                  ... on IPv6Addr {
                    id
                    value
                  }
                  ... on DomainName {
                    id
                    value
                  }
                  ... on Url {
                    id
                    value
                  }
                  ... on StixFile {
                    id
                    fileName: name
                    hashes {
                      algorithm
                      hash
                    }
                  }
                  ... on Indicator {
                    id
                    indicatorName: name
                    pattern
                    pattern_type
                    x_opencti_main_observable_type
                    created
                  }
                  ... on AttackPattern {
                    id
                    attackPatternName: name
                    x_mitre_id
                    description
                    killChainPhases { phase_name x_opencti_order }
                    coursesOfAction { edges { node { id name description x_mitre_id } } }
                  }
                  ... on Malware {
                    id
                    malwareName: name
                  }
                  ... on Vulnerability {
                    id
                    vulnerabilityName: name
                  }
                }
              }
            }
          }
        }`,
        variables: { id }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('OpenCTI API error:', errorText);
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI detail response:', JSON.stringify(data, null, 2));

      if (data.errors) {
        console.error('GraphQL errors:', data.errors);
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      const report = data.data.report;
      const objects = report.objects?.edges || [];
      
      // Get TLP marking
      const tlpMarking = report.objectMarking?.find((m: any) => m.definition_type === 'TLP');
      
      // Extract IoCs and other entities
      const ipAddresses = objects
        .filter((e: any) => e.node.__typename === 'IPv4Addr' || e.node.__typename === 'IPv6Addr')
        .map((e: any) => ({ type: e.node.__typename, value: e.node.value }));
      
      const domains = objects
        .filter((e: any) => e.node.__typename === 'DomainName')
        .map((e: any) => ({ value: e.node.value }));
      
      const urls = objects
        .filter((e: any) => e.node.__typename === 'Url')
        .map((e: any) => ({ value: e.node.value }));
      
      const files = objects
        .filter((e: any) => e.node.__typename === 'StixFile')
        .map((e: any) => ({ 
          name: e.node.fileName,
          hashes: e.node.hashes || []
        }));
      
      const indicators = objects
        .filter((e: any) => e.node.__typename === 'Indicator')
        .map((e: any) => ({ 
          id: e.node.id,
          name: e.node.indicatorName,
          pattern: e.node.pattern,
          patternType: e.node.pattern_type,
          observableType: e.node.x_opencti_main_observable_type,
          created: e.node.created
        }));
      
      const attackPatterns = objects
        .filter((e: any) => e.node.__typename === 'AttackPattern')
        .map((e: any) => ({ 
          id: e.node.id,
          name: e.node.attackPatternName,
          mitreId: e.node.x_mitre_id,
          description: e.node.description,
          killChainPhases: e.node.killChainPhases?.map((k: any) => ({ phaseName: k.phase_name, order: k.x_opencti_order || 0 })) || []
        }));
      
      const mitigatingActions = objects
        .filter((e: any) => e.node.__typename === 'AttackPattern')
        .flatMap((e: any) => 
          (e.node.coursesOfAction?.edges || []).map((coaEdge: any) => ({
            id: coaEdge.node.id,
            mitreId: coaEdge.node.x_mitre_id || e.node.x_mitre_id || '',
            attackPatternName: e.node.attackPatternName || '',
            name: coaEdge.node.name,
            description: coaEdge.node.description || ''
          }))
        ).filter((c: any) => c.id);
      
      const malware = objects
        .filter((e: any) => e.node.__typename === 'Malware')
        .map((e: any) => ({ id: e.node.id, name: e.node.malwareName }));
      
      const vulnerabilities = objects
        .filter((e: any) => e.node.__typename === 'Vulnerability')
        .map((e: any) => ({ id: e.node.id, name: e.node.vulnerabilityName }));

      const reportDetail = {
        id: report.id,
        name: report.name,
        description: report.description || 'N/A',
        date: report.published ? new Date(report.published).toISOString().split('T')[0] : new Date().toISOString().split('T')[0],
        reportTypes: report.report_types || [],
        source: report.createdBy?.name || 'Unknown',
        sourceId: report.createdBy?.id || null,
        sectors: objects
          .filter((e: any) => e.node.__typename === 'Sector')
          .map((e: any) => ({ id: e.node.id, name: e.node.sectorName })),
        countries: objects
          .filter((e: any) => e.node.__typename === 'Country')
          .map((e: any) => ({ id: e.node.id, name: e.node.countryName })),
        threatGroups: objects
          .filter((e: any) => e.node.__typename === 'IntrusionSet')
          .map((e: any) => ({ id: e.node.id, name: e.node.intrusionSetName })),
        victimOrganizations: objects
          .filter((e: any) => e.node.__typename === 'Organization')
          .map((e: any) => ({ id: e.node.id, name: e.node.organizationName })),
        labels: report.objectLabel?.map((label: any) => ({
          value: label.value,
          color: label.color
        })) || [],
        markings: report.objectMarking?.map((marking: any) => ({
          definition: marking.definition,
          color: marking.x_opencti_color
        })) || [],
        tlpMarking: tlpMarking ? {
          definition: tlpMarking.definition,
          color: tlpMarking.x_opencti_color
        } : null,
        externalReferences: report.externalReferences?.edges?.map((edge: any) => ({
          id: edge.node.id,
          sourceName: edge.node.source_name,
          description: edge.node.description,
          url: edge.node.url,
          externalId: edge.node.external_id,
        })) || [],
        // IoCs
        iocs: {
          ipAddresses,
          domains,
          urls,
          files,
          indicators,
        },
        // TTPs
        attackPatterns,
        mitigatingActions,
        malware,
        vulnerabilities,
      };

      return new Response(JSON.stringify({ data: reportDetail }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (queryType === 'vulnerabilities') {
      // Build date filter groups
      const dateFilterGroups: any[] = [];
      
      if (published_start || published_end) {
        const dateFilters: any[] = [];
        
        if (published_start) {
          dateFilters.push({
            key: "created",
            operator: "gte",
            values: [published_start],
            mode: "or"
          });
        }
        
        if (published_end) {
          dateFilters.push({
            key: "created",
            operator: "lte",
            values: [published_end],
            mode: "or"
          });
        }
        
        if (dateFilters.length > 0) {
          dateFilterGroups.push({
            mode: "and",
            filters: dateFilters,
            filterGroups: []
          });
        }
      }

      // Use native OpenCTI search parameter for full-text search
      const graphqlQuery = {
        query: `query VulnerabilitiesLinesPaginationQuery($count: Int!, $cursor: ID, $orderBy: VulnerabilitiesOrdering, $orderMode: OrderingMode, $filters: FilterGroup, $search: String) {
          vulnerabilities(first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode, filters: $filters, search: $search) {
            edges {
              node {
                id
                name
                description
                x_opencti_cvss_base_severity
                created
                modified
                confidence
                entity_type
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
                objectLabel {
                  id
                  value
                  color
                }
                creators {
                  id
                  name
                }
              }
              cursor
            }
            pageInfo {
              endCursor
              hasNextPage
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          cursor: cursor || null,
          orderMode: "desc",
          orderBy: "created",
          search: search || null,
          filters: dateFilterGroups.length > 0 ? {
            mode: "and",
            filters: [],
            filterGroups: dateFilterGroups
          } : null
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('OpenCTI API error:', errorText);
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI vulnerabilities response received, count:', data.data?.vulnerabilities?.edges?.length);

      if (data.errors) {
        console.error('GraphQL errors:', data.errors);
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      // Transform the data
      const transformedData = data.data.vulnerabilities.edges.map((edge: any) => {
        const node = edge.node;
        
        return {
          id: node.id,
          cve: node.name,
          description: node.description || '',
          severity: node.x_opencti_cvss_base_severity || 'UNKNOWN',
          created: node.created ? new Date(node.created).toISOString().split('T')[0] : '',
          modified: node.modified ? new Date(node.modified).toISOString().split('T')[0] : '',
          confidence: node.confidence,
          labels: node.objectLabel?.map((label: any) => ({
            id: label.id,
            value: label.value,
            color: label.color
          })) || [],
          markings: node.objectMarking?.map((marking: any) => ({
            definition: marking.definition,
            color: marking.x_opencti_color
          })) || [],
          creators: node.creators?.map((creator: any) => creator.name) || [],
        };
      });

      console.log('Transformed vulnerabilities:', transformedData.length, 'items');
      console.log('PageInfo:', data.data.vulnerabilities.pageInfo);

      return new Response(JSON.stringify({
        data: transformedData,
        pageInfo: data.data.vulnerabilities.pageInfo
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Reports-linked vulnerabilities - CVEs mentioned in reports from the time period
    if (queryType === 'reports-vulnerabilities') {
      // Build date filter for reports
      const dateFilterGroups: any[] = [];

      if (published_start || published_end) {
        const dateFilters: any[] = [];

        if (published_start) {
          dateFilters.push({
            key: "published",
            operator: "gte",
            values: [published_start],
            mode: "or"
          });
        }

        if (published_end) {
          dateFilters.push({
            key: "published",
            operator: "lte",
            values: [published_end],
            mode: "or"
          });
        }

        if (dateFilters.length > 0) {
          dateFilterGroups.push({
            mode: "and",
            filters: dateFilters,
            filterGroups: []
          });
        }
      }

      // Query reports (both threat-reports and media-reports) with their linked vulnerabilities
      const reportsQuery = {
        query: `query ReportsWithVulnerabilities($count: Int!, $filters: FilterGroup) {
          reports(first: $count, orderBy: published, orderMode: desc, filters: $filters) {
            edges {
              node {
                id
                published
                report_types
                objects {
                  edges {
                    node {
                      __typename
                      ... on Vulnerability {
                        id
                        name
                        description
                        x_opencti_cvss_base_severity
                        x_opencti_cvss_base_score
                        x_opencti_cisa_kev
                        created
                        modified
                      }
                    }
                  }
                }
              }
            }
            pageInfo {
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          filters: dateFilterGroups.length > 0 ? {
            mode: "and",
            filters: [
              {
                key: "entity_type",
                values: ["Report"],
                operator: "eq",
                mode: "or"
              },
              // Exclude ransomware bot reports and darkweb forums
              {
                key: "createdBy",
                operator: "not_eq",
                values: [RANSOMWARE_BOT_ID],
                mode: "or"
              },
              {
                key: "report_types",
                operator: "not_eq",
                values: ["darkweb-forum"],
                mode: "or"
              }
            ],
            filterGroups: dateFilterGroups
          } : {
            mode: "and",
            filters: [
              {
                key: "entity_type",
                values: ["Report"],
                operator: "eq",
                mode: "or"
              },
              {
                key: "createdBy",
                operator: "not_eq",
                values: [RANSOMWARE_BOT_ID],
                mode: "or"
              },
              {
                key: "report_types",
                operator: "not_eq",
                values: ["darkweb-forum"],
                mode: "or"
              }
            ],
            filterGroups: []
          }
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(reportsQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('OpenCTI API error:', errorText);
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();

      if (data.errors) {
        console.error('GraphQL errors:', data.errors);
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      // Extract unique vulnerabilities from all reports, tracking source type and report date
      const vulnMap = new Map<string, any>();

      for (const reportEdge of data.data?.reports?.edges || []) {
        const reportTypes = reportEdge.node?.report_types || [];
        const reportPublished = reportEdge.node?.published;
        const isMediaReport = reportTypes.includes('media-report');
        const source = isMediaReport ? 'Media' : 'Threat Report';

        const objects = reportEdge.node?.objects?.edges || [];
        for (const objEdge of objects) {
          const node = objEdge.node;
          if (node?.__typename === 'Vulnerability' && node.id) {
            // If we've seen this vuln before, keep the more important source (Threat Report > Media)
            // and keep the most recent report date
            const existing = vulnMap.get(node.id);
            if (!existing) {
              vulnMap.set(node.id, {
                id: node.id,
                cve: node.name,
                description: node.description || '',
                severity: node.x_opencti_cvss_base_severity || 'UNKNOWN',
                cvss: node.x_opencti_cvss_base_score ? { baseScore: node.x_opencti_cvss_base_score } : null,
                cisaKev: node.x_opencti_cisa_kev || false,
                created: node.created ? new Date(node.created).toISOString().split('T')[0] : '',
                modified: node.modified ? new Date(node.modified).toISOString().split('T')[0] : '',
                reportDate: reportPublished ? new Date(reportPublished).toISOString() : '',
                source: source,
              });
            } else {
              // Update source to Threat Report if it was previously only in Media
              if (existing.source === 'Media' && source === 'Threat Report') {
                existing.source = 'Threat Report';
              }
              // Keep the most recent report date
              if (reportPublished && (!existing.reportDate || reportPublished > existing.reportDate)) {
                existing.reportDate = new Date(reportPublished).toISOString();
              }
            }
          }
        }
      }

      // Convert map to array and sort by severity/CVSS
      const severityOrder: Record<string, number> = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'UNKNOWN': 4 };
      const vulnerabilities = Array.from(vulnMap.values())
        .sort((a, b) => {
          const severityDiff = (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4);
          if (severityDiff !== 0) return severityDiff;
          return (b.cvss?.baseScore || 0) - (a.cvss?.baseScore || 0);
        });

      console.log('Reports-vulnerabilities: Found', vulnerabilities.length, 'unique vulnerabilities from', data.data?.reports?.edges?.length || 0, 'reports');

      return new Response(JSON.stringify({
        data: vulnerabilities,
        pageInfo: {
          globalCount: vulnerabilities.length,
          hasNextPage: false,
          endCursor: null
        }
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (queryType === 'vulnerability-detail') {
      if (!id) {
        throw new Error('Vulnerability ID is required');
      }

      const graphqlQuery = {
        query: `query VulnerabilityDetail($id: String!) {
          vulnerability(id: $id) {
            id
            name
            description
            created
            modified
            confidence
            x_opencti_cvss_vector_string
            x_opencti_cvss_base_score
            x_opencti_cvss_base_severity
            x_opencti_cvss_attack_vector
            x_opencti_cvss_attack_complexity
            x_opencti_cvss_privileges_required
            x_opencti_cvss_user_interaction
            x_opencti_cvss_scope
            x_opencti_cvss_confidentiality_impact
            x_opencti_cvss_integrity_impact
            x_opencti_cvss_availability_impact
            x_opencti_cisa_kev
            x_opencti_epss_score
            x_opencti_epss_percentile
            createdBy {
              __typename
              id
              name
            }
            objectMarking {
              definition
              definition_type
              x_opencti_color
            }
            objectLabel {
              value
              color
            }
            externalReferences {
              edges {
                node {
                  id
                  source_name
                  description
                  url
                }
              }
            }
          }
        }`,
        variables: { id }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('OpenCTI API error:', errorText);
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI vulnerability detail response:', JSON.stringify(data, null, 2));

      if (data.errors) {
        console.error('GraphQL errors:', data.errors);
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      const vuln = data.data.vulnerability;
      
      const vulnerabilityDetail = {
        id: vuln.id,
        cve: vuln.name,
        description: vuln.description || 'No description available',
        created: vuln.created ? new Date(vuln.created).toISOString().split('T')[0] : '',
        modified: vuln.modified ? new Date(vuln.modified).toISOString().split('T')[0] : '',
        confidence: vuln.confidence,
        cvss: {
          vectorString: vuln.x_opencti_cvss_vector_string,
          baseScore: vuln.x_opencti_cvss_base_score,
          baseSeverity: vuln.x_opencti_cvss_base_severity,
          attackVector: vuln.x_opencti_cvss_attack_vector,
          attackComplexity: vuln.x_opencti_cvss_attack_complexity,
          privilegesRequired: vuln.x_opencti_cvss_privileges_required,
          userInteraction: vuln.x_opencti_cvss_user_interaction,
          scope: vuln.x_opencti_cvss_scope,
          confidentialityImpact: vuln.x_opencti_cvss_confidentiality_impact,
          integrityImpact: vuln.x_opencti_cvss_integrity_impact,
          availabilityImpact: vuln.x_opencti_cvss_availability_impact,
        },
        cisaKev: vuln.x_opencti_cisa_kev,
        epssScore: vuln.x_opencti_epss_score,
        epssPercentile: vuln.x_opencti_epss_percentile,
        source: vuln.createdBy?.name || 'Unknown',
        labels: vuln.objectLabel?.map((label: any) => ({
          value: label.value,
          color: label.color
        })) || [],
        markings: vuln.objectMarking?.map((marking: any) => ({
          definition: marking.definition,
          color: marking.x_opencti_color
        })) || [],
        externalReferences: vuln.externalReferences?.edges?.map((edge: any) => ({
          id: edge.node.id,
          sourceName: edge.node.source_name,
          description: edge.node.description,
          url: edge.node.url,
        })) || [],
      };

      return new Response(JSON.stringify({ data: vulnerabilityDetail }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (queryType === 'campaigns') {
      // Build date filter groups
      const dateFilterGroups: any[] = [];
      
      if (published_start || published_end) {
        const dateFilters: any[] = [];
        
        if (published_start) {
          dateFilters.push({
            key: "modified",
            operator: "gte",
            values: [published_start],
            mode: "or"
          });
        }
        
        if (published_end) {
          dateFilters.push({
            key: "modified",
            operator: "lte",
            values: [published_end],
            mode: "or"
          });
        }
        
        if (dateFilters.length > 0) {
          dateFilterGroups.push({
            mode: "and",
            filters: dateFilters,
            filterGroups: []
          });
        }
      }

      // Use native OpenCTI search parameter for full-text search
      const graphqlQuery = {
        query: `query CampaignsPaginationQuery($count: Int!, $cursor: ID, $orderBy: CampaignsOrdering, $orderMode: OrderingMode, $filters: FilterGroup, $search: String) {
          campaigns(first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode, filters: $filters, search: $search) {
            edges {
              node {
                id
                name
                description
                aliases
                created
                modified
                createdBy {
                  __typename
                  id
                  name
                }
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_color
                }
                objectLabel {
                  id
                  value
                  color
                }
                targetedCountries: stixCoreRelationships(relationship_type: "targets", toTypes: ["Country"], first: 5) {
                  edges {
                    node {
                      to {
                        __typename
                        ... on Country {
                          name
                          id
                        }
                      }
                    }
                  }
                }
                targetedSectors: stixCoreRelationships(relationship_type: "targets", toTypes: ["Sector"], first: 5) {
                  edges {
                    node {
                      to {
                        __typename
                        ... on Sector {
                          name
                          id
                        }
                      }
                    }
                  }
                }
                usedMalware: stixCoreRelationships(relationship_type: "uses", toTypes: ["Malware"], first: 5) {
                  edges {
                    node {
                      to {
                        __typename
                        ... on Malware {
                          name
                          id
                        }
                      }
                    }
                  }
                }
              }
              cursor
            }
            pageInfo {
              endCursor
              hasNextPage
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          cursor: cursor || null,
          orderMode: "desc",
          orderBy: "created",
          search: search || null,
          filters: dateFilterGroups.length > 0 ? {
            mode: "and",
            filters: [],
            filterGroups: dateFilterGroups
          } : null
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('OpenCTI API error:', errorText);
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI campaigns response received, count:', data.data?.campaigns?.edges?.length);

      if (data.errors) {
        console.error('GraphQL errors:', data.errors);
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      // Transform the data
      const transformedData = data.data.campaigns.edges.map((edge: any) => {
        const node = edge.node;
        
        const targetedCountries = node.targetedCountries?.edges
          ?.filter((e: any) => e.node.to?.__typename === 'Country')
          ?.map((e: any) => e.node.to.name) || [];
        
        const targetedSectors = node.targetedSectors?.edges
          ?.filter((e: any) => e.node.to?.__typename === 'Sector')
          ?.map((e: any) => e.node.to.name) || [];
        
        const usedMalware = node.usedMalware?.edges
          ?.filter((e: any) => e.node.to?.__typename === 'Malware')
          ?.map((e: any) => ({ id: e.node.to.id, name: e.node.to.name })) || [];
        
        return {
          id: node.id,
          name: node.name,
          description: node.description || '',
          aliases: node.aliases || [],
          date: node.created ? new Date(node.created).toISOString().split('T')[0] : '',
          created: node.created ? new Date(node.created).toISOString().split('T')[0] : '',
          source: node.createdBy?.name || 'Unknown',
          sourceId: node.createdBy?.id || null,
          targetedCountries,
          targetedSectors,
          usedMalware,
          labels: node.objectLabel?.map((label: any) => ({
            id: label.id,
            value: label.value,
            color: label.color
          })) || [],
          markings: node.objectMarking?.map((marking: any) => ({
            definition: marking.definition,
            color: marking.x_opencti_color
          })) || [],
        };
      });

      console.log('Transformed campaigns:', transformedData.length, 'items');
      console.log('PageInfo:', data.data.campaigns.pageInfo);

      return new Response(JSON.stringify({ 
        data: transformedData,
        pageInfo: data.data.campaigns.pageInfo
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (queryType === 'campaign-detail') {
      if (!id) {
        throw new Error('Campaign ID is required');
      }

      const graphqlQuery = {
        query: `query CampaignDetail($id: String!) {
          campaign(id: $id) {
            id
            name
            description
            aliases
            created
            modified
            first_seen
            last_seen
            objective
            createdBy {
              __typename
              id
              name
            }
            objectMarking {
              definition
              definition_type
              x_opencti_color
            }
            objectLabel {
              value
              color
            }
            externalReferences {
              edges {
                node {
                  id
                  source_name
                  description
                  url
                  external_id
                }
              }
            }
            targetedCountries: stixCoreRelationships(relationship_type: "targets", toTypes: ["Country"], first: 50) {
              edges {
                node {
                  to {
                    __typename
                    ... on Country {
                      name
                      id
                    }
                  }
                }
              }
            }
            targetedSectors: stixCoreRelationships(relationship_type: "targets", toTypes: ["Sector"], first: 20) {
              edges {
                node {
                  to {
                    __typename
                    ... on Sector {
                      name
                      id
                    }
                  }
                }
              }
            }
            usedMalware: stixCoreRelationships(relationship_type: "uses", toTypes: ["Malware"], first: 20) {
              edges {
                node {
                  to {
                    __typename
                    ... on Malware {
                      name
                      id
                    }
                  }
                }
              }
            }
            usedAttackPatterns: stixCoreRelationships(relationship_type: "uses", toTypes: ["Attack-Pattern"], first: 20) {
              edges {
                node {
                  to {
                    __typename
                    ... on AttackPattern {
                      name
                      id
                      description
                      x_mitre_id
                      killChainPhases { phase_name x_opencti_order }
                      coursesOfAction { edges { node { id name description x_mitre_id } } }
                    }
                  }
                }
              }
            }
            usedTools: stixCoreRelationships(relationship_type: "uses", toTypes: ["Tool"], first: 20) {
              edges {
                node {
                  to {
                    __typename
                    ... on Tool {
                      name
                      id
                    }
                  }
                }
              }
            }
            relatedIndicators: stixCoreRelationships(relationship_type: "indicates", fromTypes: ["Indicator"], first: 20) {
              edges {
                node {
                  from {
                    __typename
                    ... on Indicator {
                      name
                      id
                      pattern
                      x_opencti_main_observable_type
                      created
                    }
                  }
                }
              }
            }
            attributedTo: stixCoreRelationships(relationship_type: "attributed-to", toTypes: ["Intrusion-Set", "Threat-Actor-Group"], first: 10) {
              edges {
                node {
                  to {
                    __typename
                    ... on IntrusionSet {
                      name
                      id
                    }
                    ... on ThreatActorGroup {
                      name
                      id
                    }
                  }
                }
              }
            }
          }
        }`,
        variables: { id }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('OpenCTI API error:', errorText);
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI campaign detail response:', JSON.stringify(data, null, 2));

      if (data.errors) {
        console.error('GraphQL errors:', data.errors);
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      const campaign = data.data.campaign;
      
      const targetedCountries = campaign.targetedCountries?.edges
        ?.filter((e: any) => e.node.to?.__typename === 'Country')
        ?.map((e: any) => ({ id: e.node.to.id, name: e.node.to.name })) || [];
      
      const targetedSectors = campaign.targetedSectors?.edges
        ?.filter((e: any) => e.node.to?.__typename === 'Sector')
        ?.map((e: any) => ({ id: e.node.to.id, name: e.node.to.name })) || [];
      
      const usedMalware = campaign.usedMalware?.edges
        ?.filter((e: any) => e.node.to?.__typename === 'Malware')
        ?.map((e: any) => ({ id: e.node.to.id, name: e.node.to.name })) || [];
      
      const usedAttackPatterns = campaign.usedAttackPatterns?.edges
        ?.filter((e: any) => e.node.to?.__typename === 'AttackPattern')
        ?.map((e: any) => ({ 
          id: e.node.to.id, 
          name: e.node.to.name,
          description: e.node.to.description || '',
          mitreId: e.node.to.x_mitre_id,
          killChainPhases: e.node.to.killChainPhases?.map((k: any) => ({ phaseName: k.phase_name, order: k.x_opencti_order || 0 })) || []
        })) || [];
      
      const mitigatingActions = campaign.usedAttackPatterns?.edges?.flatMap((e: any) => 
        (e.node.to?.coursesOfAction?.edges || []).map((coaEdge: any) => ({
          id: coaEdge.node.id,
          mitreId: coaEdge.node.x_mitre_id || e.node.to?.x_mitre_id || '',
          attackPatternName: e.node.to?.name || '',
          name: coaEdge.node.name,
          description: coaEdge.node.description || ''
        }))
      ).filter((c: any) => c.id) || [];
      
      const usedTools = campaign.usedTools?.edges
        ?.filter((e: any) => e.node.to?.__typename === 'Tool')
        ?.map((e: any) => ({ id: e.node.to.id, name: e.node.to.name })) || [];
      
      const relatedIndicators = campaign.relatedIndicators?.edges
        ?.filter((e: any) => e.node.from?.__typename === 'Indicator')
        ?.map((e: any) => ({ id: e.node.from.id, name: e.node.from.name, pattern: e.node.from.pattern, observableType: e.node.from.x_opencti_main_observable_type, created: e.node.from.created })) || [];
      
      const attributedTo = campaign.attributedTo?.edges
        ?.map((e: any) => ({ 
          id: e.node.to.id, 
          name: e.node.to.name,
          type: e.node.to.__typename
        })) || [];

      const campaignDetail = {
        id: campaign.id,
        name: campaign.name,
        description: campaign.description || 'No description available',
        aliases: campaign.aliases || [],
        created: campaign.created ? new Date(campaign.created).toISOString().split('T')[0] : '',
        modified: campaign.modified ? new Date(campaign.modified).toISOString().split('T')[0] : '',
        firstSeen: campaign.first_seen ? new Date(campaign.first_seen).toISOString().split('T')[0] : null,
        lastSeen: campaign.last_seen ? new Date(campaign.last_seen).toISOString().split('T')[0] : null,
        objective: campaign.objective || null,
        source: campaign.createdBy?.name || 'Unknown',
        sourceId: campaign.createdBy?.id || null,
        targetedCountries,
        targetedSectors,
        usedMalware,
        usedAttackPatterns,
        mitigatingActions,
        usedTools,
        relatedIndicators,
        attributedTo,
        labels: campaign.objectLabel?.map((label: any) => ({
          value: label.value,
          color: label.color
        })) || [],
        markings: campaign.objectMarking?.map((marking: any) => ({
          definition: marking.definition,
          color: marking.x_opencti_color
        })) || [],
        externalReferences: campaign.externalReferences?.edges?.map((edge: any) => ({
          id: edge.node.id,
          sourceName: edge.node.source_name,
          description: edge.node.description,
          url: edge.node.url,
          externalId: edge.node.external_id,
        })) || [],
      };

      return new Response(JSON.stringify({ data: campaignDetail }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // ============ INTRUSION SETS ============
    if (queryType === 'intrusion-sets') {
      // Use native OpenCTI search parameter for full-text search
      const graphqlQuery = {
        query: `query IntrusionSetsPaginationQuery($count: Int!, $cursor: ID, $orderBy: IntrusionSetsOrdering, $orderMode: OrderingMode, $search: String) {
          intrusionSets(first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode, search: $search) {
            edges {
              node {
                id
                name
                description
                aliases
                created
                modified
                first_seen
                last_seen
                resource_level
                primary_motivation
                secondary_motivations
                goals
                objectLabel {
                  id
                  value
                  color
                }
                targetedCountries: stixCoreRelationships(relationship_type: "targets", toTypes: ["Country"], first: 5) {
                  edges {
                    node {
                      to {
                        __typename
                        ... on Country { id name }
                      }
                    }
                  }
                }
                targetedSectors: stixCoreRelationships(relationship_type: "targets", toTypes: ["Sector"], first: 5) {
                  edges {
                    node {
                      to {
                        __typename
                        ... on Sector { id name }
                      }
                    }
                  }
                }
              }
              cursor
            }
            pageInfo {
              endCursor
              hasNextPage
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          cursor: cursor || null,
          orderMode: "desc",
          orderBy: "modified",
          search: search || null
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI intrusion sets response, count:', data.data?.intrusionSets?.edges?.length);

      if (data.errors) {
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      const transformedData = data.data.intrusionSets.edges.map((edge: any) => {
        const node = edge.node;
        return {
          id: node.id,
          name: node.name,
          description: node.description || '',
          aliases: node.aliases || [],
          created: node.created || '',
          modified: node.modified || '',
          firstSeen: node.first_seen || null,
          lastSeen: node.last_seen || null,
          resourceLevel: node.resource_level || null,
          primaryMotivation: node.primary_motivation || null,
          secondaryMotivations: node.secondary_motivations || [],
          goals: node.goals || [],
          labels: node.objectLabel?.map((l: any) => ({ value: l.value, color: l.color })) || [],
          targetedCountries: node.targetedCountries?.edges?.map((e: any) => ({ id: e.node.to?.id, name: e.node.to?.name })).filter((c: any) => c.id) || [],
          targetedSectors: node.targetedSectors?.edges?.map((e: any) => ({ id: e.node.to?.id, name: e.node.to?.name })).filter((s: any) => s.id) || [],
        };
      });

      return new Response(JSON.stringify({ 
        data: transformedData,
        pageInfo: data.data.intrusionSets.pageInfo
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (queryType === 'intrusion-set-detail') {
      if (!id) throw new Error('Intrusion Set ID is required');

      const graphqlQuery = {
        query: `query IntrusionSetDetail($id: String!) {
          intrusionSet(id: $id) {
            id
            name
            description
            aliases
            created
            modified
            first_seen
            last_seen
            resource_level
            primary_motivation
            secondary_motivations
            goals
            objectLabel { value color }
            externalReferences {
              edges {
                node { id source_name url }
              }
            }
            targetedCountries: stixCoreRelationships(relationship_type: "targets", toTypes: ["Country"], first: 50) {
              edges { node { to { __typename ... on Country { id name x_opencti_aliases } } } }
            }
            targetedSectors: stixCoreRelationships(relationship_type: "targets", toTypes: ["Sector"], first: 20) {
              edges { node { to { __typename ... on Sector { id name } } } }
            }
            usedMalware: stixCoreRelationships(relationship_type: "uses", toTypes: ["Malware"], first: 20) {
              edges { node { to { __typename ... on Malware { id name } } } }
            }
            usedTools: stixCoreRelationships(relationship_type: "uses", toTypes: ["Tool"], first: 20) {
              edges { node { to { __typename ... on Tool { id name } } } }
            }
            usedAttackPatterns: stixCoreRelationships(relationship_type: "uses", toTypes: ["Attack-Pattern"], first: 30) {
              edges { node { to { __typename ... on AttackPattern { id name description x_mitre_id killChainPhases { phase_name x_opencti_order } coursesOfAction { edges { node { id name description x_mitre_id } } } } } } }
            }
            relatedIndicators: stixCoreRelationships(relationship_type: "indicates", fromTypes: ["Indicator"], first: 50) {
              edges { node { from { __typename ... on Indicator { id name pattern x_opencti_main_observable_type x_opencti_score created } } } }
            }
            relatedVulnerabilities: stixCoreRelationships(relationship_type: "targets", toTypes: ["Vulnerability"], first: 20) {
              edges { node { to { __typename ... on Vulnerability { id name description } } } }
            }
            reports { edges { node { id name published } } }
            campaigns: stixCoreRelationships(relationship_type: "attributed-to", fromTypes: ["Campaign"], first: 20) {
              edges { node { from { __typename ... on Campaign { id name } } } }
            }
          }
        }`,
        variables: { id }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      if (data.errors) throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);

      const is = data.data.intrusionSet;
      const detail = {
        id: is.id,
        name: is.name,
        description: is.description || '',
        aliases: is.aliases || [],
        created: is.created || '',
        modified: is.modified || '',
        firstSeen: is.first_seen || null,
        lastSeen: is.last_seen || null,
        resourceLevel: is.resource_level || null,
        primaryMotivation: is.primary_motivation || null,
        secondaryMotivations: is.secondary_motivations || [],
        goals: is.goals || [],
        labels: is.objectLabel?.map((l: any) => ({ value: l.value, color: l.color })) || [],
        targetedCountries: is.targetedCountries?.edges?.map((e: any) => ({ id: e.node.to?.id, name: e.node.to?.name })).filter((c: any) => c.id) || [],
        targetedSectors: is.targetedSectors?.edges?.map((e: any) => ({ id: e.node.to?.id, name: e.node.to?.name })).filter((s: any) => s.id) || [],
        usedMalware: is.usedMalware?.edges?.map((e: any) => ({ id: e.node.to?.id, name: e.node.to?.name })).filter((m: any) => m.id) || [],
        usedTools: is.usedTools?.edges?.map((e: any) => ({ id: e.node.to?.id, name: e.node.to?.name })).filter((t: any) => t.id) || [],
        usedAttackPatterns: is.usedAttackPatterns?.edges?.map((e: any) => ({ id: e.node.to?.id, name: e.node.to?.name, description: e.node.to?.description || '', mitreId: e.node.to?.x_mitre_id, killChainPhases: e.node.to?.killChainPhases?.map((k: any) => ({ phaseName: k.phase_name, order: k.x_opencti_order || 0 })) || [] })).filter((a: any) => a.id) || [],
        mitigatingActions: is.usedAttackPatterns?.edges?.flatMap((e: any) => 
          (e.node.to?.coursesOfAction?.edges || []).map((coaEdge: any) => ({
            id: coaEdge.node.id,
            mitreId: coaEdge.node.x_mitre_id || e.node.to?.x_mitre_id || '',
            attackPatternName: e.node.to?.name || '',
            name: coaEdge.node.name,
            description: coaEdge.node.description || ''
          }))
        ).filter((c: any) => c.id) || [],
        externalReferences: is.externalReferences?.edges?.map((e: any) => ({ id: e.node.id, sourceName: e.node.source_name, url: e.node.url })) || [],
        relatedReports: is.reports?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name, date: e.node.published?.split('T')[0] || '' })) || [],
        relatedCampaigns: is.campaigns?.edges?.map((e: any) => ({ id: e.node.from?.id, name: e.node.from?.name })).filter((c: any) => c.id) || [],
        relatedIndicators: is.relatedIndicators?.edges?.map((e: any) => ({ id: e.node.from?.id, name: e.node.from?.name, pattern: e.node.from?.pattern, observableType: e.node.from?.x_opencti_main_observable_type || null, score: e.node.from?.x_opencti_score || null, created: e.node.from?.created })).filter((i: any) => i.id) || [],
        relatedVulnerabilities: is.relatedVulnerabilities?.edges?.map((e: any) => ({ id: e.node.to?.id, name: e.node.to?.name, description: e.node.to?.description })).filter((v: any) => v.id) || [],
      };

      return new Response(JSON.stringify({ data: detail }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // ============ MALWARE ============
    if (queryType === 'malware') {
      // Use native OpenCTI search parameter for full-text search
      const graphqlQuery = {
        query: `query MalwarePaginationQuery($count: Int!, $cursor: ID, $orderBy: MalwaresOrdering, $orderMode: OrderingMode, $search: String) {
          malwares(first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode, search: $search) {
            edges {
              node {
                id
                name
                description
                aliases
                created
                modified
                first_seen
                last_seen
                malware_types
                is_family
                objectLabel {
                  id
                  value
                  color
                }
              }
              cursor
            }
            pageInfo {
              endCursor
              hasNextPage
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          cursor: cursor || null,
          orderMode: "desc",
          orderBy: "modified",
          search: search || null
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI malware response, count:', data.data?.malwares?.edges?.length);

      if (data.errors) {
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      const transformedData = data.data.malwares.edges.map((edge: any) => {
        const node = edge.node;
        return {
          id: node.id,
          name: node.name,
          description: node.description || '',
          aliases: node.aliases || [],
          created: node.created || '',
          modified: node.modified || '',
          firstSeen: node.first_seen || null,
          lastSeen: node.last_seen || null,
          malwareTypes: node.malware_types || [],
          isFamily: node.is_family || false,
          labels: node.objectLabel?.map((l: any) => ({ value: l.value, color: l.color })) || [],
        };
      });

      return new Response(JSON.stringify({ 
        data: transformedData,
        pageInfo: data.data.malwares.pageInfo
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    if (queryType === 'malware-detail') {
      if (!id) throw new Error('Malware ID is required');

      const graphqlQuery = {
        query: `query MalwareDetail($id: String!) {
          malware(id: $id) {
            id
            name
            description
            aliases
            created
            modified
            first_seen
            last_seen
            malware_types
            is_family
            capabilities
            architecture_execution_envs
            objectLabel { value color }
            externalReferences {
              edges { node { id source_name url } }
            }
            usedByIntrusionSets: stixCoreRelationships(relationship_type: "uses", fromTypes: ["Intrusion-Set"], first: 20) {
              edges { node { from { __typename ... on IntrusionSet { id name } } } }
            }
            usedAttackPatterns: stixCoreRelationships(relationship_type: "uses", toTypes: ["Attack-Pattern"], first: 30) {
              edges { node { to { __typename ... on AttackPattern { id name description x_mitre_id killChainPhases { phase_name x_opencti_order } coursesOfAction { edges { node { id name description x_mitre_id } } } } } } }
            }
            relatedIndicators: stixCoreRelationships(relationship_type: "indicates", fromTypes: ["Indicator"], first: 20) {
              edges { node { from { __typename ... on Indicator { id name pattern x_opencti_main_observable_type created } } } }
            }
            relatedVulnerabilities: stixCoreRelationships(relationship_type: "exploits", toTypes: ["Vulnerability"], first: 20) {
              edges { node { to { __typename ... on Vulnerability { id name description } } } }
            }
            reports { edges { node { id name published } } }
            campaigns: stixCoreRelationships(relationship_type: "uses", fromTypes: ["Campaign"], first: 20) {
              edges { node { from { __typename ... on Campaign { id name } } } }
            }
          }
        }`,
        variables: { id }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      if (data.errors) throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);

      const m = data.data.malware;
      const detail = {
        id: m.id,
        name: m.name,
        description: m.description || '',
        aliases: m.aliases || [],
        created: m.created || '',
        modified: m.modified || '',
        firstSeen: m.first_seen || null,
        lastSeen: m.last_seen || null,
        malwareTypes: m.malware_types || [],
        isFamily: m.is_family || false,
        capabilities: m.capabilities || [],
        architectures: m.architecture_execution_envs || [],
        operatingSystems: [],
        labels: m.objectLabel?.map((l: any) => ({ value: l.value, color: l.color })) || [],
        usedByIntrusionSets: m.usedByIntrusionSets?.edges?.map((e: any) => ({ id: e.node.from?.id, name: e.node.from?.name })).filter((i: any) => i.id) || [],
        usedAttackPatterns: m.usedAttackPatterns?.edges?.map((e: any) => ({ id: e.node.to?.id, name: e.node.to?.name, description: e.node.to?.description || '', mitreId: e.node.to?.x_mitre_id, killChainPhases: e.node.to?.killChainPhases?.map((k: any) => ({ phaseName: k.phase_name, order: k.x_opencti_order || 0 })) || [] })).filter((a: any) => a.id) || [],
        mitigatingActions: m.usedAttackPatterns?.edges?.flatMap((e: any) => 
          (e.node.to?.coursesOfAction?.edges || []).map((coaEdge: any) => ({
            id: coaEdge.node.id,
            mitreId: coaEdge.node.x_mitre_id || e.node.to?.x_mitre_id || '',
            attackPatternName: e.node.to?.name || '',
            name: coaEdge.node.name,
            description: coaEdge.node.description || ''
          }))
        ).filter((c: any) => c.id) || [],
        externalReferences: m.externalReferences?.edges?.map((e: any) => ({ id: e.node.id, sourceName: e.node.source_name, url: e.node.url })) || [],
        relatedReports: m.reports?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name, date: e.node.published?.split('T')[0] || '' })) || [],
        relatedCampaigns: m.campaigns?.edges?.map((e: any) => ({ id: e.node.from?.id, name: e.node.from?.name })).filter((c: any) => c.id) || [],
        relatedIndicators: m.relatedIndicators?.edges?.map((e: any) => ({ id: e.node.from?.id, name: e.node.from?.name, pattern: e.node.from?.pattern, observableType: e.node.from?.x_opencti_main_observable_type, created: e.node.from?.created })).filter((i: any) => i.id) || [],
        relatedVulnerabilities: m.relatedVulnerabilities?.edges?.map((e: any) => ({ id: e.node.to?.id, name: e.node.to?.name, description: e.node.to?.description })).filter((v: any) => v.id) || [],
      };

      return new Response(JSON.stringify({ data: detail }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // ============ INDICATORS ============
    if (queryType === 'indicators') {
      // Build date filter groups for indicators
      const dateFilterGroups: any[] = [];

      if (published_start || published_end) {
        const dateFilters: any[] = [];

        if (published_start) {
          dateFilters.push({
            key: "created",
            operator: "gte",
            values: [published_start],
            mode: "or"
          });
        }

        if (published_end) {
          dateFilters.push({
            key: "created",
            operator: "lte",
            values: [published_end],
            mode: "or"
          });
        }

        if (dateFilters.length > 0) {
          dateFilterGroups.push({
            mode: "and",
            filters: dateFilters,
            filterGroups: []
          });
        }
      }

      // Build filters object
      const filters = {
        mode: "and",
        filters: [],
        filterGroups: dateFilterGroups
      };

      const graphqlQuery = {
        query: `query IndicatorsPaginationQuery($count: Int!, $cursor: ID, $orderBy: IndicatorsOrdering, $orderMode: OrderingMode, $search: String, $filters: FilterGroup) {
          indicators(first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode, search: $search, filters: $filters) {
            edges {
              node {
                id
                name
                description
                pattern
                pattern_type
                valid_from
                valid_until
                x_opencti_score
                x_opencti_main_observable_type
                created
                modified
                objectLabel {
                  id
                  value
                  color
                }
              }
              cursor
            }
            pageInfo {
              endCursor
              hasNextPage
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          cursor: cursor || null,
          orderMode: "desc",
          orderBy: "created",
          search: search || null,
          filters: (dateFilterGroups.length > 0) ? filters : null
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI indicators response, count:', data.data?.indicators?.edges?.length);

      if (data.errors) {
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      const transformedData = data.data.indicators.edges.map((edge: any) => {
        const node = edge.node;
        return {
          id: node.id,
          name: node.name || node.pattern?.substring(0, 50) + '...',
          description: node.description || '',
          pattern: node.pattern || '',
          patternType: node.pattern_type || '',
          validFrom: node.valid_from || null,
          validUntil: node.valid_until || null,
          score: node.x_opencti_score || null,
          observableType: node.x_opencti_main_observable_type || null,
          created: node.created || '',
          modified: node.modified || '',
          labels: node.objectLabel?.map((l: any) => ({ value: l.value, color: l.color })) || [],
        };
      });

      return new Response(JSON.stringify({ 
        data: transformedData,
        pageInfo: data.data.indicators.pageInfo
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // ============ TOOLS ============
    if (queryType === 'tools') {
      // Use native OpenCTI search parameter for full-text search
      const graphqlQuery = {
        query: `query ToolsPaginationQuery($count: Int!, $cursor: ID, $orderBy: ToolsOrdering, $orderMode: OrderingMode, $search: String) {
          tools(first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode, search: $search) {
            edges {
              node {
                id
                name
                description
                aliases
                created
                modified
                tool_types
                objectLabel {
                  id
                  value
                  color
                }
              }
              cursor
            }
            pageInfo {
              endCursor
              hasNextPage
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          cursor: cursor || null,
          orderMode: "desc",
          orderBy: "modified",
          search: search || null
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI tools response, count:', data.data?.tools?.edges?.length);

      if (data.errors) {
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      const transformedData = data.data.tools.edges.map((edge: any) => {
        const node = edge.node;
        return {
          id: node.id,
          name: node.name,
          description: node.description || '',
          aliases: node.aliases || [],
          created: node.created || '',
          modified: node.modified || '',
          toolTypes: node.tool_types || [],
          labels: node.objectLabel?.map((l: any) => ({ value: l.value, color: l.color })) || [],
        };
      });

      return new Response(JSON.stringify({ 
        data: transformedData,
        pageInfo: data.data.tools.pageInfo
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // ============ ATTACK PATTERNS ============
    if (queryType === 'attack-patterns') {
      // Use native OpenCTI search parameter for full-text search
      const graphqlQuery = {
        query: `query AttackPatternsPaginationQuery($count: Int!, $cursor: ID, $orderBy: AttackPatternsOrdering, $orderMode: OrderingMode, $search: String) {
          attackPatterns(first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode, search: $search) {
            edges {
              node {
                id
                name
                description
                x_mitre_id
                created
                modified
                x_mitre_platforms
                killChainPhases {
                  id
                  phase_name
                  x_opencti_order
                }
                objectLabel {
                  id
                  value
                  color
                }
              }
              cursor
            }
            pageInfo {
              endCursor
              hasNextPage
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          cursor: cursor || null,
          orderMode: "desc",
          orderBy: "modified",
          search: search || null
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI attack patterns response, count:', data.data?.attackPatterns?.edges?.length);

      if (data.errors) {
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      const transformedData = data.data.attackPatterns.edges.map((edge: any) => {
        const node = edge.node;
        return {
          id: node.id,
          name: node.name,
          description: node.description || '',
          mitreId: node.x_mitre_id || '',
          created: node.created || '',
          modified: node.modified || '',
          platforms: node.x_mitre_platforms || [],
          killChainPhases: node.killChainPhases?.map((k: any) => ({ phaseName: k.phase_name, order: k.x_opencti_order })) || [],
          labels: node.objectLabel?.map((l: any) => ({ value: l.value, color: l.color })) || [],
        };
      });

      return new Response(JSON.stringify({ 
        data: transformedData,
        pageInfo: data.data.attackPatterns.pageInfo
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // ============ COURSES OF ACTION (MITIGATIONS) ============
    if (queryType === 'courses-of-action') {
      // Use native OpenCTI search parameter for full-text search
      const graphqlQuery = {
        query: `query CoursesOfActionPaginationQuery($count: Int!, $cursor: ID, $orderBy: CoursesOfActionOrdering, $orderMode: OrderingMode, $search: String) {
          coursesOfAction(first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode, search: $search) {
            edges {
              node {
                id
                name
                description
                x_mitre_id
                created
                modified
                objectLabel {
                  id
                  value
                  color
                }
                attackPatterns {
                  pageInfo {
                    globalCount
                  }
                }
              }
              cursor
            }
            pageInfo {
              endCursor
              hasNextPage
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          cursor: cursor || null,
          orderMode: "desc",
          orderBy: "modified",
          search: search || null
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openctiToken}`,
        },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`OpenCTI API error: ${response.status} - ${errorText}`);
      }

      const data = await response.json();
      console.log('OpenCTI courses of action response, count:', data.data?.coursesOfAction?.edges?.length);

      if (data.errors) {
        throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);
      }

      const transformedData = data.data.coursesOfAction.edges.map((edge: any) => {
        const node = edge.node;
        return {
          id: node.id,
          name: node.name,
          description: node.description || '',
          mitreId: node.x_mitre_id || '',
          created: node.created || '',
          modified: node.modified || '',
          labels: node.objectLabel?.map((l: any) => ({ value: l.value, color: l.color })) || [],
          mitigatedTTPsCount: node.attackPatterns?.pageInfo?.globalCount || 0,
        };
      });

      return new Response(JSON.stringify({ 
        data: transformedData,
        pageInfo: data.data.coursesOfAction.pageInfo
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // ============ SECTORS ============
    if (queryType === 'sectors') {
      const graphqlQuery = {
        query: `query SectorsPaginationQuery($count: Int!, $cursor: ID, $orderBy: SectorsOrdering, $orderMode: OrderingMode) {
          sectors(first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode) {
            edges {
              node {
                id
                name
                description
              }
            }
            pageInfo {
              hasNextPage
              endCursor
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          cursor: cursor || null,
          orderBy: 'name',
          orderMode: 'asc'
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) throw new Error(`OpenCTI API error: ${response.status}`);
      const data = await response.json();
      if (data.errors) throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);

      const sectors = data.data.sectors.edges.map((edge: any) => ({
        id: edge.node.id,
        name: edge.node.name,
        description: edge.node.description || '',
      }));

      return new Response(JSON.stringify({
        data: sectors,
        pageInfo: {
          hasNextPage: data.data.sectors.pageInfo.hasNextPage,
          endCursor: data.data.sectors.pageInfo.endCursor,
          globalCount: data.data.sectors.pageInfo.globalCount,
        }
      }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // ============ COUNTRIES ============
    if (queryType === 'countries') {
      const graphqlQuery = {
        query: `query CountriesPaginationQuery($count: Int!, $cursor: ID, $orderBy: CountriesOrdering, $orderMode: OrderingMode) {
          countries(first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode) {
            edges {
              node {
                id
                name
                description
                isLocatedAt: stixCoreRelationships(relationship_type: "located-at", toTypes: ["Region"]) {
                  edges { node { to { __typename ... on Region { id name } } } }
                }
              }
            }
            pageInfo {
              hasNextPage
              endCursor
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          cursor: cursor || null,
          orderBy: 'name',
          orderMode: 'asc'
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) throw new Error(`OpenCTI API error: ${response.status}`);
      const data = await response.json();
      if (data.errors) throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);

      const countries = data.data.countries.edges.map((edge: any) => {
        const regionEdge = edge.node.isLocatedAt?.edges?.find((e: any) => e.node.to?.__typename === 'Region');
        return {
          id: edge.node.id,
          name: edge.node.name,
          description: edge.node.description || '',
          region: regionEdge?.node?.to?.name || null,
          regionId: regionEdge?.node?.to?.id || null,
        };
      });

      return new Response(JSON.stringify({
        data: countries,
        pageInfo: {
          hasNextPage: data.data.countries.pageInfo.hasNextPage,
          endCursor: data.data.countries.pageInfo.endCursor,
          globalCount: data.data.countries.pageInfo.globalCount,
        }
      }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // ============ REGIONS ============
    if (queryType === 'regions') {
      const graphqlQuery = {
        query: `query RegionsPaginationQuery($count: Int!, $cursor: ID, $orderBy: RegionsOrdering, $orderMode: OrderingMode) {
          regions(first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode) {
            edges {
              node {
                id
                name
                description
                countries: stixCoreRelationships(relationship_type: "located-at", fromTypes: ["Country"]) {
                  edges { node { from { __typename ... on Country { id name } } } }
                }
              }
            }
            pageInfo {
              hasNextPage
              endCursor
              globalCount
            }
          }
        }`,
        variables: {
          count: limit,
          cursor: cursor || null,
          orderBy: 'name',
          orderMode: 'asc'
        }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) throw new Error(`OpenCTI API error: ${response.status}`);
      const data = await response.json();
      if (data.errors) throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);

      const regions = data.data.regions.edges.map((edge: any) => {
        const countryEdges = edge.node.countries?.edges || [];
        return {
          id: edge.node.id,
          name: edge.node.name,
          description: edge.node.description || '',
          countryCount: countryEdges.filter((e: any) => e.node.from?.__typename === 'Country').length,
        };
      });

      return new Response(JSON.stringify({
        data: regions,
        pageInfo: {
          hasNextPage: data.data.regions.pageInfo.hasNextPage,
          endCursor: data.data.regions.pageInfo.endCursor,
          globalCount: data.data.regions.pageInfo.globalCount,
        }
      }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // ============ REGION DETAIL ============
    if (queryType === 'region-detail') {
      if (!id) throw new Error('Region ID is required');

      const graphqlQuery = {
        query: `query RegionDetail($id: String!) {
          region(id: $id) {
            id
            name
            description
            countries: stixCoreRelationships(relationship_type: "located-at", fromTypes: ["Country"]) {
              edges { node { from { __typename ... on Country { id name } } } }
            }
            stixCoreRelationships(relationship_type: "targets") {
              edges {
                node {
                  from { __typename ... on IntrusionSet { id name } ... on Campaign { id name } }
                }
              }
            }
            reports { edges { node { id name published } } }
          }
        }`,
        variables: { id }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) throw new Error(`OpenCTI API error: ${response.status}`);
      const data = await response.json();
      if (data.errors) throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);

      const r = data.data.region;
      
      if (!r) {
        return new Response(JSON.stringify({ data: null, error: 'Region not found' }), { 
          status: 404,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        });
      }
      
      const countryEdges = r.countries?.edges || [];
      const rels = r.stixCoreRelationships?.edges || [];
      
      return new Response(JSON.stringify({ data: {
        id: r.id,
        name: r.name,
        description: r.description || '',
        countries: countryEdges
          .filter((e: any) => e.node.from?.__typename === 'Country')
          .map((e: any) => ({ id: e.node.from.id, name: e.node.from.name }))
          .sort((a: any, b: any) => a.name.localeCompare(b.name)),
        targetedByIntrusionSets: rels.filter((rel: any) => rel.node.from?.__typename === 'IntrusionSet').map((rel: any) => ({ id: rel.node.from.id, name: rel.node.from.name })),
        relatedCampaigns: rels.filter((rel: any) => rel.node.from?.__typename === 'Campaign').map((rel: any) => ({ id: rel.node.from.id, name: rel.node.from.name })),
        relatedReports: r.reports?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name, date: e.node.published?.split('T')[0] || '' })) || [],
      }}), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // ============ COUNTRY DETAIL ============
    if (queryType === 'country-detail') {
      if (!id) throw new Error('Country ID is required');

      const graphqlQuery = {
        query: `query CountryDetail($id: String!) {
          country(id: $id) {
            id
            name
            description
            x_opencti_aliases
            created
            modified
            objectLabel { value color }
            reports(first: 50) { edges { node { id name published report_types } } }
          }
          intrusionSets(
            first: 50
            filters: {
              mode: and
              filters: [{ key: "targets", values: ["${id}"] }]
              filterGroups: []
            }
          ) {
            edges { node { id name } }
          }
          campaigns(
            first: 50
            filters: {
              mode: and
              filters: [{ key: "targets", values: ["${id}"] }]
              filterGroups: []
            }
          ) {
            edges { node { id name } }
          }
        }`,
        variables: { id }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) throw new Error(`OpenCTI API error: ${response.status}`);
      const data = await response.json();
      console.log('Country detail response:', JSON.stringify(data, null, 2));
      if (data.errors) throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);

      const c = data.data.country;
      
      if (!c) {
        return new Response(JSON.stringify({ data: null, error: 'Country not found' }), { 
          status: 404,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        });
      }
      
      return new Response(JSON.stringify({ data: {
        id: c.id,
        name: c.name,
        description: c.description || '',
        region: c.x_opencti_aliases?.[0] || null,
        created: c.created || '',
        modified: c.modified || '',
        labels: c.objectLabel?.map((l: any) => ({ value: l.value, color: l.color })) || [],
        targetedByIntrusionSets: data.data.intrusionSets?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name })) || [],
        relatedCampaigns: data.data.campaigns?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name })) || [],
        relatedReports: c.reports?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name, date: e.node.published?.split('T')[0] || '' })) || [],
      }}), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // ============ SECTOR DETAIL ============
    if (queryType === 'sector-detail') {
      if (!id) throw new Error('Sector ID is required');

      const graphqlQuery = {
        query: `query SectorDetail($id: String!) {
          sector(id: $id) {
            id
            name
            description
            created
            modified
            objectLabel { value color }
            reports(first: 50) { edges { node { id name published report_types } } }
          }
          intrusionSets(
            first: 50
            filters: {
              mode: and
              filters: [{ key: "targets", values: ["${id}"] }]
              filterGroups: []
            }
          ) {
            edges { node { id name } }
          }
          campaigns(
            first: 50
            filters: {
              mode: and
              filters: [{ key: "targets", values: ["${id}"] }]
              filterGroups: []
            }
          ) {
            edges { node { id name } }
          }
        }`,
        variables: { id }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) throw new Error(`OpenCTI API error: ${response.status}`);
      const data = await response.json();
      console.log('Sector detail response:', JSON.stringify(data, null, 2));
      if (data.errors) throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);

      const s = data.data.sector;
      
      if (!s) {
        return new Response(JSON.stringify({ data: null, error: 'Sector not found' }), { 
          status: 404,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        });
      }
      
      return new Response(JSON.stringify({ data: {
        id: s.id,
        name: s.name,
        description: s.description || '',
        created: s.created || '',
        modified: s.modified || '',
        labels: s.objectLabel?.map((l: any) => ({ value: l.value, color: l.color })) || [],
        targetedByIntrusionSets: data.data.intrusionSets?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name })) || [],
        relatedCampaigns: data.data.campaigns?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name })) || [],
        relatedReports: s.reports?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name, date: e.node.published?.split('T')[0] || '' })) || [],
      }}), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // ============ ATTACK PATTERN DETAIL ============
    if (queryType === 'attack-pattern-detail') {
      if (!id) throw new Error('Attack Pattern ID is required');

      const graphqlQuery = {
        query: `query AttackPatternDetail($id: String!) {
          attackPattern(id: $id) {
            id
            name
            description
            x_mitre_id
            x_mitre_platforms
            x_mitre_detection
            created
            modified
            killChainPhases { phase_name x_opencti_order }
            objectLabel { value color }
            coursesOfAction { edges { node { id name description x_mitre_id } } }
            usedByIntrusionSets: stixCoreRelationships(relationship_type: "uses", fromTypes: ["Intrusion-Set"]) {
              edges { node { from { ... on IntrusionSet { id name } } } }
            }
            usedByMalware: stixCoreRelationships(relationship_type: "uses", fromTypes: ["Malware"]) {
              edges { node { from { ... on Malware { id name } } } }
            }
            usedByCampaigns: stixCoreRelationships(relationship_type: "uses", fromTypes: ["Campaign"]) {
              edges { node { from { ... on Campaign { id name } } } }
            }
            relatedTools: stixCoreRelationships(relationship_type: "uses", toTypes: ["Tool"]) {
              edges { node { to { ... on Tool { id name } } } }
            }
            externalReferences { edges { node { id source_name url } } }
          }
        }`,
        variables: { id }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) throw new Error(`OpenCTI API error: ${response.status}`);
      const data = await response.json();
      if (data.errors) throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);

      const ap = data.data.attackPattern;
      
      const mitigatingActions = ap.coursesOfAction?.edges?.map((e: any) => ({
        id: e.node.id,
        mitreId: e.node.x_mitre_id || ap.x_mitre_id || '',
        attackPatternName: ap.name,
        name: e.node.name,
        description: e.node.description || ''
      })).filter((c: any) => c.id) || [];
      
      return new Response(JSON.stringify({ data: {
        id: ap.id,
        name: ap.name,
        description: ap.description || '',
        mitreId: ap.x_mitre_id || null,
        platforms: ap.x_mitre_platforms || [],
        detectionMethods: ap.x_mitre_detection || null,
        created: ap.created || '',
        modified: ap.modified || '',
        killChainPhases: ap.killChainPhases?.map((k: any) => ({ phaseName: k.phase_name, order: k.x_opencti_order })) || [],
        labels: ap.objectLabel?.map((l: any) => ({ value: l.value, color: l.color })) || [],
        usedByIntrusionSets: ap.usedByIntrusionSets?.edges?.map((e: any) => ({ id: e.node.from?.id, name: e.node.from?.name })).filter((i: any) => i.id) || [],
        usedByMalware: ap.usedByMalware?.edges?.map((e: any) => ({ id: e.node.from?.id, name: e.node.from?.name })).filter((i: any) => i.id) || [],
        usedByCampaigns: ap.usedByCampaigns?.edges?.map((e: any) => ({ id: e.node.from?.id, name: e.node.from?.name })).filter((i: any) => i.id) || [],
        relatedTools: ap.relatedTools?.edges?.map((e: any) => ({ id: e.node.to?.id, name: e.node.to?.name })).filter((i: any) => i.id) || [],
        mitigatingActions,
        externalReferences: ap.externalReferences?.edges?.map((e: any) => ({ id: e.node.id, sourceName: e.node.source_name, url: e.node.url })) || [],
      }}), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // ============ COURSE OF ACTION DETAIL ============
    if (queryType === 'course-of-action-detail') {
      if (!id) throw new Error('Course of Action ID is required');

      const graphqlQuery = {
        query: `query CourseOfActionDetail($id: String!) {
          courseOfAction(id: $id) {
            id
            name
            description
            x_mitre_id
            created
            modified
            attackPatterns: stixCoreRelationships(relationship_type: "mitigates", toTypes: ["Attack-Pattern"], first: 50) {
              edges { node { to { ... on AttackPattern { id name description x_mitre_id killChainPhases { phase_name x_opencti_order } } } } }
            }
            externalReferences { edges { node { id source_name url } } }
          }
        }`,
        variables: { id }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) throw new Error(`OpenCTI API error: ${response.status}`);
      const data = await response.json();
      if (data.errors) throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);

      const coa = data.data.courseOfAction;
      
      const mitigatedAttackPatterns = coa.attackPatterns?.edges?.map((e: any) => ({
        id: e.node.to?.id,
        name: e.node.to?.name,
        description: e.node.to?.description || '',
        mitreId: e.node.to?.x_mitre_id,
        killChainPhases: e.node.to?.killChainPhases?.map((k: any) => ({ phaseName: k.phase_name, order: k.x_opencti_order })) || []
      })).filter((ap: any) => ap.id) || [];
      
      return new Response(JSON.stringify({ data: {
        id: coa.id,
        name: coa.name,
        description: coa.description || '',
        mitreId: coa.x_mitre_id || null,
        created: coa.created || '',
        modified: coa.modified || '',
        mitigatedAttackPatterns,
        externalReferences: coa.externalReferences?.edges?.map((e: any) => ({ id: e.node.id, sourceName: e.node.source_name, url: e.node.url })) || [],
      }}), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // ============ TOOL DETAIL ============
    if (queryType === 'tool-detail') {
      if (!id) throw new Error('Tool ID is required');

      const graphqlQuery = {
        query: `query ToolDetail($id: String!) {
          tool(id: $id) {
            id
            name
            description
            aliases
            created
            modified
            tool_types
            objectLabel { value color }
            usedByIntrusionSets: stixCoreRelationships(relationship_type: "uses", fromTypes: ["Intrusion-Set"]) {
              edges { node { from { ... on IntrusionSet { id name } } } }
            }
            usedInCampaigns: stixCoreRelationships(relationship_type: "uses", fromTypes: ["Campaign"]) {
              edges { node { from { ... on Campaign { id name } } } }
            }
            externalReferences { edges { node { id source_name url } } }
          }
        }`,
        variables: { id }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) throw new Error(`OpenCTI API error: ${response.status}`);
      const data = await response.json();
      if (data.errors) throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);

      const t = data.data.tool;
      
      return new Response(JSON.stringify({ data: {
        id: t.id,
        name: t.name,
        description: t.description || '',
        aliases: t.aliases || [],
        created: t.created || '',
        modified: t.modified || '',
        toolTypes: t.tool_types || [],
        labels: t.objectLabel?.map((l: any) => ({ value: l.value, color: l.color })) || [],
        usedByIntrusionSets: t.usedByIntrusionSets?.edges?.map((e: any) => ({ id: e.node.from?.id, name: e.node.from?.name })).filter((i: any) => i.id) || [],
        usedInCampaigns: t.usedInCampaigns?.edges?.map((e: any) => ({ id: e.node.from?.id, name: e.node.from?.name })).filter((i: any) => i.id) || [],
        externalReferences: t.externalReferences?.edges?.map((e: any) => ({ id: e.node.id, sourceName: e.node.source_name, url: e.node.url })) || [],
      }}), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // ============ INDICATOR DETAIL ============
    if (queryType === 'indicator-detail') {
      if (!id) throw new Error('Indicator ID is required');

      const graphqlQuery = {
        query: `query IndicatorDetail($id: String!) {
          indicator(id: $id) {
            id
            name
            description
            pattern
            pattern_type
            valid_from
            valid_until
            x_opencti_score
            created
            modified
            objectLabel { value color }
            observables { edges { node { id entity_type observable_value } } }
            reports { edges { node { id name published } } }
            externalReferences { edges { node { id source_name url } } }
            stixCoreRelationships(relationship_type: "indicates") {
              edges {
                node {
                  to {
                    __typename
                    ... on IntrusionSet {
                      id
                      name
                    }
                    ... on Malware {
                      id
                      name
                    }
                    ... on Campaign {
                      id
                      name
                    }
                    ... on AttackPattern {
                      id
                      name
                      x_mitre_id
                    }
                  }
                }
              }
            }
          }
        }`,
        variables: { id }
      };

      const response = await fetch(openctiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
        body: JSON.stringify(graphqlQuery),
      });

      if (!response.ok) throw new Error(`OpenCTI API error: ${response.status}`);
      const data = await response.json();
      if (data.errors) throw new Error(`GraphQL errors: ${JSON.stringify(data.errors)}`);

      const ind = data.data.indicator;
      
      // Extract relationships from stixCoreRelationships
      const relationships = ind.stixCoreRelationships?.edges || [];
      const relatedIntrusionSets: any[] = [];
      const relatedMalware: any[] = [];
      const relatedCampaigns: any[] = [];
      const relatedAttackPatterns: any[] = [];
      
      relationships.forEach((edge: any) => {
        const toNode = edge.node?.to;
        if (!toNode || !toNode.id) return;
        
        const typename = toNode.__typename;
        if (typename === 'IntrusionSet') {
          relatedIntrusionSets.push({ id: toNode.id, name: toNode.name });
        } else if (typename === 'Malware') {
          relatedMalware.push({ id: toNode.id, name: toNode.name });
        } else if (typename === 'Campaign') {
          relatedCampaigns.push({ id: toNode.id, name: toNode.name });
        } else if (typename === 'AttackPattern') {
          relatedAttackPatterns.push({ id: toNode.id, name: toNode.name, mitreId: toNode.x_mitre_id });
        }
      });
      
      console.log('Indicator relationships found:', {
        intrusionSets: relatedIntrusionSets.length,
        malware: relatedMalware.length,
        campaigns: relatedCampaigns.length,
        attackPatterns: relatedAttackPatterns.length
      });
      
      return new Response(JSON.stringify({ data: {
        id: ind.id,
        name: ind.name || ind.pattern?.substring(0, 50) + '...',
        description: ind.description || '',
        pattern: ind.pattern || '',
        patternType: ind.pattern_type || '',
        validFrom: ind.valid_from || null,
        validUntil: ind.valid_until || null,
        score: ind.x_opencti_score || null,
        created: ind.created || '',
        modified: ind.modified || '',
        labels: ind.objectLabel?.map((l: any) => ({ value: l.value, color: l.color })) || [],
        relatedObservables: ind.observables?.edges?.map((e: any) => ({ id: e.node.id, type: e.node.entity_type, value: e.node.observable_value })) || [],
        relatedReports: ind.reports?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name, published: e.node.published })) || [],
        externalReferences: ind.externalReferences?.edges?.map((e: any) => ({ id: e.node.id, sourceName: e.node.source_name, url: e.node.url })) || [],
        relatedIntrusionSets,
        relatedMalware,
        relatedCampaigns,
        relatedAttackPatterns,
      }}), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    if (queryType === 'activity-ticker') {
      // Fetch recent items from multiple entity types for the activity ticker (2 from each for 10 total)
      const queries = [
        // Recent reports (non-ransomware)
        fetch(openctiUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
          body: JSON.stringify({
            query: `query { reports(first: 2, orderBy: created_at, orderMode: desc, filters: { mode: "and", filters: [{ key: "createdBy", operator: "not_eq", values: ["${RANSOMWARE_BOT_ID}"], mode: "or" }], filterGroups: [] }) { edges { node { id name created_at } } } }`
          })
        }),
        // Recent campaigns
        fetch(openctiUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
          body: JSON.stringify({
            query: `query { campaigns(first: 2, orderBy: modified, orderMode: desc) { edges { node { id name modified } } } }`
          })
        }),
        // Recent vulnerabilities
        fetch(openctiUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
          body: JSON.stringify({
            query: `query { vulnerabilities(first: 2, orderBy: modified, orderMode: desc) { edges { node { id name modified } } } }`
          })
        }),
        // Recent indicators
        fetch(openctiUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
          body: JSON.stringify({
            query: `query { indicators(first: 2, orderBy: created, orderMode: desc) { edges { node { id name pattern created } } } }`
          })
        }),
        // Recent intrusion sets
        fetch(openctiUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
          body: JSON.stringify({
            query: `query { intrusionSets(first: 1, orderBy: modified, orderMode: desc) { edges { node { id name modified } } } }`
          })
        }),
        // Recent malware
        fetch(openctiUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openctiToken}` },
          body: JSON.stringify({
            query: `query { malwares(first: 1, orderBy: modified, orderMode: desc) { edges { node { id name modified } } } }`
          })
        }),
      ];

      const responses = await Promise.all(queries);
      const results = await Promise.all(responses.map(r => r.json()));

      return new Response(JSON.stringify({
        reports: results[0].data?.reports?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name, date: e.node.created_at })) || [],
        campaigns: results[1].data?.campaigns?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name, date: e.node.modified })) || [],
        vulnerabilities: results[2].data?.vulnerabilities?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name, date: e.node.modified })) || [],
        indicators: results[3].data?.indicators?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name, pattern: e.node.pattern, date: e.node.created })) || [],
        intrusionSets: results[4].data?.intrusionSets?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name, date: e.node.modified })) || [],
        malware: results[5].data?.malwares?.edges?.map((e: any) => ({ id: e.node.id, name: e.node.name, date: e.node.modified })) || [],
      }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    throw new Error(`Unknown queryType: ${queryType}`);

  } catch (error) {
    console.error('Error in kb:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    const errorDetails = error instanceof Error ? error.toString() : String(error);
    
    return new Response(
      JSON.stringify({ 
        error: errorMessage,
        details: errorDetails
      }), 
      {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  }
});
