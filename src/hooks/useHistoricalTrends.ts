import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "./useAuth";
import { subDays, format, eachDayOfInterval } from "date-fns";

export type TrendPeriod = "7d" | "30d" | "90d" | "6m" | "1y";

interface DailyActivity {
  date: string;
  ransomware: number;
  vulnerabilities: number;
  reports: number;
  advisories: number;
  media: number;
}

interface ThreatActorTrend {
  name: string;
  data: { date: string; count: number }[];
  total: number;
}

interface VulnerabilitySeverityTrend {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface HistoricalTrendsData {
  dailyActivity: DailyActivity[];
  threatActorTrends: ThreatActorTrend[];
  vulnerabilitySeverityTrends: VulnerabilitySeverityTrend[];
  summary: {
    totalRansomware: number;
    totalVulnerabilities: number;
    totalReports: number;
    totalAdvisories: number;
    totalMedia: number;
    avgDailyRansomware: number;
    avgDailyVulnerabilities: number;
    peakDay: string;
    peakCount: number;
  };
}

const getPeriodDays = (period: TrendPeriod): number => {
  switch (period) {
    case "7d": return 7;
    case "30d": return 30;
    case "90d": return 90;
    case "6m": return 180;
    case "1y": return 365;
    default: return 30;
  }
};

// Cast supabase to any to bypass strict type checking for intel schema
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const intelDb = (supabase as any).schema('intel');

// Helper function to get CVSS severity from base score
const getSeverityFromScore = (score: number | null): string => {
  if (score === null) return 'Unknown';
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score >= 0.1) return 'Low';
  return 'Unknown';
};

export const useHistoricalTrends = (period: TrendPeriod = "30d") => {
  const { session } = useAuth();
  const periodDays = getPeriodDays(period);
  const now = new Date();
  const startDate = subDays(now, periodDays);

  return useQuery({
    queryKey: ["historical-trends", period],
    queryFn: async (): Promise<HistoricalTrendsData> => {
      const startDateStr = startDate.toISOString();
      const nowStr = now.toISOString();

      // Generate all dates in the range
      const dateRange = eachDayOfInterval({ start: startDate, end: now });
      const dateMap = new Map<string, DailyActivity>();
      dateRange.forEach((date) => {
        const key = format(date, 'yyyy-MM-dd');
        dateMap.set(key, {
          date: key,
          ransomware: 0,
          vulnerabilities: 0,
          reports: 0,
          advisories: 0,
          media: 0,
        });
      });

      // Fetch all data in parallel
      const [
        ransomwareResult,
        vulnResult,
        reportsResult,
        mediaResult,
        advisoriesResult,
      ] = await Promise.all([
        // Ransomware victims
        intelDb
          .from('object_current')
          .select('internal_id, name, data, source_created_at')
          .eq('entity_type', 'Report')
          .contains('data', { report_types: ['Ransomware-report'] })
          .gte('source_created_at', startDateStr)
          .lte('source_created_at', nowStr),
        // Vulnerabilities
        intelDb
          .from('object_current')
          .select('internal_id, name, data, source_created_at')
          .eq('entity_type', 'Vulnerability')
          .gte('source_created_at', startDateStr)
          .lte('source_created_at', nowStr),
        // Threat reports
        intelDb
          .from('object_current')
          .select('internal_id, name, data, source_created_at')
          .eq('entity_type', 'Report')
          .contains('data', { report_types: ['threat-report'] })
          .gte('source_created_at', startDateStr)
          .lte('source_created_at', nowStr),
        // Media reports
        intelDb
          .from('object_current')
          .select('internal_id, name, data, source_created_at')
          .eq('entity_type', 'Report')
          .contains('data', { report_types: ['media-report'] })
          .gte('source_created_at', startDateStr)
          .lte('source_created_at', nowStr),
        // Advisories
        intelDb
          .from('object_current')
          .select('internal_id, name, data, source_created_at')
          .eq('entity_type', 'Report')
          .contains('data', { report_types: ['threat-advisory'] })
          .gte('source_created_at', startDateStr)
          .lte('source_created_at', nowStr),
      ]);

      const ransomwareData = ransomwareResult.data || [];
      const vulnData = vulnResult.data || [];
      const reportsData = reportsResult.data || [];
      const mediaData = mediaResult.data || [];
      const advisoriesData = advisoriesResult.data || [];

      // Count daily activity
      ransomwareData.forEach((item: any) => {
        const date = format(new Date(item.source_created_at), 'yyyy-MM-dd');
        if (dateMap.has(date)) {
          dateMap.get(date)!.ransomware++;
        }
      });

      vulnData.forEach((item: any) => {
        const date = format(new Date(item.source_created_at), 'yyyy-MM-dd');
        if (dateMap.has(date)) {
          dateMap.get(date)!.vulnerabilities++;
        }
      });

      reportsData.forEach((item: any) => {
        const date = format(new Date(item.source_created_at), 'yyyy-MM-dd');
        if (dateMap.has(date)) {
          dateMap.get(date)!.reports++;
        }
      });

      mediaData.forEach((item: any) => {
        const date = format(new Date(item.source_created_at), 'yyyy-MM-dd');
        if (dateMap.has(date)) {
          dateMap.get(date)!.media++;
        }
      });

      advisoriesData.forEach((item: any) => {
        const date = format(new Date(item.source_created_at), 'yyyy-MM-dd');
        if (dateMap.has(date)) {
          dateMap.get(date)!.advisories++;
        }
      });

      const dailyActivity = Array.from(dateMap.values());

      // Calculate vulnerability severity trends
      const severityMap = new Map<string, VulnerabilitySeverityTrend>();
      dateRange.forEach((date) => {
        const key = format(date, 'yyyy-MM-dd');
        severityMap.set(key, {
          date: key,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
        });
      });

      vulnData.forEach((item: any) => {
        const date = format(new Date(item.source_created_at), 'yyyy-MM-dd');
        if (severityMap.has(date)) {
          const data = item.data || {};
          const severity = data.x_opencti_cvss_base_severity ||
                          getSeverityFromScore(data.x_opencti_cvss_base_score);
          const entry = severityMap.get(date)!;
          switch (severity.toLowerCase()) {
            case 'critical':
              entry.critical++;
              break;
            case 'high':
              entry.high++;
              break;
            case 'medium':
              entry.medium++;
              break;
            case 'low':
              entry.low++;
              break;
          }
        }
      });

      const vulnerabilitySeverityTrends = Array.from(severityMap.values());

      // Extract threat actor trends from ransomware reports
      const threatActorCounts: Record<string, { dates: Record<string, number>; total: number }> = {};

      ransomwareData.forEach((item: any) => {
        const name = item.name || '';
        const date = format(new Date(item.source_created_at), 'yyyy-MM-dd');

        // Extract group name from "groupname has published a new victim:" pattern
        const victimMatch = name.match(/^(.+?)\s+has published a new victim:/i);
        if (victimMatch) {
          const groupName = victimMatch[1].trim();
          if (groupName && groupName.length < 50) {
            if (!threatActorCounts[groupName]) {
              threatActorCounts[groupName] = { dates: {}, total: 0 };
            }
            threatActorCounts[groupName].dates[date] = (threatActorCounts[groupName].dates[date] || 0) + 1;
            threatActorCounts[groupName].total++;
          }
        }
      });

      // Get top 5 threat actors by volume
      const threatActorTrends: ThreatActorTrend[] = Object.entries(threatActorCounts)
        .sort((a, b) => b[1].total - a[1].total)
        .slice(0, 5)
        .map(([name, { dates, total }]) => ({
          name,
          total,
          data: dateRange.map((date) => ({
            date: format(date, 'yyyy-MM-dd'),
            count: dates[format(date, 'yyyy-MM-dd')] || 0,
          })),
        }));

      // Calculate summary
      const totalRansomware = ransomwareData.length;
      const totalVulnerabilities = vulnData.length;
      const totalReports = reportsData.length;
      const totalAdvisories = advisoriesData.length;
      const totalMedia = mediaData.length;

      // Find peak day
      let peakDay = '';
      let peakCount = 0;
      dailyActivity.forEach((day) => {
        const total = day.ransomware + day.vulnerabilities + day.reports + day.advisories + day.media;
        if (total > peakCount) {
          peakCount = total;
          peakDay = day.date;
        }
      });

      return {
        dailyActivity,
        threatActorTrends,
        vulnerabilitySeverityTrends,
        summary: {
          totalRansomware,
          totalVulnerabilities,
          totalReports,
          totalAdvisories,
          totalMedia,
          avgDailyRansomware: Math.round(totalRansomware / periodDays * 10) / 10,
          avgDailyVulnerabilities: Math.round(totalVulnerabilities / periodDays * 10) / 10,
          peakDay,
          peakCount,
        },
      };
    },
    enabled: !!session,
    staleTime: 10 * 60 * 1000, // 10 minutes
    refetchOnWindowFocus: false,
  });
};
