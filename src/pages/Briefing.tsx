import { AppLayout } from "@/components/layout/AppLayout";
import { useIntelSummaries } from "@/hooks/useIntelSummaries";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  FileText,
  Calendar,
  AlertTriangle,
  Shield,
  Target,
  Bug,
  Users,
  Skull,
  CheckCircle2,
  TrendingUp,
} from "lucide-react";
import { format } from "date-fns";
import type { IntelSummary } from "@/hooks/useIntelSummaries";

// Confidence badge component
function ConfidenceBadge({ level }: { level?: string }) {
  if (!level) return null;
  const colors = {
    HIGH: "bg-green-500/20 text-green-400 border-green-500/30",
    MODERATE: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    LOW: "bg-red-500/20 text-red-400 border-red-500/30",
  };
  return (
    <Badge
      variant="outline"
      className={colors[level as keyof typeof colors] || colors.MODERATE}
    >
      {level} Confidence
    </Badge>
  );
}

// Section component for consistent styling
function BriefingSection({
  title,
  icon: Icon,
  iconColor,
  confidence,
  children,
}: {
  title: string;
  icon: typeof AlertTriangle;
  iconColor: string;
  confidence?: string;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-8 h-8 rounded-lg ${iconColor} flex items-center justify-center`}>
              <Icon className="w-4 h-4 text-white" />
            </div>
            <CardTitle className="text-lg">{title}</CardTitle>
          </div>
          <ConfidenceBadge level={confidence} />
        </div>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

// Executive Summary Section
function ExecutiveSummary({ summary }: { summary: IntelSummary }) {
  return (
    <BriefingSection
      title="Executive Summary"
      icon={FileText}
      iconColor="bg-blue-500"
    >
      <p className="text-muted-foreground leading-relaxed">
        {summary.executive_summary || "No executive summary available."}
      </p>
    </BriefingSection>
  );
}

// Key Takeaways Section
function KeyTakeaways({ summary }: { summary: IntelSummary }) {
  const takeaways = summary.key_takeaways || [];
  return (
    <BriefingSection
      title="Key Takeaways"
      icon={CheckCircle2}
      iconColor="bg-amber-500"
    >
      {takeaways.length > 0 ? (
        <ol className="space-y-3">
          {takeaways.map((item, i) => (
            <li key={i} className="flex gap-3">
              <span className="flex-shrink-0 w-6 h-6 rounded-full bg-amber-500/20 text-amber-400 flex items-center justify-center text-sm font-medium">
                {i + 1}
              </span>
              <span className="text-sm text-muted-foreground">{item}</span>
            </li>
          ))}
        </ol>
      ) : (
        <p className="text-sm text-muted-foreground">No key takeaways available.</p>
      )}
    </BriefingSection>
  );
}

// Threat Landscape Section
function ThreatLandscape({ summary }: { summary: IntelSummary }) {
  const landscape = summary.threat_landscape;
  if (!landscape) return null;

  return (
    <BriefingSection
      title="Threat Landscape"
      icon={Shield}
      iconColor="bg-blue-600"
      confidence={landscape.confidence}
    >
      <div className="space-y-4">
        {landscape.bluf && (
          <div className="p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
            <p className="text-sm font-medium text-blue-400">Bottom Line Up Front</p>
            <p className="text-sm text-muted-foreground mt-1">{landscape.bluf}</p>
          </div>
        )}
        <p className="text-sm text-muted-foreground">{landscape.assessment}</p>
        {landscape.key_themes && landscape.key_themes.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {landscape.key_themes.map((theme, i) => (
              <Badge key={i} variant="secondary" className="text-xs">
                {theme}
              </Badge>
            ))}
          </div>
        )}
      </div>
    </BriefingSection>
  );
}

// Actor Analysis Section
function ActorAnalysis({ summary }: { summary: IntelSummary }) {
  const analysis = summary.actor_analysis;
  if (!analysis) return null;

  return (
    <BriefingSection
      title="Threat Actor Activity"
      icon={Users}
      iconColor="bg-purple-500"
      confidence={analysis.confidence}
    >
      <div className="space-y-4">
        {analysis.bluf && (
          <div className="p-3 bg-purple-500/10 border border-purple-500/20 rounded-lg">
            <p className="text-sm font-medium text-purple-400">Bottom Line Up Front</p>
            <p className="text-sm text-muted-foreground mt-1">{analysis.bluf}</p>
          </div>
        )}
        <p className="text-sm text-muted-foreground">{analysis.assessment}</p>
        {analysis.active_actors && analysis.active_actors.length > 0 && (
          <div className="grid gap-3">
            {analysis.active_actors.slice(0, 5).map((actor, i) => (
              <div key={i} className="p-3 border rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-sm">{actor.name}</span>
                  {actor.source_count && (
                    <Badge variant="outline" className="text-xs">
                      {actor.source_count} sources
                    </Badge>
                  )}
                </div>
                <p className="text-xs text-muted-foreground">{actor.activity_summary}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </BriefingSection>
  );
}

// Ransomware Analysis Section
function RansomwareAnalysis({ summary }: { summary: IntelSummary }) {
  const analysis = summary.ransomware_analysis;
  if (!analysis) return null;

  return (
    <BriefingSection
      title="Ransomware Activity"
      icon={Skull}
      iconColor="bg-red-500"
      confidence={analysis.confidence}
    >
      <div className="space-y-4">
        {analysis.bluf && (
          <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
            <p className="text-sm font-medium text-red-400">Bottom Line Up Front</p>
            <p className="text-sm text-muted-foreground mt-1">{analysis.bluf}</p>
          </div>
        )}
        <div className="flex items-center gap-4 mb-3">
          <div className="text-center">
            <div className="text-2xl font-bold text-red-400">{analysis.total_victims}</div>
            <div className="text-xs text-muted-foreground">Total Victims</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold">{analysis.active_groups?.length || 0}</div>
            <div className="text-xs text-muted-foreground">Active Groups</div>
          </div>
        </div>
        <p className="text-sm text-muted-foreground">{analysis.assessment}</p>
        {analysis.active_groups && analysis.active_groups.length > 0 && (
          <div className="grid grid-cols-2 gap-2">
            {analysis.active_groups.slice(0, 6).map((group, i) => (
              <div key={i} className="p-2 border rounded-lg flex items-center justify-between">
                <span className="text-sm font-medium">{group.name}</span>
                <Badge variant="destructive" className="text-xs">
                  {group.victim_count} victims
                </Badge>
              </div>
            ))}
          </div>
        )}
      </div>
    </BriefingSection>
  );
}

// Vulnerability Analysis Section
function VulnerabilityAnalysis({ summary }: { summary: IntelSummary }) {
  const analysis = summary.vulnerability_analysis;
  if (!analysis) return null;

  return (
    <BriefingSection
      title="Vulnerability Analysis"
      icon={Bug}
      iconColor="bg-orange-500"
      confidence={analysis.confidence}
    >
      <div className="space-y-4">
        {analysis.bluf && (
          <div className="p-3 bg-orange-500/10 border border-orange-500/20 rounded-lg">
            <p className="text-sm font-medium text-orange-400">Bottom Line Up Front</p>
            <p className="text-sm text-muted-foreground mt-1">{analysis.bluf}</p>
          </div>
        )}
        <p className="text-sm text-muted-foreground">{analysis.assessment}</p>
        {analysis.critical_vulns && analysis.critical_vulns.length > 0 && (
          <div className="space-y-2">
            {analysis.critical_vulns.slice(0, 5).map((vuln, i) => (
              <div key={i} className="p-3 border border-orange-500/30 rounded-lg">
                <div className="flex items-center justify-between mb-1">
                  <code className="text-sm font-mono text-orange-400">{vuln.cve}</code>
                  <Badge variant="outline" className="text-xs bg-orange-500/10">
                    {vuln.urgency}
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground">{vuln.context}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </BriefingSection>
  );
}

// Targeting Analysis Section
function TargetingAnalysis({ summary }: { summary: IntelSummary }) {
  const analysis = summary.targeting_analysis;
  if (!analysis) return null;

  return (
    <BriefingSection
      title="Targeting Analysis"
      icon={Target}
      iconColor="bg-cyan-500"
      confidence={analysis.confidence}
    >
      <div className="space-y-4">
        {analysis.bluf && (
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-lg">
            <p className="text-sm font-medium text-cyan-400">Bottom Line Up Front</p>
            <p className="text-sm text-muted-foreground mt-1">{analysis.bluf}</p>
          </div>
        )}
        <p className="text-sm text-muted-foreground">{analysis.assessment}</p>
        <div className="grid grid-cols-2 gap-4">
          {analysis.sectors_at_risk && analysis.sectors_at_risk.length > 0 && (
            <div>
              <p className="text-xs font-medium text-muted-foreground mb-2">Sectors at Risk</p>
              <div className="flex flex-wrap gap-1">
                {analysis.sectors_at_risk.map((sector, i) => (
                  <Badge key={i} variant="secondary" className="text-xs">
                    {sector}
                  </Badge>
                ))}
              </div>
            </div>
          )}
          {analysis.geographic_focus && analysis.geographic_focus.length > 0 && (
            <div>
              <p className="text-xs font-medium text-muted-foreground mb-2">Geographic Focus</p>
              <div className="flex flex-wrap gap-1">
                {analysis.geographic_focus.map((geo, i) => (
                  <Badge key={i} variant="outline" className="text-xs">
                    {geo}
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </BriefingSection>
  );
}

// Recommended Actions Section
function RecommendedActions({ summary }: { summary: IntelSummary }) {
  const actions = summary.recommended_actions || [];
  if (actions.length === 0) return null;

  const urgencyOrder = ["IMMEDIATE", "THIS_WEEK", "THIS_MONTH", "ONGOING"];
  const sortedActions = [...actions].sort(
    (a, b) => urgencyOrder.indexOf(a.urgency || "ONGOING") - urgencyOrder.indexOf(b.urgency || "ONGOING")
  );

  return (
    <BriefingSection
      title="Recommended Actions"
      icon={TrendingUp}
      iconColor="bg-green-500"
    >
      <div className="space-y-3">
        {sortedActions.slice(0, 8).map((action, i) => (
          <div key={i} className="p-3 border rounded-lg">
            <div className="flex items-start justify-between gap-3">
              <div className="flex-1">
                <p className="text-sm font-medium">{action.action}</p>
                {action.why && (
                  <p className="text-xs text-muted-foreground mt-1">{action.why}</p>
                )}
              </div>
              <div className="flex flex-col items-end gap-1">
                <Badge
                  className={
                    action.urgency === "IMMEDIATE"
                      ? "bg-red-500/20 text-red-400"
                      : action.urgency === "THIS_WEEK"
                      ? "bg-amber-500/20 text-amber-400"
                      : "bg-green-500/20 text-green-400"
                  }
                >
                  {action.urgency || "ONGOING"}
                </Badge>
                {action.responsible_party && (
                  <span className="text-xs text-muted-foreground">
                    {action.responsible_party}
                  </span>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </BriefingSection>
  );
}

// Loading skeleton
function BriefingSkeleton() {
  return (
    <div className="space-y-6">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-40" />
      <Skeleton className="h-32" />
      <div className="grid grid-cols-2 gap-4">
        <Skeleton className="h-48" />
        <Skeleton className="h-48" />
      </div>
    </div>
  );
}

// Main Briefing Page
export function Briefing() {
  const { todaySummary, isTodayLoading } = useIntelSummaries();

  return (
    <AppLayout>
      <div className="max-w-4xl mx-auto space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-3">
              <FileText className="w-6 h-6 text-primary" />
              Daily Intelligence Briefing
            </h1>
            {todaySummary && (
              <p className="text-sm text-muted-foreground flex items-center gap-2 mt-1">
                <Calendar className="w-4 h-4" />
                {format(new Date(todaySummary.report_date), "EEEE, MMMM d, yyyy")}
              </p>
            )}
          </div>
          {todaySummary?.source_counts && (
            <div className="flex gap-2">
              <Badge variant="outline">{todaySummary.source_counts.media} media</Badge>
              <Badge variant="outline">{todaySummary.source_counts.threats} threats</Badge>
              <Badge variant="outline">{todaySummary.source_counts.advisories} advisories</Badge>
            </div>
          )}
        </div>

        {/* Content */}
        {isTodayLoading ? (
          <BriefingSkeleton />
        ) : !todaySummary ? (
          <Card className="border-dashed">
            <CardContent className="py-12 text-center">
              <FileText className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
              <h2 className="text-lg font-semibold mb-2">No Briefing Available</h2>
              <p className="text-sm text-muted-foreground">
                Today's intelligence briefing hasn't been generated yet.
              </p>
            </CardContent>
          </Card>
        ) : (
          <ScrollArea className="h-[calc(100vh-12rem)]">
            <div className="space-y-6 pr-4">
              <ExecutiveSummary summary={todaySummary} />
              <KeyTakeaways summary={todaySummary} />
              <ThreatLandscape summary={todaySummary} />
              <ActorAnalysis summary={todaySummary} />
              <RansomwareAnalysis summary={todaySummary} />
              <VulnerabilityAnalysis summary={todaySummary} />
              <TargetingAnalysis summary={todaySummary} />
              <RecommendedActions summary={todaySummary} />
            </div>
          </ScrollArea>
        )}
      </div>
    </AppLayout>
  );
}
