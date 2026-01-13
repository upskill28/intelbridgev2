import { useState } from "react";
import { AppLayout } from "@/components/layout/AppLayout";
import { useIntelSummaries } from "@/hooks/useIntelSummaries";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Rss,
  Skull,
  Bug,
  Newspaper,
  ShieldAlert,
  FileText,
  ExternalLink,
  Filter,
  Calendar,
  Search,
} from "lucide-react";
import { format } from "date-fns";
import { cn } from "@/lib/utils";
import type {
  MediaSummary,
  ThreatSummary,
  AdvisorySummary,
  RansomwareActivity,
} from "@/hooks/useIntelSummaries";

type FeedFilter = "all" | "ransomware" | "vulnerabilities" | "media" | "advisories" | "threats";

const filterConfig: Record<FeedFilter, { icon: typeof Rss; label: string; color: string }> = {
  all: { icon: Rss, label: "All", color: "text-primary" },
  ransomware: { icon: Skull, label: "Ransomware", color: "text-red-500" },
  vulnerabilities: { icon: Bug, label: "Vulnerabilities", color: "text-orange-500" },
  media: { icon: Newspaper, label: "Media", color: "text-blue-500" },
  advisories: { icon: ShieldAlert, label: "Advisories", color: "text-purple-500" },
  threats: { icon: FileText, label: "Threat Reports", color: "text-green-500" },
};

// Ransomware Card
function RansomwareCard({ activity }: { activity: RansomwareActivity }) {
  return (
    <Card className="hover:bg-muted/30 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
              <Skull className="w-5 h-5 text-red-500" />
            </div>
            <div>
              <h3 className="font-semibold">{activity.actor}</h3>
              <p className="text-xs text-muted-foreground">Ransomware Group</p>
            </div>
          </div>
          <Badge variant="destructive">{activity.victimCount} victims</Badge>
        </div>
        {activity.victims.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1">
            {activity.victims.slice(0, 5).map((victim, i) => (
              <Badge key={i} variant="outline" className="text-xs">
                {victim}
              </Badge>
            ))}
            {activity.victims.length > 5 && (
              <Badge variant="outline" className="text-xs">
                +{activity.victims.length - 5} more
              </Badge>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// Media Report Card
function MediaCard({ report }: { report: MediaSummary }) {
  return (
    <Card className="hover:bg-muted/30 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center shrink-0">
            <Newspaper className="w-5 h-5 text-blue-500" />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="font-medium text-sm line-clamp-2">{report.title}</h3>
            <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
              {report.summary}
            </p>
            <div className="flex items-center gap-2 mt-2">
              <Calendar className="w-3 h-3 text-muted-foreground" />
              <span className="text-xs text-muted-foreground">
                {format(new Date(report.date), "MMM d, yyyy")}
              </span>
              {report.sourceUrl && (
                <a
                  href={report.sourceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-primary hover:underline flex items-center gap-1 ml-auto"
                >
                  Source <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// Threat Report Card
function ThreatCard({ report }: { report: ThreatSummary }) {
  return (
    <Card className="hover:bg-muted/30 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center shrink-0">
            <FileText className="w-5 h-5 text-green-500" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h3 className="font-medium text-sm line-clamp-1">{report.title}</h3>
              <Badge
                className={cn(
                  "text-xs shrink-0",
                  report.severity === "critical" && "bg-red-500/20 text-red-400",
                  report.severity === "high" && "bg-orange-500/20 text-orange-400",
                  report.severity === "medium" && "bg-yellow-500/20 text-yellow-400",
                  report.severity === "low" && "bg-green-500/20 text-green-400"
                )}
              >
                {report.severity}
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground line-clamp-2">
              {report.summary}
            </p>
            {report.threatActor && (
              <Badge variant="outline" className="mt-2 text-xs">
                {report.threatActor}
              </Badge>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// Advisory Card
function AdvisoryCard({ advisory }: { advisory: AdvisorySummary }) {
  return (
    <Card className="hover:bg-muted/30 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center shrink-0">
            <ShieldAlert className="w-5 h-5 text-purple-500" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h3 className="font-medium text-sm line-clamp-1">{advisory.title}</h3>
              <Badge
                className={cn(
                  "text-xs shrink-0",
                  advisory.severity === "critical" && "bg-red-500/20 text-red-400",
                  advisory.severity === "high" && "bg-orange-500/20 text-orange-400"
                )}
              >
                {advisory.severity}
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground line-clamp-2">
              {advisory.summary}
            </p>
            <div className="flex items-center gap-2 mt-2">
              <Badge variant="secondary" className="text-xs">
                {advisory.source}
              </Badge>
              <span className="text-xs text-muted-foreground">
                {format(new Date(advisory.date), "MMM d, yyyy")}
              </span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// Loading skeleton
function FeedSkeleton() {
  return (
    <div className="space-y-4">
      {[...Array(5)].map((_, i) => (
        <Skeleton key={i} className="h-24" />
      ))}
    </div>
  );
}

// Main Feed Page
export function Feed() {
  const { todaySummary, isTodayLoading } = useIntelSummaries();
  const [filter, setFilter] = useState<FeedFilter>("all");
  const [searchQuery, setSearchQuery] = useState("");

  // Combine all feed items
  const getFeedItems = () => {
    if (!todaySummary) return [];

    const items: Array<{
      type: FeedFilter;
      data: RansomwareActivity | MediaSummary | ThreatSummary | AdvisorySummary;
      date: string;
    }> = [];

    // Add ransomware activity
    if (filter === "all" || filter === "ransomware") {
      todaySummary.ransomware_activity?.forEach((r) => {
        items.push({ type: "ransomware", data: r, date: todaySummary.report_date });
      });
    }

    // Add media reports
    if (filter === "all" || filter === "media") {
      todaySummary.media_summaries?.forEach((m) => {
        items.push({ type: "media", data: m, date: m.date });
      });
    }

    // Add threat reports
    if (filter === "all" || filter === "threats") {
      todaySummary.threat_summaries?.forEach((t) => {
        items.push({ type: "threats", data: t, date: t.date });
      });
    }

    // Add advisories
    if (filter === "all" || filter === "advisories") {
      todaySummary.advisory_summaries?.forEach((a) => {
        items.push({ type: "advisories", data: a, date: a.date });
      });
    }

    // Filter by search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return items.filter((item) => {
        if ("title" in item.data) {
          return item.data.title.toLowerCase().includes(query);
        }
        if ("actor" in item.data) {
          return item.data.actor.toLowerCase().includes(query);
        }
        return false;
      });
    }

    return items;
  };

  const feedItems = getFeedItems();

  return (
    <AppLayout>
      <div className="space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-3">
              <Rss className="w-6 h-6 text-primary" />
              Threat Feed
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Real-time threat intelligence from multiple sources
            </p>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {Object.entries(filterConfig).map(([key, config]) => {
            const Icon = config.icon;
            return (
              <Button
                key={key}
                variant={filter === key ? "default" : "outline"}
                size="sm"
                onClick={() => setFilter(key as FeedFilter)}
                className="gap-2"
              >
                <Icon className={cn("w-4 h-4", filter !== key && config.color)} />
                {config.label}
              </Button>
            );
          })}
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search threats, actors, vulnerabilities..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-muted/50 border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary"
          />
        </div>

        {/* Feed */}
        {isTodayLoading ? (
          <FeedSkeleton />
        ) : feedItems.length === 0 ? (
          <Card className="border-dashed">
            <CardContent className="py-12 text-center">
              <Filter className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
              <h2 className="text-lg font-semibold mb-2">No Items Found</h2>
              <p className="text-sm text-muted-foreground">
                {searchQuery
                  ? "Try adjusting your search query"
                  : "No threat intelligence items available for the selected filter"}
              </p>
            </CardContent>
          </Card>
        ) : (
          <ScrollArea className="h-[calc(100vh-16rem)]">
            <div className="space-y-3 pr-4">
              {feedItems.map((item, i) => (
                <div key={i}>
                  {item.type === "ransomware" && (
                    <RansomwareCard activity={item.data as RansomwareActivity} />
                  )}
                  {item.type === "media" && <MediaCard report={item.data as MediaSummary} />}
                  {item.type === "threats" && <ThreatCard report={item.data as ThreatSummary} />}
                  {item.type === "advisories" && (
                    <AdvisoryCard advisory={item.data as AdvisorySummary} />
                  )}
                </div>
              ))}
            </div>
          </ScrollArea>
        )}
      </div>
    </AppLayout>
  );
}
