import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { ArrowRight, Calendar, Sparkles } from "lucide-react";
import { format } from "date-fns";
import type { IntelSummary } from "@/hooks/useIntelSummaries";

interface TodaysBriefingCardProps {
  summary: IntelSummary | null | undefined;
  isLoading: boolean;
}

export function TodaysBriefingCard({ summary, isLoading }: TodaysBriefingCardProps) {
  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-48" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-20 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (!summary) {
    return (
      <Card className="border-dashed">
        <CardContent className="py-8 text-center">
          <Sparkles className="w-10 h-10 mx-auto text-muted-foreground mb-3" />
          <h3 className="font-semibold mb-1">No Briefing Available</h3>
          <p className="text-sm text-muted-foreground">
            Today's threat briefing hasn't been generated yet.
          </p>
        </CardContent>
      </Card>
    );
  }

  // Get the BLUF or first part of threat landscape
  const briefSummary =
    summary.threat_landscape?.bluf ||
    summary.executive_summary?.slice(0, 300) ||
    "No summary available";

  return (
    <Card className="overflow-hidden">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center">
              <Sparkles className="w-4 h-4 text-primary" />
            </div>
            <div>
              <h2 className="font-semibold">Today's Briefing</h2>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Calendar className="w-3 h-3" />
                {format(new Date(summary.report_date), "MMMM d, yyyy")}
              </div>
            </div>
          </div>
          <Badge variant="secondary" className="text-xs">
            {summary.threat_landscape?.confidence || "AI Generated"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <p className="text-sm text-muted-foreground leading-relaxed mb-4">
          {briefSummary}
          {briefSummary.length >= 300 && "..."}
        </p>

        {/* Key themes */}
        {summary.threat_landscape?.key_themes && summary.threat_landscape.key_themes.length > 0 && (
          <div className="flex flex-wrap gap-2 mb-4">
            {summary.threat_landscape.key_themes.slice(0, 4).map((theme, i) => (
              <Badge key={i} variant="outline" className="text-xs">
                {theme}
              </Badge>
            ))}
          </div>
        )}

        <Button variant="ghost" size="sm" className="gap-2 -ml-2">
          Read Full Briefing
          <ArrowRight className="w-4 h-4" />
        </Button>
      </CardContent>
    </Card>
  );
}
