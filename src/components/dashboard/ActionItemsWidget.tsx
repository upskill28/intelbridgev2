import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { CheckCircle2, Clock, AlertCircle, ChevronRight } from "lucide-react";
import type { IntelSummary, RecommendedAction } from "@/hooks/useIntelSummaries";

interface ActionItemsWidgetProps {
  summary: IntelSummary | null | undefined;
  isLoading: boolean;
}

const urgencyConfig = {
  IMMEDIATE: {
    label: "Immediate",
    icon: AlertCircle,
    bgClass: "bg-red-500/10 border-red-500/30",
    textClass: "text-red-400",
    badgeClass: "bg-red-500/20 text-red-400",
  },
  THIS_WEEK: {
    label: "This Week",
    icon: Clock,
    bgClass: "bg-amber-500/10 border-amber-500/30",
    textClass: "text-amber-400",
    badgeClass: "bg-amber-500/20 text-amber-400",
  },
  THIS_MONTH: {
    label: "This Month",
    icon: Clock,
    bgClass: "bg-blue-500/10 border-blue-500/30",
    textClass: "text-blue-400",
    badgeClass: "bg-blue-500/20 text-blue-400",
  },
  ONGOING: {
    label: "Ongoing",
    icon: CheckCircle2,
    bgClass: "bg-green-500/10 border-green-500/30",
    textClass: "text-green-400",
    badgeClass: "bg-green-500/20 text-green-400",
  },
};

function ActionCard({ action }: { action: RecommendedAction }) {
  const urgency = action.urgency || "ONGOING";
  const config = urgencyConfig[urgency as keyof typeof urgencyConfig] || urgencyConfig.ONGOING;
  const Icon = config.icon;

  return (
    <div
      className={cn(
        "p-4 rounded-lg border transition-all hover:scale-[1.02] cursor-pointer",
        config.bgClass
      )}
    >
      <div className="flex items-start gap-3">
        <Icon className={cn("w-5 h-5 mt-0.5 shrink-0", config.textClass)} />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium line-clamp-2">{action.action}</p>
          {action.responsible_party && (
            <p className="text-xs text-muted-foreground mt-1">
              Owner: {action.responsible_party}
            </p>
          )}
        </div>
      </div>
      <div className="flex items-center justify-between mt-3">
        <Badge className={cn("text-xs", config.badgeClass)}>
          {config.label}
        </Badge>
        <Button variant="ghost" size="sm" className="h-7 px-2 text-xs gap-1">
          Details
          <ChevronRight className="w-3 h-3" />
        </Button>
      </div>
    </div>
  );
}

export function ActionItemsWidget({ summary, isLoading }: ActionItemsWidgetProps) {
  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-32" />
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Skeleton className="h-32" />
            <Skeleton className="h-32" />
            <Skeleton className="h-32" />
          </div>
        </CardContent>
      </Card>
    );
  }

  const actions = summary?.recommended_actions || [];
  const immediate = actions.filter((a) => a.urgency === "IMMEDIATE").slice(0, 2);
  const thisWeek = actions.filter((a) => a.urgency === "THIS_WEEK").slice(0, 2);
  const ongoing = actions
    .filter((a) => a.urgency === "ONGOING" || a.urgency === "THIS_MONTH")
    .slice(0, 2);

  if (actions.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Recommended Actions</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground text-center py-4">
            No recommended actions at this time.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg">Recommended Actions</CardTitle>
          <Badge variant="outline" className="text-xs">
            {actions.length} total
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Immediate Column */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-red-400 flex items-center gap-2">
              <AlertCircle className="w-3 h-3" />
              Immediate
            </h3>
            {immediate.length > 0 ? (
              immediate.map((action, i) => <ActionCard key={i} action={action} />)
            ) : (
              <p className="text-xs text-muted-foreground py-4 text-center">
                No immediate actions
              </p>
            )}
          </div>

          {/* This Week Column */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-amber-400 flex items-center gap-2">
              <Clock className="w-3 h-3" />
              This Week
            </h3>
            {thisWeek.length > 0 ? (
              thisWeek.map((action, i) => <ActionCard key={i} action={action} />)
            ) : (
              <p className="text-xs text-muted-foreground py-4 text-center">
                No actions this week
              </p>
            )}
          </div>

          {/* Ongoing Column */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-green-400 flex items-center gap-2">
              <CheckCircle2 className="w-3 h-3" />
              Ongoing
            </h3>
            {ongoing.length > 0 ? (
              ongoing.map((action, i) => <ActionCard key={i} action={action} />)
            ) : (
              <p className="text-xs text-muted-foreground py-4 text-center">
                No ongoing actions
              </p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
