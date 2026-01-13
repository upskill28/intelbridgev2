import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import {
  Skull,
  Bug,
  FileText,
  Newspaper,
  ShieldAlert,
  TrendingUp,
  TrendingDown,
  Minus,
} from "lucide-react";
import type { IntelSummary } from "@/hooks/useIntelSummaries";

interface QuickStatsRowProps {
  summary: IntelSummary | null | undefined;
  isLoading: boolean;
}

interface StatCardProps {
  icon: typeof Skull;
  label: string;
  value: number;
  trend?: "up" | "down" | "neutral";
  iconColor: string;
  bgColor: string;
}

function StatCard({ icon: Icon, label, value, trend, iconColor, bgColor }: StatCardProps) {
  const TrendIcon = trend === "up" ? TrendingUp : trend === "down" ? TrendingDown : Minus;
  const trendColor =
    trend === "up" ? "text-red-400" : trend === "down" ? "text-green-400" : "text-muted-foreground";

  return (
    <Card className="hover:bg-muted/30 transition-colors cursor-pointer">
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div
            className={cn(
              "w-10 h-10 rounded-lg flex items-center justify-center",
              bgColor
            )}
          >
            <Icon className={cn("w-5 h-5", iconColor)} />
          </div>
          {trend && (
            <TrendIcon className={cn("w-4 h-4", trendColor)} />
          )}
        </div>
        <div className="mt-3">
          <div className="text-2xl font-bold">{value.toLocaleString()}</div>
          <div className="text-xs text-muted-foreground">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}

export function QuickStatsRow({ summary, isLoading }: QuickStatsRowProps) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[...Array(5)].map((_, i) => (
          <Skeleton key={i} className="h-28" />
        ))}
      </div>
    );
  }

  const stats = [
    {
      icon: Skull,
      label: "Ransomware Victims",
      value: summary?.source_counts?.ransomwareVictims || 0,
      trend: "up" as const,
      iconColor: "text-red-500",
      bgColor: "bg-red-500/10",
    },
    {
      icon: Bug,
      label: "Critical CVEs",
      value:
        summary?.advisory_summaries?.filter(
          (a) => a.severity?.toLowerCase() === "critical"
        ).length || 0,
      trend: "neutral" as const,
      iconColor: "text-orange-500",
      bgColor: "bg-orange-500/10",
    },
    {
      icon: FileText,
      label: "Threat Reports",
      value: summary?.source_counts?.threats || 0,
      trend: "neutral" as const,
      iconColor: "text-green-500",
      bgColor: "bg-green-500/10",
    },
    {
      icon: Newspaper,
      label: "Media Reports",
      value: summary?.source_counts?.media || 0,
      trend: "neutral" as const,
      iconColor: "text-blue-500",
      bgColor: "bg-blue-500/10",
    },
    {
      icon: ShieldAlert,
      label: "Advisories",
      value: summary?.source_counts?.advisories || 0,
      trend: "neutral" as const,
      iconColor: "text-purple-500",
      bgColor: "bg-purple-500/10",
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
      {stats.map((stat, i) => (
        <StatCard key={i} {...stat} />
      ))}
    </div>
  );
}
