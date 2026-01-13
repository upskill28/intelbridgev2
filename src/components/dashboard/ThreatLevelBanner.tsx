import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { AlertTriangle, Shield, ShieldAlert, ShieldCheck } from "lucide-react";
import type { IntelSummary } from "@/hooks/useIntelSummaries";

interface ThreatLevelBannerProps {
  summary: IntelSummary | null | undefined;
  isLoading: boolean;
}

type ThreatLevel = "CRITICAL" | "ELEVATED" | "GUARDED" | "LOW";

const threatLevelConfig: Record<
  ThreatLevel,
  {
    icon: typeof AlertTriangle;
    label: string;
    message: string;
    bgClass: string;
    iconColor: string;
  }
> = {
  CRITICAL: {
    icon: AlertTriangle,
    label: "Critical",
    message: "Active threats targeting your sector - immediate action required",
    bgClass: "threat-critical-bg",
    iconColor: "text-red-500",
  },
  ELEVATED: {
    icon: ShieldAlert,
    label: "Elevated",
    message: "Increased threat activity detected - stay vigilant",
    bgClass: "threat-elevated-bg",
    iconColor: "text-amber-500",
  },
  GUARDED: {
    icon: Shield,
    label: "Guarded",
    message: "Normal threat levels - maintain standard security posture",
    bgClass: "threat-guarded-bg",
    iconColor: "text-yellow-500",
  },
  LOW: {
    icon: ShieldCheck,
    label: "Low",
    message: "Below average threat activity - continue monitoring",
    bgClass: "threat-low-bg",
    iconColor: "text-green-500",
  },
};

function calculateThreatLevel(summary: IntelSummary | null | undefined): ThreatLevel {
  if (!summary) return "GUARDED";

  // Use threat_posture if available
  if (summary.threat_posture?.level) {
    const level = summary.threat_posture.level.toUpperCase();
    if (level === "ELEVATED") return "ELEVATED";
    if (level === "LOW") return "LOW";
    return "GUARDED";
  }

  // Fallback: Calculate based on activity
  const ransomwareCount = summary.source_counts?.ransomwareVictims || 0;
  const criticalCount = summary.advisory_summaries?.filter(
    (a) => a.severity?.toLowerCase() === "critical"
  ).length || 0;

  if (ransomwareCount > 50 || criticalCount > 5) return "CRITICAL";
  if (ransomwareCount > 30 || criticalCount > 2) return "ELEVATED";
  if (ransomwareCount > 10) return "GUARDED";
  return "LOW";
}

export function ThreatLevelBanner({ summary, isLoading }: ThreatLevelBannerProps) {
  if (isLoading) {
    return <Skeleton className="h-20 w-full rounded-xl" />;
  }

  const level = calculateThreatLevel(summary);
  const config = threatLevelConfig[level];
  const Icon = config.icon;

  // Count pending actions
  const actionCount = summary?.recommended_actions?.filter(
    (a) => a.urgency === "IMMEDIATE" || a.urgency === "THIS_WEEK"
  ).length || 0;

  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-xl border p-4",
        config.bgClass
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div
            className={cn(
              "w-12 h-12 rounded-xl flex items-center justify-center",
              "bg-background/20 backdrop-blur"
            )}
          >
            <Icon className={cn("w-6 h-6", config.iconColor)} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Threat Level
              </span>
              <span
                className={cn(
                  "px-2 py-0.5 rounded-full text-xs font-semibold",
                  level === "CRITICAL" && "bg-red-500/20 text-red-400",
                  level === "ELEVATED" && "bg-amber-500/20 text-amber-400",
                  level === "GUARDED" && "bg-yellow-500/20 text-yellow-400",
                  level === "LOW" && "bg-green-500/20 text-green-400"
                )}
              >
                {config.label}
              </span>
            </div>
            <p className="text-sm text-foreground/80 mt-1">{config.message}</p>
          </div>
        </div>

        {actionCount > 0 && (
          <div className="text-right">
            <div className="text-2xl font-bold">{actionCount}</div>
            <div className="text-xs text-muted-foreground">
              actions needed
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
