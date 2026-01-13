import { useIntelSummaries } from "@/hooks/useIntelSummaries";
import { ThreatLevelBanner } from "@/components/dashboard/ThreatLevelBanner";
import { TodaysBriefingCard } from "@/components/dashboard/TodaysBriefingCard";
import { ActionItemsWidget } from "@/components/dashboard/ActionItemsWidget";
import { QuickStatsRow } from "@/components/dashboard/QuickStatsRow";
import { Sidebar } from "@/components/layout/Sidebar";
import { Shield } from "lucide-react";

export function Dashboard() {
  const { todaySummary, isTodayLoading } = useIntelSummaries();

  return (
    <div className="flex min-h-screen bg-background">
      {/* Sidebar Navigation */}
      <Sidebar />

      {/* Main Content */}
      <main className="flex-1 p-6 space-y-6 overflow-auto">
        {/* Header */}
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Intel Bridge</h1>
              <p className="text-sm text-muted-foreground">
                Threat Intelligence for Your Business
              </p>
            </div>
          </div>
        </header>

        {/* Threat Level Banner */}
        <ThreatLevelBanner summary={todaySummary} isLoading={isTodayLoading} />

        {/* Today's Briefing Card */}
        <TodaysBriefingCard summary={todaySummary} isLoading={isTodayLoading} />

        {/* Action Items */}
        <ActionItemsWidget summary={todaySummary} isLoading={isTodayLoading} />

        {/* Quick Stats Row */}
        <QuickStatsRow summary={todaySummary} isLoading={isTodayLoading} />
      </main>
    </div>
  );
}
