import { useState } from "react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { useHistoricalTrends } from "@/hooks/useHistoricalTrends";
import type { TrendPeriod } from "@/hooks/useHistoricalTrends";
import {
  TrendingUp,
  Activity,
  Shield,
  AlertTriangle,
  Skull,
  FileText,
  Newspaper,
  Calendar,
  Target,
} from "lucide-react";
import { format, parseISO } from "date-fns";

const periodOptions: { value: TrendPeriod; label: string }[] = [
  { value: "7d", label: "7 Days" },
  { value: "30d", label: "30 Days" },
  { value: "90d", label: "90 Days" },
  { value: "6m", label: "6 Months" },
  { value: "1y", label: "1 Year" },
];

function SummaryCard({
  title,
  value,
  icon: Icon,
  description,
  color,
}: {
  title: string;
  value: string | number;
  icon: React.ElementType;
  description?: string;
  color?: string;
}) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg ${color || 'bg-primary/10'} flex items-center justify-center`}>
            <Icon className={`w-5 h-5 ${color ? 'text-white' : 'text-primary'}`} />
          </div>
          <div>
            <p className="text-2xl font-bold">{value}</p>
            <p className="text-sm text-muted-foreground">{title}</p>
            {description && <p className="text-xs text-muted-foreground mt-0.5">{description}</p>}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ActivityTrendChart({ data, isLoading }: { data?: any[]; isLoading: boolean }) {
  if (isLoading) {
    return <Skeleton className="h-[350px] w-full" />;
  }

  if (!data || data.length === 0) {
    return (
      <div className="h-[350px] flex items-center justify-center text-muted-foreground">
        No activity data available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={350}>
      <AreaChart data={data} margin={{ top: 10, right: 10, left: -10, bottom: 30 }}>
        <defs>
          <linearGradient id="colorRansomware" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="colorVuln" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="colorReports" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
          </linearGradient>
        </defs>
        <XAxis
          dataKey="date"
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 10 }}
          angle={-45}
          textAnchor="end"
          interval="preserveStartEnd"
          tickFormatter={(value) => {
            try {
              return format(parseISO(value), 'MMM d');
            } catch {
              return value;
            }
          }}
        />
        <YAxis
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: 'hsl(var(--card))',
            border: '1px solid hsl(var(--border))',
            borderRadius: '8px',
            fontSize: '12px',
          }}
          labelStyle={{ color: 'hsl(var(--foreground))' }}
          labelFormatter={(value) => {
            try {
              return format(parseISO(value), 'MMM d, yyyy');
            } catch {
              return value;
            }
          }}
        />
        <Legend verticalAlign="top" height={36} />
        <Area
          type="monotone"
          dataKey="ransomware"
          name="Ransomware"
          stroke="#ef4444"
          fill="url(#colorRansomware)"
          strokeWidth={2}
        />
        <Area
          type="monotone"
          dataKey="vulnerabilities"
          name="Vulnerabilities"
          stroke="#f97316"
          fill="url(#colorVuln)"
          strokeWidth={2}
        />
        <Area
          type="monotone"
          dataKey="reports"
          name="Reports"
          stroke="#22c55e"
          fill="url(#colorReports)"
          strokeWidth={2}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function VulnerabilitySeverityChart({ data, isLoading }: { data?: any[]; isLoading: boolean }) {
  if (isLoading) {
    return <Skeleton className="h-[300px] w-full" />;
  }

  if (!data || data.length === 0) {
    return (
      <div className="h-[300px] flex items-center justify-center text-muted-foreground">
        No vulnerability data available
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data} margin={{ top: 10, right: 10, left: -10, bottom: 30 }}>
        <XAxis
          dataKey="date"
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 10 }}
          angle={-45}
          textAnchor="end"
          interval="preserveStartEnd"
          tickFormatter={(value) => {
            try {
              return format(parseISO(value), 'MMM d');
            } catch {
              return value;
            }
          }}
        />
        <YAxis
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: 'hsl(var(--card))',
            border: '1px solid hsl(var(--border))',
            borderRadius: '8px',
            fontSize: '12px',
          }}
          labelFormatter={(value) => {
            try {
              return format(parseISO(value), 'MMM d, yyyy');
            } catch {
              return value;
            }
          }}
        />
        <Legend verticalAlign="top" height={36} />
        <Bar dataKey="critical" name="Critical" stackId="a" fill="#ef4444" />
        <Bar dataKey="high" name="High" stackId="a" fill="#f97316" />
        <Bar dataKey="medium" name="Medium" stackId="a" fill="#eab308" />
        <Bar dataKey="low" name="Low" stackId="a" fill="#22c55e" />
      </BarChart>
    </ResponsiveContainer>
  );
}

function ThreatActorTrendsChart({ data, isLoading }: { data?: any[]; isLoading: boolean }) {
  if (isLoading) {
    return <Skeleton className="h-[300px] w-full" />;
  }

  if (!data || data.length === 0) {
    return (
      <div className="h-[300px] flex items-center justify-center text-muted-foreground">
        No threat actor data available
      </div>
    );
  }

  // Transform data for the chart
  const colors = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6'];
  const allDates = data[0]?.data.map((d: any) => d.date) || [];

  const chartData = allDates.map((date: string) => {
    const point: any = { date };
    data.forEach((actor) => {
      const dayData = actor.data.find((d: any) => d.date === date);
      point[actor.name] = dayData?.count || 0;
    });
    return point;
  });

  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={chartData} margin={{ top: 10, right: 10, left: -10, bottom: 30 }}>
        <XAxis
          dataKey="date"
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 10 }}
          angle={-45}
          textAnchor="end"
          interval="preserveStartEnd"
          tickFormatter={(value) => {
            try {
              return format(parseISO(value), 'MMM d');
            } catch {
              return value;
            }
          }}
        />
        <YAxis
          tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: 'hsl(var(--card))',
            border: '1px solid hsl(var(--border))',
            borderRadius: '8px',
            fontSize: '12px',
          }}
          labelFormatter={(value) => {
            try {
              return format(parseISO(value), 'MMM d, yyyy');
            } catch {
              return value;
            }
          }}
        />
        <Legend verticalAlign="top" height={36} />
        {data.map((actor, i) => (
          <Line
            key={actor.name}
            type="monotone"
            dataKey={actor.name}
            stroke={colors[i % colors.length]}
            strokeWidth={2}
            dot={{ r: 2 }}
            activeDot={{ r: 4 }}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}

export function HistoricalTrends() {
  const [period, setPeriod] = useState<TrendPeriod>("30d");
  const { data, isLoading, error } = useHistoricalTrends(period);

  return (
    <AppLayout>
      <div className="max-w-6xl mx-auto space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-3">
              <TrendingUp className="w-6 h-6" />
              Historical Trends
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Analyze threat intelligence activity over time
            </p>
          </div>

          {/* Period Selector */}
          <div className="flex gap-2">
            {periodOptions.map((option) => (
              <Button
                key={option.value}
                variant={period === option.value ? "default" : "outline"}
                size="sm"
                onClick={() => setPeriod(option.value)}
              >
                {option.label}
              </Button>
            ))}
          </div>
        </div>

        {/* Summary Cards */}
        {isLoading ? (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {[...Array(5)].map((_, i) => (
              <Skeleton key={i} className="h-24" />
            ))}
          </div>
        ) : error ? (
          <Card className="border-dashed">
            <CardContent className="py-12 text-center">
              <AlertTriangle className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
              <h2 className="text-lg font-semibold mb-2">Error Loading Data</h2>
              <p className="text-sm text-muted-foreground">
                Failed to load historical trends. Please try again.
              </p>
            </CardContent>
          </Card>
        ) : (
          <>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <SummaryCard
                title="Ransomware Victims"
                value={data?.summary.totalRansomware || 0}
                icon={Skull}
                description={`${data?.summary.avgDailyRansomware || 0}/day avg`}
                color="bg-red-500"
              />
              <SummaryCard
                title="Vulnerabilities"
                value={data?.summary.totalVulnerabilities || 0}
                icon={AlertTriangle}
                description={`${data?.summary.avgDailyVulnerabilities || 0}/day avg`}
                color="bg-orange-500"
              />
              <SummaryCard
                title="Threat Reports"
                value={data?.summary.totalReports || 0}
                icon={FileText}
                color="bg-green-500"
              />
              <SummaryCard
                title="Advisories"
                value={data?.summary.totalAdvisories || 0}
                icon={Shield}
                color="bg-purple-500"
              />
              <SummaryCard
                title="Media Reports"
                value={data?.summary.totalMedia || 0}
                icon={Newspaper}
                color="bg-cyan-500"
              />
            </div>

            {/* Peak Day Banner */}
            {data?.summary.peakDay && (
              <Card className="bg-gradient-to-r from-amber-500/10 to-orange-500/10 border-amber-500/30">
                <CardContent className="py-4 flex items-center gap-4">
                  <div className="w-10 h-10 rounded-lg bg-amber-500 flex items-center justify-center">
                    <Calendar className="w-5 h-5 text-white" />
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Peak Activity Day</p>
                    <p className="font-semibold">
                      {format(parseISO(data.summary.peakDay), 'MMMM d, yyyy')} with{' '}
                      <span className="text-amber-500">{data.summary.peakCount} events</span>
                    </p>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Charts */}
            <Tabs defaultValue="activity" className="space-y-6">
              <TabsList>
                <TabsTrigger value="activity" className="gap-2">
                  <Activity className="w-4 h-4" />
                  Overall Activity
                </TabsTrigger>
                <TabsTrigger value="vulnerabilities" className="gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  Vulnerabilities
                </TabsTrigger>
                <TabsTrigger value="threat-actors" className="gap-2">
                  <Target className="w-4 h-4" />
                  Threat Actors
                </TabsTrigger>
              </TabsList>

              <TabsContent value="activity">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <Activity className="w-4 h-4" />
                      Daily Activity Trend
                    </CardTitle>
                    <CardDescription>
                      Combined view of ransomware, vulnerabilities, and threat reports over time
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ActivityTrendChart data={data?.dailyActivity} isLoading={isLoading} />
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="vulnerabilities">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      Vulnerability Severity Distribution
                    </CardTitle>
                    <CardDescription>
                      Daily breakdown of vulnerabilities by CVSS severity level
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <VulnerabilitySeverityChart
                      data={data?.vulnerabilitySeverityTrends}
                      isLoading={isLoading}
                    />
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="threat-actors">
                <div className="space-y-6">
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base flex items-center gap-2">
                        <Target className="w-4 h-4" />
                        Top Threat Actor Activity
                      </CardTitle>
                      <CardDescription>
                        Daily victim count by top ransomware groups
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <ThreatActorTrendsChart
                        data={data?.threatActorTrends}
                        isLoading={isLoading}
                      />
                    </CardContent>
                  </Card>

                  {/* Threat Actor Leaderboard */}
                  {data?.threatActorTrends && data.threatActorTrends.length > 0 && (
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base">Most Active Groups</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          {data.threatActorTrends.map((actor, i) => (
                            <div
                              key={actor.name}
                              className="flex items-center justify-between p-3 rounded-lg bg-muted/50"
                            >
                              <div className="flex items-center gap-3">
                                <Badge
                                  variant="outline"
                                  className={
                                    i === 0
                                      ? 'bg-red-500/20 text-red-400 border-red-500/30'
                                      : i === 1
                                      ? 'bg-orange-500/20 text-orange-400 border-orange-500/30'
                                      : i === 2
                                      ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                                      : 'bg-muted'
                                  }
                                >
                                  #{i + 1}
                                </Badge>
                                <span className="font-medium">{actor.name}</span>
                              </div>
                              <div className="text-right">
                                <span className="text-lg font-bold">{actor.total}</span>
                                <span className="text-sm text-muted-foreground ml-1">victims</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </div>
              </TabsContent>
            </Tabs>
          </>
        )}
      </div>
    </AppLayout>
  );
}
