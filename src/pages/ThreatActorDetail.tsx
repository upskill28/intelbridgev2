import { useParams, useNavigate } from "react-router-dom";
import { AppLayout } from "@/components/layout/AppLayout";
import { useIntrusionSetDetail } from "@/hooks/useIntrusionSets";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { VictimologyCard } from "@/components/threat-actors/VictimologyCard";
import { AttackPatternsTable } from "@/components/threat-actors/AttackPatternsTable";
import { IndicatorsTable } from "@/components/threat-actors/IndicatorsTable";
import { MitigationsTable } from "@/components/threat-actors/MitigationsTable";
import { ReportsTable } from "@/components/threat-actors/ReportsTable";
import { sanitizeHtml } from "@/lib/utils";
import {
  Users,
  ArrowLeft,
  Target,
  Bug,
  Wrench,
  Shield,
  ShieldCheck,
  FileText,
  Crosshair,
  AlertTriangle,
  ExternalLink,
  Calendar,
} from "lucide-react";
import { format } from "date-fns";

function LoadingSkeleton() {
  return (
    <div className="space-y-6">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-4 w-48" />
      <Skeleton className="h-40" />
      <div className="grid grid-cols-2 gap-4">
        <Skeleton className="h-48" />
        <Skeleton className="h-48" />
      </div>
    </div>
  );
}

export function ThreatActorDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data, isLoading, error } = useIntrusionSetDetail(id || "");

  if (isLoading) {
    return (
      <AppLayout>
        <div className="max-w-4xl mx-auto">
          <LoadingSkeleton />
        </div>
      </AppLayout>
    );
  }

  if (error || !data) {
    return (
      <AppLayout>
        <div className="max-w-4xl mx-auto">
          <Button variant="ghost" onClick={() => navigate("/threat-actors")} className="mb-4">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Threat Actors
          </Button>
          <Card className="border-dashed">
            <CardContent className="py-12 text-center">
              <Users className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
              <h2 className="text-lg font-semibold mb-2">Threat Actor Not Found</h2>
              <p className="text-sm text-muted-foreground">
                The requested threat actor could not be found.
              </p>
            </CardContent>
          </Card>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <div className="max-w-4xl mx-auto space-y-6 animate-fade-in">
        {/* Back button */}
        <Button variant="ghost" onClick={() => navigate("/threat-actors")} className="mb-2">
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Threat Actors
        </Button>

        {/* Header */}
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-lg bg-purple-500/10 flex items-center justify-center">
              <Users className="w-6 h-6 text-purple-500" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">{data.name}</h1>
              {data.modified && (
                <div className="flex items-center gap-1 text-sm text-muted-foreground">
                  <Calendar className="w-4 h-4" />
                  Last updated: {format(new Date(data.modified), "MMMM d, yyyy")}
                </div>
              )}
            </div>
          </div>
          {data.aliases && data.aliases.length > 0 && (
            <p className="text-muted-foreground">Also known as: {data.aliases.join(", ")}</p>
          )}
        </div>

        <ScrollArea className="h-[calc(100vh-14rem)]">
          <div className="space-y-6 pr-4">
            {/* Description */}
            {data.description && (
              <Card>
                <CardHeader>
                  <CardTitle>Description</CardTitle>
                </CardHeader>
                <CardContent>
                  <div
                    className="text-muted-foreground whitespace-pre-wrap leading-relaxed prose prose-invert max-w-none"
                    dangerouslySetInnerHTML={{ __html: sanitizeHtml(data.description) }}
                  />
                </CardContent>
              </Card>
            )}

            {/* Motivation & Resource Level */}
            {(data.primaryMotivation || data.resourceLevel) && (
              <div className="flex flex-wrap gap-4">
                {data.primaryMotivation && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Primary Motivation</p>
                    <Badge className="capitalize">{data.primaryMotivation.replace(/-/g, " ")}</Badge>
                  </div>
                )}
                {data.resourceLevel && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Resource Level</p>
                    <Badge variant="outline" className="capitalize">
                      {data.resourceLevel.replace(/-/g, " ")}
                    </Badge>
                  </div>
                )}
              </div>
            )}

            {/* Goals */}
            {data.goals && data.goals.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Target className="h-5 w-5" />
                    Goals
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                    {data.goals.map((goal, i) => (
                      <li key={i}>{goal}</li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}

            {/* Victimology */}
            <VictimologyCard countries={data.targetedCountries} sectors={data.targetedSectors} />

            {/* Used Malware */}
            {data.usedMalware.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Bug className="h-5 w-5 text-red-500" />
                    Used Malware
                    <Badge variant="secondary">{data.usedMalware.length}</Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {data.usedMalware.map((malware) => (
                      <Badge key={malware.id} variant="outline" className="bg-red-500/10 text-red-400">
                        {malware.name}
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Used Tools */}
            {data.usedTools.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Wrench className="h-5 w-5" />
                    Used Tools
                    <Badge variant="secondary">{data.usedTools.length}</Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {data.usedTools.map((tool) => (
                      <Badge key={tool.id} variant="outline">
                        {tool.name}
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* MITRE ATT&CK Techniques */}
            {data.usedAttackPatterns.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-5 w-5 text-orange-500" />
                    MITRE ATT&CK Techniques
                    <Badge variant="secondary">{data.usedAttackPatterns.length}</Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <AttackPatternsTable patterns={data.usedAttackPatterns} />
                </CardContent>
              </Card>
            )}

            {/* Mitigating Actions */}
            {data.mitigatingActions && data.mitigatingActions.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <ShieldCheck className="h-5 w-5 text-green-500" />
                    Mitigating Actions
                    <Badge variant="secondary">{data.mitigatingActions.length}</Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <MitigationsTable mitigatingActions={data.mitigatingActions} />
                </CardContent>
              </Card>
            )}

            {/* Related Reports */}
            {data.relatedReports && data.relatedReports.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <FileText className="h-5 w-5 text-primary" />
                    Related Reports
                    <Badge variant="secondary">{data.relatedReports.length}</Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ReportsTable reports={data.relatedReports} />
                </CardContent>
              </Card>
            )}

            {/* Indicators (IOCs) */}
            {data.relatedIndicators && data.relatedIndicators.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Crosshair className="h-5 w-5 text-orange-500" />
                    Indicators of Compromise
                    <Badge variant="secondary">{data.relatedIndicators.length}</Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <IndicatorsTable indicators={data.relatedIndicators} />
                </CardContent>
              </Card>
            )}

            {/* Vulnerabilities */}
            {data.relatedVulnerabilities && data.relatedVulnerabilities.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-yellow-500" />
                    Exploited Vulnerabilities
                    <Badge variant="secondary">{data.relatedVulnerabilities.length}</Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {data.relatedVulnerabilities.map((vuln) => (
                      <Badge
                        key={vuln.id}
                        variant="outline"
                        className="bg-yellow-500/10 text-yellow-400 cursor-pointer"
                        onClick={() => navigate(`/vulnerabilities/${vuln.id}`)}
                      >
                        {vuln.name}
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* External References */}
            {data.externalReferences.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <ExternalLink className="h-5 w-5" />
                    External References
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {data.externalReferences
                      .filter((ref) => ref.url)
                      .map((ref) => (
                        <a
                          key={ref.id}
                          href={ref.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="block text-sm text-primary hover:underline truncate"
                        >
                          {ref.url}
                        </a>
                      ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </ScrollArea>
      </div>
    </AppLayout>
  );
}
