import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AppLayout } from "@/components/layout/AppLayout";
import { useVulnerabilities, getSeverityColor } from "@/hooks/useVulnerabilities";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  AlertTriangle,
  Search,
  ChevronLeft,
  ChevronRight,
  Calendar,
  Shield,
  TrendingUp,
} from "lucide-react";
import { format } from "date-fns";

function VulnerabilityCard({
  vuln,
  onClick,
}: {
  vuln: {
    id: string;
    cve: string;
    description: string;
    severity: string;
    modified: string;
    cvssScore: number | null;
    cisaKev: boolean;
    epssScore: number | null;
  };
  onClick: () => void;
}) {
  return (
    <Card
      className="hover:bg-muted/30 transition-colors cursor-pointer"
      onClick={onClick}
    >
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-10 h-10 rounded-lg bg-yellow-500/10 flex items-center justify-center shrink-0">
                <AlertTriangle className="w-5 h-5 text-yellow-500" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <h3 className="font-semibold">{vuln.cve}</h3>
                  {vuln.cisaKev && (
                    <Badge variant="destructive" className="text-xs">
                      KEV
                    </Badge>
                  )}
                  <Badge className={getSeverityColor(vuln.severity)}>
                    {vuln.severity.toUpperCase()}
                  </Badge>
                </div>
              </div>
            </div>

            {vuln.description && (
              <p className="text-sm text-muted-foreground line-clamp-2 mb-3">
                {vuln.description}
              </p>
            )}

            <div className="flex flex-wrap gap-3">
              {vuln.cvssScore !== null && (
                <div className="flex items-center gap-1 text-xs text-muted-foreground">
                  <Shield className="w-3 h-3" />
                  CVSS: {vuln.cvssScore.toFixed(1)}
                </div>
              )}
              {vuln.epssScore !== null && (
                <div className="flex items-center gap-1 text-xs text-muted-foreground">
                  <TrendingUp className="w-3 h-3" />
                  EPSS: {(vuln.epssScore * 100).toFixed(2)}%
                </div>
              )}
            </div>
          </div>

          <div className="text-right shrink-0">
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <Calendar className="w-3 h-3" />
              {vuln.modified ? format(new Date(vuln.modified), "MMM d, yyyy") : "-"}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function LoadingSkeleton() {
  return (
    <div className="space-y-4">
      {[...Array(5)].map((_, i) => (
        <Skeleton key={i} className="h-32" />
      ))}
    </div>
  );
}

export function Vulnerabilities() {
  const navigate = useNavigate();
  const [searchInput, setSearchInput] = useState("");

  const {
    data,
    pageInfo,
    isLoading,
    error,
    search,
    nextPage,
    previousPage,
    hasPreviousPage,
  } = useVulnerabilities(25);

  const handleSearch = (value: string) => {
    setSearchInput(value);
    search({ search: value || undefined });
  };

  return (
    <AppLayout>
      <div className="space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-3">
              <AlertTriangle className="w-6 h-6 text-yellow-500" />
              Vulnerabilities
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              CVEs and security vulnerabilities tracked in the intelligence database
            </p>
          </div>
          {pageInfo && (
            <Badge variant="secondary">{pageInfo.globalCount} CVEs</Badge>
          )}
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            type="text"
            placeholder="Search CVEs (e.g. CVE-2024-1234)..."
            value={searchInput}
            onChange={(e) => handleSearch(e.target.value)}
            className="pl-10"
          />
        </div>

        {/* Results */}
        {isLoading ? (
          <LoadingSkeleton />
        ) : error ? (
          <Card className="border-dashed">
            <CardContent className="py-12 text-center">
              <AlertTriangle className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
              <h2 className="text-lg font-semibold mb-2">Error Loading Data</h2>
              <p className="text-sm text-muted-foreground">
                Failed to load vulnerabilities. Please try again.
              </p>
            </CardContent>
          </Card>
        ) : data.length === 0 ? (
          <Card className="border-dashed">
            <CardContent className="py-12 text-center">
              <AlertTriangle className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
              <h2 className="text-lg font-semibold mb-2">No Vulnerabilities Found</h2>
              <p className="text-sm text-muted-foreground">
                {searchInput ? "Try adjusting your search query" : "No vulnerabilities available"}
              </p>
            </CardContent>
          </Card>
        ) : (
          <>
            <ScrollArea className="h-[calc(100vh-18rem)]">
              <div className="space-y-3 pr-4">
                {data.map((vuln) => (
                  <VulnerabilityCard
                    key={vuln.id}
                    vuln={vuln}
                    onClick={() => navigate(`/vulnerabilities/${vuln.id}`)}
                  />
                ))}
              </div>
            </ScrollArea>

            {/* Pagination */}
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                Showing {data.length} of {pageInfo?.globalCount} CVEs
              </p>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={previousPage}
                  disabled={!hasPreviousPage}
                >
                  <ChevronLeft className="w-4 h-4 mr-1" />
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={nextPage}
                  disabled={!pageInfo?.hasNextPage}
                >
                  Next
                  <ChevronRight className="w-4 h-4 ml-1" />
                </Button>
              </div>
            </div>
          </>
        )}
      </div>
    </AppLayout>
  );
}
