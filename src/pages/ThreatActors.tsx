import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AppLayout } from "@/components/layout/AppLayout";
import { useIntrusionSets } from "@/hooks/useIntrusionSets";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Users,
  Search,
  ChevronLeft,
  ChevronRight,
  Globe,
  Building,
  Calendar,
} from "lucide-react";
import { format } from "date-fns";

function ThreatActorCard({
  actor,
  onClick,
}: {
  actor: {
    id: string;
    name: string;
    description: string;
    aliases: string[];
    modified: string;
    targetedCountries: { id: string; name: string }[];
    targetedSectors: { id: string; name: string }[];
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
              <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center shrink-0">
                <Users className="w-5 h-5 text-purple-500" />
              </div>
              <div className="min-w-0">
                <h3 className="font-semibold truncate">{actor.name}</h3>
                {actor.aliases.length > 0 && (
                  <p className="text-xs text-muted-foreground truncate">
                    aka {actor.aliases.slice(0, 3).join(", ")}
                    {actor.aliases.length > 3 && ` +${actor.aliases.length - 3} more`}
                  </p>
                )}
              </div>
            </div>

            {actor.description && (
              <p className="text-sm text-muted-foreground line-clamp-2 mb-3">
                {actor.description}
              </p>
            )}

            <div className="flex flex-wrap gap-2">
              {actor.targetedSectors.slice(0, 3).map((sector) => (
                <Badge key={sector.id} variant="outline" className="text-xs">
                  <Building className="w-3 h-3 mr-1" />
                  {sector.name}
                </Badge>
              ))}
              {actor.targetedCountries.slice(0, 2).map((country) => (
                <Badge key={country.id} variant="secondary" className="text-xs">
                  <Globe className="w-3 h-3 mr-1" />
                  {country.name}
                </Badge>
              ))}
            </div>
          </div>

          <div className="text-right shrink-0">
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <Calendar className="w-3 h-3" />
              {actor.modified ? format(new Date(actor.modified), "MMM d, yyyy") : "-"}
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

export function ThreatActors() {
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const [cursorHistory, setCursorHistory] = useState<string[]>([]);

  const { data, isLoading, error } = useIntrusionSets(25, cursor, search || undefined);

  const handleNext = () => {
    if (data?.pageInfo.endCursor) {
      setCursorHistory((prev) => [...prev, cursor || ""]);
      setCursor(data.pageInfo.endCursor);
    }
  };

  const handlePrev = () => {
    if (cursorHistory.length > 0) {
      const prev = cursorHistory[cursorHistory.length - 1];
      setCursorHistory((h) => h.slice(0, -1));
      setCursor(prev || null);
    }
  };

  const handleSearch = (value: string) => {
    setSearch(value);
    setCursor(null);
    setCursorHistory([]);
  };

  return (
    <AppLayout>
      <div className="space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-3">
              <Users className="w-6 h-6 text-purple-500" />
              Threat Actors
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              APT groups and threat actors tracked in the intelligence database
            </p>
          </div>
          {data?.pageInfo && (
            <Badge variant="secondary">{data.pageInfo.globalCount} actors</Badge>
          )}
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            type="text"
            placeholder="Search threat actors..."
            value={search}
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
              <Users className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
              <h2 className="text-lg font-semibold mb-2">Error Loading Data</h2>
              <p className="text-sm text-muted-foreground">
                Failed to load threat actors. Please try again.
              </p>
            </CardContent>
          </Card>
        ) : data?.data.length === 0 ? (
          <Card className="border-dashed">
            <CardContent className="py-12 text-center">
              <Users className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
              <h2 className="text-lg font-semibold mb-2">No Threat Actors Found</h2>
              <p className="text-sm text-muted-foreground">
                {search ? "Try adjusting your search query" : "No threat actors available"}
              </p>
            </CardContent>
          </Card>
        ) : (
          <>
            <ScrollArea className="h-[calc(100vh-18rem)]">
              <div className="space-y-3 pr-4">
                {data?.data.map((actor) => (
                  <ThreatActorCard
                    key={actor.id}
                    actor={actor}
                    onClick={() => navigate(`/threat-actors/${actor.id}`)}
                  />
                ))}
              </div>
            </ScrollArea>

            {/* Pagination */}
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                Showing {data?.data.length} of {data?.pageInfo.globalCount} actors
              </p>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handlePrev}
                  disabled={cursorHistory.length === 0}
                >
                  <ChevronLeft className="w-4 h-4 mr-1" />
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleNext}
                  disabled={!data?.pageInfo.hasNextPage}
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
