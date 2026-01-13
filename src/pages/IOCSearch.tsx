import { useState } from "react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import {
  useIOCSearch,
  useBulkIOCLookup,
  getIOCTypeColor,
  getIOCType,
} from "@/hooks/useIOCSearch";
import type { IOCResult, IOCSearchParams, BulkIOCResult } from "@/hooks/useIOCSearch";
import {
  Search,
  Copy,
  Check,
  Loader2,
  AlertTriangle,
  Shield,
  ExternalLink,
  FileSearch,
  List,
  Upload,
  Target,
} from "lucide-react";
import { format } from "date-fns";
import { toast } from "sonner";

type IOCType = IOCSearchParams["type"];

function IOCResultCard({ result }: { result: IOCResult }) {
  const [copied, setCopied] = useState(false);
  const iocType = getIOCType(result.pattern, result.observableType);
  const displayValue = result.observableValue || result.name;

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(displayValue);
    setCopied(true);
    toast.success("Copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Card className="hover:bg-muted/30 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <Badge className={getIOCTypeColor(iocType)} variant="outline">
                {iocType}
              </Badge>
              {result.score !== null && (
                <Badge
                  variant="outline"
                  className={
                    result.score >= 70
                      ? "bg-red-500/20 text-red-400 border-red-500/30"
                      : result.score >= 40
                      ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                      : "bg-green-500/20 text-green-400 border-green-500/30"
                  }
                >
                  Score: {result.score}
                </Badge>
              )}
            </div>

            <div className="mt-2 flex items-center gap-2">
              <code className="text-sm font-mono bg-muted px-2 py-1 rounded break-all">
                {displayValue}
              </code>
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6 shrink-0"
                onClick={copyToClipboard}
              >
                {copied ? (
                  <Check className="h-3 w-3 text-green-500" />
                ) : (
                  <Copy className="h-3 w-3" />
                )}
              </Button>
            </div>

            {result.description && (
              <p className="text-sm text-muted-foreground mt-2 line-clamp-2">
                {result.description}
              </p>
            )}

            {/* Related Entities */}
            <div className="flex flex-wrap gap-2 mt-3">
              {result.relatedThreatActors.map((actor) => (
                <Badge key={actor.id} variant="secondary" className="text-xs">
                  {actor.name}
                </Badge>
              ))}
              {result.relatedMalware.map((malware) => (
                <Badge key={malware.id} variant="secondary" className="text-xs bg-orange-500/10">
                  {malware.name}
                </Badge>
              ))}
              {result.relatedCampaigns.map((campaign) => (
                <Badge key={campaign.id} variant="secondary" className="text-xs bg-purple-500/10">
                  {campaign.name}
                </Badge>
              ))}
            </div>

            {/* Validity Period */}
            {(result.validFrom || result.validUntil) && (
              <p className="text-xs text-muted-foreground mt-2">
                {result.validFrom && `Valid from ${format(new Date(result.validFrom), "MMM d, yyyy")}`}
                {result.validFrom && result.validUntil && " - "}
                {result.validUntil && `until ${format(new Date(result.validUntil), "MMM d, yyyy")}`}
              </p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function BulkResultRow({ result }: { result: BulkIOCResult }) {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(result.query);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="flex items-center gap-3 py-2 px-3 rounded-lg hover:bg-muted/50">
      <div className="flex-1 min-w-0">
        <code className="text-sm font-mono break-all">{result.query}</code>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {result.found ? (
          <>
            <Badge className="bg-green-500/20 text-green-400 border-green-500/30" variant="outline">
              Found
            </Badge>
            {result.result?.score !== null && (
              <Badge variant="outline">Score: {result.result?.score}</Badge>
            )}
          </>
        ) : (
          <Badge className="bg-muted text-muted-foreground" variant="outline">
            Not Found
          </Badge>
        )}
        <Button variant="ghost" size="icon" className="h-6 w-6" onClick={copyToClipboard}>
          {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
        </Button>
      </div>
    </div>
  );
}

function SearchTab() {
  const [searchQuery, setSearchQuery] = useState("");
  const [searchType, setSearchType] = useState<IOCType>("all");
  const [activeQuery, setActiveQuery] = useState("");

  const { data: results, isLoading, error } = useIOCSearch({
    query: activeQuery,
    type: searchType,
    limit: 50,
  });

  const handleSearch = () => {
    if (searchQuery.trim()) {
      setActiveQuery(searchQuery.trim());
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      handleSearch();
    }
  };

  return (
    <div className="space-y-6">
      {/* Search Controls */}
      <Card>
        <CardContent className="p-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="flex-1">
              <Input
                placeholder="Search for IP, domain, URL, hash, or email..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                className="h-10"
              />
            </div>
            <Select value={searchType} onValueChange={(v) => setSearchType(v as IOCType)}>
              <SelectTrigger className="w-full sm:w-40">
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="ipv4">IPv4</SelectItem>
                <SelectItem value="ipv6">IPv6</SelectItem>
                <SelectItem value="domain">Domain</SelectItem>
                <SelectItem value="url">URL</SelectItem>
                <SelectItem value="file-hash">File Hash</SelectItem>
                <SelectItem value="email">Email</SelectItem>
              </SelectContent>
            </Select>
            <Button onClick={handleSearch} disabled={!searchQuery.trim()}>
              <Search className="w-4 h-4 mr-2" />
              Search
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      {isLoading ? (
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <Skeleton key={i} className="h-32" />
          ))}
        </div>
      ) : error ? (
        <Card className="border-dashed">
          <CardContent className="py-12 text-center">
            <AlertTriangle className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
            <h2 className="text-lg font-semibold mb-2">Search Error</h2>
            <p className="text-sm text-muted-foreground">
              Failed to search indicators. Please try again.
            </p>
          </CardContent>
        </Card>
      ) : !activeQuery ? (
        <Card className="border-dashed">
          <CardContent className="py-12 text-center">
            <FileSearch className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
            <h2 className="text-lg font-semibold mb-2">Search for Indicators</h2>
            <p className="text-sm text-muted-foreground">
              Enter an IP address, domain, URL, file hash, or email address to search the threat
              intelligence database.
            </p>
          </CardContent>
        </Card>
      ) : results && results.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="py-12 text-center">
            <Shield className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
            <h2 className="text-lg font-semibold mb-2">No Results Found</h2>
            <p className="text-sm text-muted-foreground">
              No indicators matching "{activeQuery}" were found in the database.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Found {results?.length || 0} indicator{results?.length !== 1 ? "s" : ""}
            </p>
          </div>
          <ScrollArea className="h-[calc(100vh-24rem)]">
            <div className="space-y-3 pr-4">
              {results?.map((result) => (
                <IOCResultCard key={result.id} result={result} />
              ))}
            </div>
          </ScrollArea>
        </div>
      )}
    </div>
  );
}

function BulkLookupTab() {
  const [inputText, setInputText] = useState("");
  const [results, setResults] = useState<BulkIOCResult[] | null>(null);
  const bulkLookup = useBulkIOCLookup();

  const handleLookup = async () => {
    const queries = inputText
      .split(/[\n,]/)
      .map((q) => q.trim())
      .filter((q) => q.length > 0);

    if (queries.length === 0) {
      toast.error("Please enter at least one indicator");
      return;
    }

    if (queries.length > 100) {
      toast.error("Maximum 100 indicators per lookup");
      return;
    }

    try {
      const lookupResults = await bulkLookup.mutateAsync(queries);
      setResults(lookupResults);
    } catch (error) {
      toast.error("Bulk lookup failed");
    }
  };

  const foundCount = results?.filter((r) => r.found).length || 0;
  const notFoundCount = results?.filter((r) => !r.found).length || 0;

  const exportResults = () => {
    if (!results) return;

    const csv = [
      "Indicator,Found,Score,Type",
      ...results.map((r) => {
        const type = r.result ? getIOCType(r.result.pattern, r.result.observableType) : "";
        return `"${r.query}",${r.found},${r.result?.score || ""},${type}`;
      }),
    ].join("\n");

    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ioc-lookup-${format(new Date(), "yyyy-MM-dd-HHmm")}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Results exported");
  };

  return (
    <div className="space-y-6">
      {/* Input */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Bulk IOC Lookup</CardTitle>
          <CardDescription>
            Enter multiple indicators (one per line or comma-separated) to check against the threat
            intelligence database. Maximum 100 indicators per lookup.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Textarea
            placeholder="Enter indicators here...&#10;192.168.1.1&#10;malware.com&#10;abc123hash..."
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            rows={8}
            className="font-mono text-sm"
          />
          <div className="flex justify-end gap-2">
            <Button
              variant="outline"
              onClick={() => {
                setInputText("");
                setResults(null);
              }}
            >
              Clear
            </Button>
            <Button onClick={handleLookup} disabled={bulkLookup.isPending || !inputText.trim()}>
              {bulkLookup.isPending ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Upload className="w-4 h-4 mr-2" />
              )}
              Lookup
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      {results && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base">Lookup Results</CardTitle>
                <CardDescription>
                  <span className="text-green-500">{foundCount} found</span>
                  {" · "}
                  <span className="text-muted-foreground">{notFoundCount} not found</span>
                </CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={exportResults}>
                <ExternalLink className="w-4 h-4 mr-2" />
                Export CSV
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[calc(100vh-32rem)]">
              <div className="space-y-1">
                {results.map((result, idx) => (
                  <BulkResultRow key={idx} result={result} />
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export function IOCSearch() {
  return (
    <AppLayout>
      <div className="max-w-4xl mx-auto space-y-6 animate-fade-in">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <Target className="w-6 h-6" />
            IOC Search
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Search and lookup indicators of compromise in the threat intelligence database
          </p>
        </div>

        {/* Tabs */}
        <Tabs defaultValue="search" className="space-y-6">
          <TabsList>
            <TabsTrigger value="search" className="gap-2">
              <FileSearch className="w-4 h-4" />
              Search
            </TabsTrigger>
            <TabsTrigger value="bulk" className="gap-2">
              <List className="w-4 h-4" />
              Bulk Lookup
            </TabsTrigger>
          </TabsList>

          <TabsContent value="search">
            <SearchTab />
          </TabsContent>

          <TabsContent value="bulk">
            <BulkLookupTab />
          </TabsContent>
        </Tabs>
      </div>
    </AppLayout>
  );
}
