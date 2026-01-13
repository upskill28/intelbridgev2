import { useState } from "react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ChevronLeft, ChevronRight, Copy, Check } from "lucide-react";
import { toast } from "sonner";
import { extractIndicatorType, getIndicatorTypeColor } from "@/lib/utils";
import { format } from "date-fns";

interface Indicator {
  id: string;
  name?: string;
  pattern?: string;
  observableType?: string | null;
  score?: number | null;
  created?: string | null;
}

interface IndicatorsTableProps {
  indicators: Indicator[];
  itemsPerPage?: number;
}

export function IndicatorsTable({ indicators, itemsPerPage = 10 }: IndicatorsTableProps) {
  const [page, setPage] = useState(0);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const sortedIndicators = [...indicators].sort((a, b) => {
    if (!a.created && !b.created) return 0;
    if (!a.created) return 1;
    if (!b.created) return -1;
    return new Date(b.created).getTime() - new Date(a.created).getTime();
  });

  const totalPages = Math.ceil(sortedIndicators.length / itemsPerPage);
  const paginatedItems = sortedIndicators.slice(page * itemsPerPage, (page + 1) * itemsPerPage);

  const copyToClipboard = (text: string, id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    toast.success("Copied to clipboard");
    setTimeout(() => setCopiedId(null), 2000);
  };

  if (indicators.length === 0) return null;

  return (
    <div className="space-y-3">
      {totalPages > 1 && (
        <div className="flex items-center justify-end gap-1 text-xs text-muted-foreground">
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
          >
            <ChevronLeft className="h-3.5 w-3.5" />
          </Button>
          <span>
            {page + 1}/{totalPages}
          </span>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
          >
            <ChevronRight className="h-3.5 w-3.5" />
          </Button>
        </div>
      )}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Indicator</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Date Added</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {paginatedItems.map((indicator) => {
            const displayValue = indicator.pattern || indicator.name || "";
            const type = extractIndicatorType(indicator.pattern || null, indicator.observableType || null);

            return (
              <TableRow key={indicator.id} className="group hover:bg-muted/50">
                <TableCell className="font-mono text-sm max-w-[400px]">
                  <div className="flex items-center gap-2">
                    <span className="truncate" title={displayValue}>
                      {indicator.name || displayValue?.substring(0, 60)}
                    </span>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
                      onClick={(e) => copyToClipboard(displayValue, indicator.id, e)}
                    >
                      {copiedId === indicator.id ? (
                        <Check className="h-3 w-3 text-green-500" />
                      ) : (
                        <Copy className="h-3 w-3" />
                      )}
                    </Button>
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className={getIndicatorTypeColor(type)}>
                    {type}
                  </Badge>
                </TableCell>
                <TableCell className="text-sm text-muted-foreground whitespace-nowrap">
                  {indicator.created ? format(new Date(indicator.created), "MMM d, yyyy") : "-"}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
