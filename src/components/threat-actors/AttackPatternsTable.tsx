import { useState } from "react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ChevronLeft, ChevronRight, ExternalLink } from "lucide-react";

interface AttackPattern {
  id: string;
  name: string;
  mitreId?: string;
}

interface AttackPatternsTableProps {
  patterns: AttackPattern[];
  itemsPerPage?: number;
}

export function AttackPatternsTable({ patterns, itemsPerPage = 10 }: AttackPatternsTableProps) {
  const [page, setPage] = useState(0);

  const totalPages = Math.ceil(patterns.length / itemsPerPage);
  const paginatedItems = patterns.slice(page * itemsPerPage, (page + 1) * itemsPerPage);

  if (patterns.length === 0) return null;

  const getMitreUrl = (mitreId: string) => {
    return `https://attack.mitre.org/techniques/${mitreId.replace(".", "/")}`;
  };

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
            <TableHead className="w-[120px]">MITRE ID</TableHead>
            <TableHead>Technique</TableHead>
            <TableHead className="w-[80px]">Link</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {paginatedItems.map((pattern) => (
            <TableRow key={pattern.id} className="hover:bg-muted/50">
              <TableCell>
                {pattern.mitreId ? (
                  <Badge variant="destructive" className="font-mono">
                    {pattern.mitreId}
                  </Badge>
                ) : (
                  <span className="text-muted-foreground">-</span>
                )}
              </TableCell>
              <TableCell className="font-medium">{pattern.name}</TableCell>
              <TableCell>
                {pattern.mitreId && (
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    onClick={() => window.open(getMitreUrl(pattern.mitreId!), "_blank")}
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                  </Button>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
