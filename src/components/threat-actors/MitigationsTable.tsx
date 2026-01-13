import { useState } from "react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ChevronLeft, ChevronRight, ExternalLink } from "lucide-react";

interface MitigatingAction {
  id: string;
  mitreId: string;
  attackPatternName: string;
  name: string;
  description: string;
}

interface MitigationsTableProps {
  mitigatingActions: MitigatingAction[];
  itemsPerPage?: number;
}

export function MitigationsTable({ mitigatingActions, itemsPerPage = 10 }: MitigationsTableProps) {
  const [page, setPage] = useState(0);

  // Deduplicate by id
  const uniqueActions = mitigatingActions.filter(
    (action, index, self) => index === self.findIndex((a) => a.id === action.id)
  );

  const totalPages = Math.ceil(uniqueActions.length / itemsPerPage);
  const paginatedItems = uniqueActions.slice(page * itemsPerPage, (page + 1) * itemsPerPage);

  if (uniqueActions.length === 0) return null;

  const getMitreUrl = (mitreId: string) => {
    if (mitreId.startsWith("M")) {
      return `https://attack.mitre.org/mitigations/${mitreId}`;
    }
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
            <TableHead className="w-[100px]">MITRE ID</TableHead>
            <TableHead>Mitigation</TableHead>
            <TableHead className="w-[80px]">Link</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {paginatedItems.map((action) => (
            <TableRow key={action.id} className="hover:bg-muted/50">
              <TableCell>
                {action.mitreId ? (
                  <Badge variant="outline" className="font-mono bg-green-500/10 text-green-600 border-green-500/30">
                    {action.mitreId}
                  </Badge>
                ) : (
                  <span className="text-muted-foreground">-</span>
                )}
              </TableCell>
              <TableCell>
                <div className="space-y-1">
                  <span className="font-medium">{action.name}</span>
                  {action.attackPatternName && (
                    <p className="text-xs text-muted-foreground">Mitigates: {action.attackPatternName}</p>
                  )}
                </div>
              </TableCell>
              <TableCell>
                {action.mitreId && (
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    onClick={() => window.open(getMitreUrl(action.mitreId), "_blank")}
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
