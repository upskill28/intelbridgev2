import { useState } from "react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { ChevronLeft, ChevronRight, FileText } from "lucide-react";
import { format } from "date-fns";

interface Report {
  id: string;
  name: string;
  published?: string;
  created?: string;
  date?: string;
}

interface ReportsTableProps {
  reports: Report[];
  itemsPerPage?: number;
}

export function ReportsTable({ reports, itemsPerPage = 10 }: ReportsTableProps) {
  const [page, setPage] = useState(0);

  // Deduplicate reports by ID
  const uniqueReports = reports.filter((report, index, self) => index === self.findIndex((r) => r.id === report.id));

  const totalPages = Math.ceil(uniqueReports.length / itemsPerPage);
  const paginatedItems = uniqueReports.slice(page * itemsPerPage, (page + 1) * itemsPerPage);

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return "-";
    try {
      return format(new Date(dateStr), "MMM d, yyyy");
    } catch {
      return dateStr;
    }
  };

  if (uniqueReports.length === 0) return null;

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
            <TableHead className="w-[120px]">Date</TableHead>
            <TableHead>Title</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {paginatedItems.map((report) => (
            <TableRow key={report.id} className="hover:bg-muted/50">
              <TableCell className="text-sm text-muted-foreground">
                {formatDate(report.published || report.date || report.created)}
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <FileText className="h-4 w-4 text-primary shrink-0" />
                  <span className="truncate" title={report.name}>
                    {report.name}
                  </span>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
