import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Globe, Building, MapPin } from "lucide-react";

interface Country {
  id: string;
  name: string;
}

interface Sector {
  id: string;
  name: string;
}

interface VictimologyCardProps {
  countries?: Country[];
  sectors?: Sector[];
  showTitle?: boolean;
}

export function VictimologyCard({ countries = [], sectors = [], showTitle = true }: VictimologyCardProps) {
  // Deduplicate by ID
  const uniqueCountries = countries.filter(
    (country, index, self) => index === self.findIndex((c) => c.id === country.id)
  );

  const uniqueSectors = sectors.filter(
    (sector, index, self) => index === self.findIndex((s) => s.id === sector.id)
  );

  if (uniqueCountries.length === 0 && uniqueSectors.length === 0) return null;

  return (
    <Card>
      {showTitle && (
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MapPin className="h-5 w-5 text-red-500" />
            Victimology
          </CardTitle>
        </CardHeader>
      )}
      <CardContent className={showTitle ? "" : "pt-6"}>
        <div className="space-y-6">
          {/* Targeted Sectors */}
          {uniqueSectors.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Building className="h-4 w-4 text-orange-500" />
                <h4 className="text-sm font-medium">Targeted Sectors</h4>
                <Badge variant="secondary" className="text-xs">
                  {uniqueSectors.length}
                </Badge>
              </div>
              <div className="flex flex-wrap gap-2">
                {uniqueSectors.map((sector) => (
                  <Badge key={sector.id} variant="outline" className="whitespace-nowrap">
                    <Building className="h-3 w-3 mr-1" />
                    {sector.name}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Targeted Countries */}
          {uniqueCountries.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Globe className="h-4 w-4 text-blue-500" />
                <h4 className="text-sm font-medium">Targeted Countries</h4>
                <Badge variant="secondary" className="text-xs">
                  {uniqueCountries.length}
                </Badge>
              </div>
              <div className="flex flex-wrap gap-2">
                {uniqueCountries.map((country) => (
                  <Badge key={country.id} variant="outline" className="whitespace-nowrap">
                    <Globe className="h-3 w-3 mr-1" />
                    {country.name}
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
