import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Loader2, X, Building2, Globe, MapPin, Skull, Search, Tag } from "lucide-react";
import { useIntelOptions } from "@/hooks/useIntelOptions";
import type { IntelOption } from "@/hooks/useIntelOptions";
import { useUserIntelProfile } from "@/hooks/useUserIntelProfile";
import type { UserIntelProfileUpdate } from "@/hooks/useUserIntelProfile";
import { cn } from "@/lib/utils";

interface IntelProfileSettingsProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface MultiSelectProps {
  options: IntelOption[];
  selected: string[];
  onChange: (selected: string[]) => void;
  placeholder: string;
  icon: React.ReactNode;
}

function MultiSelect({ options, selected, onChange, placeholder, icon }: MultiSelectProps) {
  const [search, setSearch] = useState("");

  const filteredOptions = options.filter((opt) => opt.name.toLowerCase().includes(search.toLowerCase()));

  const selectedOptions = options.filter((opt) => selected.includes(opt.id));

  const toggleOption = (id: string) => {
    if (selected.includes(id)) {
      onChange(selected.filter((s) => s !== id));
    } else {
      onChange([...selected, id]);
    }
  };

  return (
    <div className="space-y-3">
      {/* Selected items */}
      {selectedOptions.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {selectedOptions.map((opt) => (
            <Badge key={opt.id} variant="secondary" className="gap-1 pr-1">
              {opt.name}
              <button onClick={() => toggleOption(opt.id)} className="ml-1 hover:bg-muted rounded-full p-0.5">
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder={placeholder}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9"
        />
      </div>

      {/* Options list */}
      <ScrollArea className="h-48 rounded-md border">
        <div className="p-2 space-y-1">
          {filteredOptions.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-4">No results found</p>
          ) : (
            filteredOptions.map((opt) => (
              <button
                key={opt.id}
                onClick={() => toggleOption(opt.id)}
                className={cn(
                  "w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-sm text-left transition-colors",
                  selected.includes(opt.id) ? "bg-primary/10 text-primary" : "hover:bg-muted"
                )}
              >
                {icon}
                <span className="truncate">{opt.name}</span>
                {selected.includes(opt.id) && (
                  <Badge variant="default" className="ml-auto text-xs">
                    Selected
                  </Badge>
                )}
              </button>
            ))
          )}
        </div>
      </ScrollArea>
    </div>
  );
}

export function IntelProfileSettings({ open, onOpenChange }: IntelProfileSettingsProps) {
  const { data: options, isLoading: optionsLoading } = useIntelOptions();
  const { profile, updateProfile, isUpdating } = useUserIntelProfile();

  // Local state for form
  const [sectors, setSectors] = useState<string[]>([]);
  const [regions, setRegions] = useState<string[]>([]);
  const [countries, setCountries] = useState<string[]>([]);
  const [threatActors, setThreatActors] = useState<string[]>([]);
  const [keywords, setKeywords] = useState<string[]>([]);
  const [keywordInput, setKeywordInput] = useState("");
  const [alertThreshold, setAlertThreshold] = useState<"critical" | "high" | "medium" | "all">("high");
  const [summaryFrequency, setSummaryFrequency] = useState<"realtime" | "daily" | "weekly">("daily");
  const [showGlobalThreats, setShowGlobalThreats] = useState(true);

  // Load existing profile when dialog opens
  useEffect(() => {
    if (profile) {
      setSectors(profile.sectors || []);
      setRegions(profile.regions || []);
      setCountries(profile.countries || []);
      setThreatActors(profile.threat_actors || []);
      setKeywords(profile.keywords || []);
      setAlertThreshold(profile.alert_threshold || "high");
      setSummaryFrequency(profile.summary_frequency || "daily");
      setShowGlobalThreats(profile.show_global_threats ?? true);
    }
  }, [profile, open]);

  const addKeyword = () => {
    const keyword = keywordInput.trim().toLowerCase();
    if (keyword && !keywords.includes(keyword)) {
      setKeywords([...keywords, keyword]);
      setKeywordInput("");
    }
  };

  const removeKeyword = (keyword: string) => {
    setKeywords(keywords.filter((k) => k !== keyword));
  };

  const handleSave = async () => {
    const update: UserIntelProfileUpdate = {
      sectors,
      regions,
      countries,
      threat_actors: threatActors,
      keywords,
      alert_threshold: alertThreshold,
      summary_frequency: summaryFrequency,
      show_global_threats: showGlobalThreats,
    };

    await updateProfile(update);
    onOpenChange(false);
  };

  if (optionsLoading) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-2xl">
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle>Intel Profile Settings</DialogTitle>
          <DialogDescription>
            Customize your threat intelligence feed. We'll prioritize threats relevant to your organization.
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="sectors" className="flex-1 overflow-hidden">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="sectors" className="gap-1">
              <Building2 className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">Sectors</span>
            </TabsTrigger>
            <TabsTrigger value="geography" className="gap-1">
              <Globe className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">Geography</span>
            </TabsTrigger>
            <TabsTrigger value="watchlist" className="gap-1">
              <Skull className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">Watchlist</span>
            </TabsTrigger>
            <TabsTrigger value="preferences" className="gap-1">
              <Tag className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">Preferences</span>
            </TabsTrigger>
          </TabsList>

          <ScrollArea className="flex-1 mt-4">
            <TabsContent value="sectors" className="mt-0 px-1">
              <div className="space-y-4">
                <div>
                  <Label className="text-base font-medium">Industry Sectors</Label>
                  <p className="text-sm text-muted-foreground mb-3">
                    Select the sectors your organization operates in. We'll highlight threats targeting these
                    industries.
                  </p>
                  <MultiSelect
                    options={options?.sectors || []}
                    selected={sectors}
                    onChange={setSectors}
                    placeholder="Search sectors..."
                    icon={<Building2 className="h-4 w-4 text-muted-foreground" />}
                  />
                </div>
              </div>
            </TabsContent>

            <TabsContent value="geography" className="mt-0 px-1">
              <div className="space-y-6">
                <div>
                  <Label className="text-base font-medium">Regions</Label>
                  <p className="text-sm text-muted-foreground mb-3">Select broad geographic regions of interest.</p>
                  <MultiSelect
                    options={options?.regions || []}
                    selected={regions}
                    onChange={setRegions}
                    placeholder="Search regions..."
                    icon={<MapPin className="h-4 w-4 text-muted-foreground" />}
                  />
                </div>

                <div>
                  <Label className="text-base font-medium">Countries</Label>
                  <p className="text-sm text-muted-foreground mb-3">Select specific countries to monitor.</p>
                  <MultiSelect
                    options={options?.countries || []}
                    selected={countries}
                    onChange={setCountries}
                    placeholder="Search countries..."
                    icon={<Globe className="h-4 w-4 text-muted-foreground" />}
                  />
                </div>
              </div>
            </TabsContent>

            <TabsContent value="watchlist" className="mt-0 px-1">
              <div className="space-y-6">
                <div>
                  <Label className="text-base font-medium">Threat Actors</Label>
                  <p className="text-sm text-muted-foreground mb-3">Track specific threat actors or groups.</p>
                  <MultiSelect
                    options={options?.threatActors || []}
                    selected={threatActors}
                    onChange={setThreatActors}
                    placeholder="Search threat actors..."
                    icon={<Skull className="h-4 w-4 text-muted-foreground" />}
                  />
                </div>

                <div>
                  <Label className="text-base font-medium">Keywords</Label>
                  <p className="text-sm text-muted-foreground mb-3">
                    Add keywords to watch for in reports (e.g., product names, technologies).
                  </p>
                  <div className="flex gap-2 mb-3">
                    <Input
                      placeholder="Add a keyword..."
                      value={keywordInput}
                      onChange={(e) => setKeywordInput(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && addKeyword()}
                    />
                    <Button onClick={addKeyword} variant="secondary">
                      Add
                    </Button>
                  </div>
                  {keywords.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {keywords.map((keyword) => (
                        <Badge key={keyword} variant="secondary" className="gap-1 pr-1">
                          {keyword}
                          <button
                            onClick={() => removeKeyword(keyword)}
                            className="ml-1 hover:bg-muted rounded-full p-0.5"
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </Badge>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="preferences" className="mt-0 px-1">
              <div className="space-y-6">
                <div className="space-y-3">
                  <Label className="text-base font-medium">Alert Threshold</Label>
                  <p className="text-sm text-muted-foreground">Minimum severity level for highlighting threats.</p>
                  <Select value={alertThreshold} onValueChange={(v) => setAlertThreshold(v as any)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical only</SelectItem>
                      <SelectItem value="high">High and above</SelectItem>
                      <SelectItem value="medium">Medium and above</SelectItem>
                      <SelectItem value="all">All severities</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-3">
                  <Label className="text-base font-medium">Summary Frequency</Label>
                  <p className="text-sm text-muted-foreground">How often to generate AI briefings.</p>
                  <Select value={summaryFrequency} onValueChange={(v) => setSummaryFrequency(v as any)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="realtime">Real-time updates</SelectItem>
                      <SelectItem value="daily">Daily digest</SelectItem>
                      <SelectItem value="weekly">Weekly summary</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex items-center justify-between rounded-lg border p-4">
                  <div className="space-y-0.5">
                    <Label className="text-base font-medium">Include Global Threats</Label>
                    <p className="text-sm text-muted-foreground">
                      Show major threats even if they don't match your filters.
                    </p>
                  </div>
                  <Switch checked={showGlobalThreats} onCheckedChange={setShowGlobalThreats} />
                </div>
              </div>
            </TabsContent>
          </ScrollArea>
        </Tabs>

        <DialogFooter className="mt-4">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={isUpdating}>
            {isUpdating && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Save Profile
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
