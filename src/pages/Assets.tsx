import { useState } from "react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAssets } from "@/hooks/useAssets";
import type { Asset, AssetCreate } from "@/hooks/useAssets";
import {
  Globe,
  Mail,
  Plus,
  Trash2,
  Loader2,
  Shield,
  AlertTriangle,
  Package,
} from "lucide-react";
import { format } from "date-fns";

function AssetCard({
  asset,
  onDelete,
  isDeleting,
}: {
  asset: Asset;
  onDelete: (id: string) => void;
  isDeleting: boolean;
}) {
  const Icon = asset.asset_type === "domain" ? Globe : Mail;
  const typeLabel = asset.asset_type === "domain" ? "Domain" : "Email Domain";

  return (
    <Card className="hover:bg-muted/30 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
              <Icon className="w-5 h-5 text-primary" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-semibold">{asset.value}</h3>
                <Badge variant={asset.is_active ? "default" : "secondary"}>
                  {asset.is_active ? "Active" : "Inactive"}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {typeLabel} - Added {format(new Date(asset.created_at), "MMM d, yyyy")}
              </p>
              {asset.description && (
                <p className="text-sm text-muted-foreground mt-2">{asset.description}</p>
              )}
            </div>
          </div>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => onDelete(asset.id)}
            disabled={isDeleting}
          >
            {isDeleting ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Trash2 className="w-4 h-4 text-muted-foreground hover:text-destructive" />
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function AddAssetDialog({
  open,
  onOpenChange,
  onSubmit,
  isSubmitting,
  defaultType,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (asset: AssetCreate) => Promise<void>;
  isSubmitting: boolean;
  defaultType: "domain" | "email_domain";
}) {
  const [assetType, setAssetType] = useState<"domain" | "email_domain">(defaultType);
  const [value, setValue] = useState("");
  const [description, setDescription] = useState("");

  const handleSubmit = async () => {
    if (!value.trim()) return;
    await onSubmit({
      asset_type: assetType,
      value: value.trim(),
      description: description.trim() || undefined,
    });
    setValue("");
    setDescription("");
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add Asset</DialogTitle>
          <DialogDescription>
            Register a domain or email domain to monitor for threats and breaches.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label>Asset Type</Label>
            <Tabs value={assetType} onValueChange={(v) => setAssetType(v as any)}>
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="domain" className="gap-2">
                  <Globe className="w-4 h-4" />
                  Domain
                </TabsTrigger>
                <TabsTrigger value="email_domain" className="gap-2">
                  <Mail className="w-4 h-4" />
                  Email Domain
                </TabsTrigger>
              </TabsList>
            </Tabs>
          </div>

          <div className="space-y-2">
            <Label htmlFor="value">
              {assetType === "domain" ? "Domain Name" : "Email Domain"}
            </Label>
            <Input
              id="value"
              placeholder={assetType === "domain" ? "example.com" : "company.com"}
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              {assetType === "domain"
                ? "Enter the domain you want to monitor for mentions in threat intelligence."
                : "Enter your business email domain to track in breach databases."}
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="description">Description (Optional)</Label>
            <Input
              id="description"
              placeholder="Main company website"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!value.trim() || isSubmitting}>
            {isSubmitting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            Add Asset
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function LoadingSkeleton() {
  return (
    <div className="space-y-4">
      {[...Array(3)].map((_, i) => (
        <Skeleton key={i} className="h-24" />
      ))}
    </div>
  );
}

export function Assets() {
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [addDialogType, setAddDialogType] = useState<"domain" | "email_domain">("domain");
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const { domains, emailDomains, isLoading, error, addAsset, isAdding, removeAsset } = useAssets();

  const handleAddAsset = async (asset: AssetCreate) => {
    await addAsset(asset);
  };

  const handleDelete = async (id: string) => {
    setDeletingId(id);
    try {
      await removeAsset(id);
    } finally {
      setDeletingId(null);
    }
  };

  const openAddDialog = (type: "domain" | "email_domain") => {
    setAddDialogType(type);
    setAddDialogOpen(true);
  };

  return (
    <AppLayout>
      <div className="max-w-4xl mx-auto space-y-6 animate-fade-in">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-3">
              <Package className="w-6 h-6" />
              Asset Inventory
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Register your domains and email addresses to monitor for threats
            </p>
          </div>
        </div>

        {/* Overview Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
                  <Globe className="w-5 h-5 text-blue-500" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{domains.length}</p>
                  <p className="text-sm text-muted-foreground">Domains</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center">
                  <Mail className="w-5 h-5 text-green-500" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{emailDomains.length}</p>
                  <p className="text-sm text-muted-foreground">Email Domains</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-primary" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{domains.length + emailDomains.length}</p>
                  <p className="text-sm text-muted-foreground">Total Monitored</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Asset Lists */}
        {isLoading ? (
          <LoadingSkeleton />
        ) : error ? (
          <Card className="border-dashed">
            <CardContent className="py-12 text-center">
              <AlertTriangle className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
              <h2 className="text-lg font-semibold mb-2">Error Loading Assets</h2>
              <p className="text-sm text-muted-foreground">Failed to load your assets. Please try again.</p>
            </CardContent>
          </Card>
        ) : (
          <Tabs defaultValue="domains" className="space-y-4">
            <TabsList>
              <TabsTrigger value="domains" className="gap-2">
                <Globe className="w-4 h-4" />
                Domains ({domains.length})
              </TabsTrigger>
              <TabsTrigger value="email" className="gap-2">
                <Mail className="w-4 h-4" />
                Email Domains ({emailDomains.length})
              </TabsTrigger>
            </TabsList>

            <TabsContent value="domains" className="space-y-4">
              <div className="flex justify-end">
                <Button onClick={() => openAddDialog("domain")} size="sm">
                  <Plus className="w-4 h-4 mr-2" />
                  Add Domain
                </Button>
              </div>

              {domains.length === 0 ? (
                <Card className="border-dashed">
                  <CardContent className="py-12 text-center">
                    <Globe className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                    <h2 className="text-lg font-semibold mb-2">No Domains Registered</h2>
                    <p className="text-sm text-muted-foreground mb-4">
                      Add your company domains to monitor for mentions in threat intelligence.
                    </p>
                    <Button onClick={() => openAddDialog("domain")}>
                      <Plus className="w-4 h-4 mr-2" />
                      Add Your First Domain
                    </Button>
                  </CardContent>
                </Card>
              ) : (
                <ScrollArea className="h-[calc(100vh-26rem)]">
                  <div className="space-y-3 pr-4">
                    {domains.map((asset) => (
                      <AssetCard
                        key={asset.id}
                        asset={asset}
                        onDelete={handleDelete}
                        isDeleting={deletingId === asset.id}
                      />
                    ))}
                  </div>
                </ScrollArea>
              )}
            </TabsContent>

            <TabsContent value="email" className="space-y-4">
              <div className="flex justify-end">
                <Button onClick={() => openAddDialog("email_domain")} size="sm">
                  <Plus className="w-4 h-4 mr-2" />
                  Add Email Domain
                </Button>
              </div>

              {emailDomains.length === 0 ? (
                <Card className="border-dashed">
                  <CardContent className="py-12 text-center">
                    <Mail className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                    <h2 className="text-lg font-semibold mb-2">No Email Domains Registered</h2>
                    <p className="text-sm text-muted-foreground mb-4">
                      Add your business email domains to track in breach databases.
                    </p>
                    <Button onClick={() => openAddDialog("email_domain")}>
                      <Plus className="w-4 h-4 mr-2" />
                      Add Your First Email Domain
                    </Button>
                  </CardContent>
                </Card>
              ) : (
                <ScrollArea className="h-[calc(100vh-26rem)]">
                  <div className="space-y-3 pr-4">
                    {emailDomains.map((asset) => (
                      <AssetCard
                        key={asset.id}
                        asset={asset}
                        onDelete={handleDelete}
                        isDeleting={deletingId === asset.id}
                      />
                    ))}
                  </div>
                </ScrollArea>
              )}
            </TabsContent>
          </Tabs>
        )}

        {/* Add Asset Dialog */}
        <AddAssetDialog
          open={addDialogOpen}
          onOpenChange={setAddDialogOpen}
          onSubmit={handleAddAsset}
          isSubmitting={isAdding}
          defaultType={addDialogType}
        />
      </div>
    </AppLayout>
  );
}
