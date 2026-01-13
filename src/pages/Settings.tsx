import { useState } from "react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useUserIntelProfile } from "@/hooks/useUserIntelProfile";
import { useAuth } from "@/hooks/useAuth";
import { IntelProfileSettings } from "@/components/intel-profile/IntelProfileSettings";
import {
  Settings as SettingsIcon,
  Building2,
  Globe,
  Skull,
  Tag,
  Bell,
  Clock,
  Eye,
  Loader2,
  User,
} from "lucide-react";

export function Settings() {
  const [profileDialogOpen, setProfileDialogOpen] = useState(false);
  const { user, isLoading: authLoading } = useAuth();
  const { profile, isLoading: profileLoading, hasCompletedOnboarding } = useUserIntelProfile();

  const isLoading = authLoading || profileLoading;

  return (
    <AppLayout>
      <div className="max-w-4xl mx-auto space-y-6 animate-fade-in">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <SettingsIcon className="w-6 h-6" />
            Settings
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage your account and intelligence preferences
          </p>
        </div>

        {/* Account Info */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <User className="w-5 h-5" />
              Account
            </CardTitle>
            <CardDescription>Your account information</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="flex items-center gap-2 text-muted-foreground">
                <Loader2 className="w-4 h-4 animate-spin" />
                Loading...
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Email</span>
                  <span className="font-medium">{user?.email || "Not signed in"}</span>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Intel Profile */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Building2 className="w-5 h-5" />
                  Intel Profile
                </CardTitle>
                <CardDescription>
                  Customize your threat intelligence feed to focus on what matters most
                </CardDescription>
              </div>
              <Button onClick={() => setProfileDialogOpen(true)}>
                {hasCompletedOnboarding ? "Edit Profile" : "Set Up Profile"}
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="flex items-center gap-2 text-muted-foreground">
                <Loader2 className="w-4 h-4 animate-spin" />
                Loading profile...
              </div>
            ) : !hasCompletedOnboarding ? (
              <div className="text-center py-6 text-muted-foreground">
                <Building2 className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>Set up your intel profile to receive personalized threat intelligence</p>
              </div>
            ) : (
              <div className="space-y-4">
                {/* Sectors */}
                {profile?.sectors && profile.sectors.length > 0 && (
                  <div>
                    <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                      <Building2 className="w-4 h-4" />
                      Industry Sectors
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {profile.sectors.slice(0, 5).map((id) => (
                        <Badge key={id} variant="outline">
                          {id}
                        </Badge>
                      ))}
                      {profile.sectors.length > 5 && (
                        <Badge variant="secondary">+{profile.sectors.length - 5} more</Badge>
                      )}
                    </div>
                  </div>
                )}

                {/* Geography */}
                {((profile?.regions && profile.regions.length > 0) ||
                  (profile?.countries && profile.countries.length > 0)) && (
                  <div>
                    <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                      <Globe className="w-4 h-4" />
                      Geographic Focus
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {profile.regions?.slice(0, 3).map((id) => (
                        <Badge key={id} variant="outline">
                          {id}
                        </Badge>
                      ))}
                      {profile.countries?.slice(0, 3).map((id) => (
                        <Badge key={id} variant="secondary">
                          {id}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Threat Actors */}
                {profile?.threat_actors && profile.threat_actors.length > 0 && (
                  <div>
                    <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                      <Skull className="w-4 h-4" />
                      Tracked Threat Actors
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {profile.threat_actors.slice(0, 5).map((id) => (
                        <Badge key={id} variant="outline" className="bg-purple-500/10 text-purple-400">
                          {id}
                        </Badge>
                      ))}
                      {profile.threat_actors.length > 5 && (
                        <Badge variant="secondary">+{profile.threat_actors.length - 5} more</Badge>
                      )}
                    </div>
                  </div>
                )}

                {/* Keywords */}
                {profile?.keywords && profile.keywords.length > 0 && (
                  <div>
                    <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                      <Tag className="w-4 h-4" />
                      Keywords
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {profile.keywords.map((keyword) => (
                        <Badge key={keyword} variant="secondary">
                          {keyword}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Preferences */}
                <div className="pt-4 border-t space-y-2">
                  <div className="flex items-center gap-2 text-sm">
                    <Bell className="w-4 h-4 text-muted-foreground" />
                    <span className="text-muted-foreground">Alert Threshold:</span>
                    <Badge variant="outline" className="capitalize">
                      {profile?.alert_threshold || "high"}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <Clock className="w-4 h-4 text-muted-foreground" />
                    <span className="text-muted-foreground">Summary Frequency:</span>
                    <Badge variant="outline" className="capitalize">
                      {profile?.summary_frequency || "daily"}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <Eye className="w-4 h-4 text-muted-foreground" />
                    <span className="text-muted-foreground">Global Threats:</span>
                    <Badge variant={profile?.show_global_threats ? "default" : "secondary"}>
                      {profile?.show_global_threats ? "Shown" : "Hidden"}
                    </Badge>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Intel Profile Settings Dialog */}
        <IntelProfileSettings open={profileDialogOpen} onOpenChange={setProfileDialogOpen} />
      </div>
    </AppLayout>
  );
}
