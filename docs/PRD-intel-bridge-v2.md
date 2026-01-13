# Intel Bridge V2 - Product Requirements Document

## Executive Summary

**Product:** Intel Bridge V2 - Threat Intelligence for SMBs
**Version:** 2.0
**Date:** January 2026

Intel Bridge V2 is a complete reimagining of the threat intelligence dashboard, purpose-built for small and medium-sized businesses (SMBs) that lack dedicated security teams or expensive vendor solutions.

---

## 1. Problem Statement

### The SMB Security Gap

- 43% of cyber attacks target small businesses
- Average cost of a data breach for SMBs: $2.98 million
- Only 14% of SMBs have a dedicated security team
- Traditional threat intel platforms cost $50,000-$500,000+ annually

### Our Solution

Intel Bridge V2 transforms complex threat intelligence into **5-minute daily briefings** that tell SMB leaders:
- What threats are relevant to YOUR business
- What you should do about them TODAY
- How to explain the risk to stakeholders

---

## 2. Design Principles

1. **Glanceable Intelligence** - Every insight understandable in <5 seconds
2. **Action, Not Information** - Lead with what to do
3. **Relevant by Default** - Filter noise automatically
4. **Executive-Ready** - Shareable with non-technical stakeholders
5. **Time-Respectful** - Daily briefing in 5 minutes

---

## 3. Implementation Phases

### Phase 1: Project Setup & Migration [COMPLETED]
- [x] Initialize Vite + React + TypeScript project
- [x] Configure Tailwind CSS and shadcn/ui
- [x] Migrate Supabase client and configuration
- [x] Migrate data hooks
- [x] Implement auth-disabled mode
- [x] Push to GitHub

### Phase 2: Core Layout & Navigation [COMPLETED]
- [x] Create responsive app layout
- [x] Build sidebar navigation
- [x] Implement route structure
- [x] Add header with threat level banner

### Phase 3: Dashboard - Threat Level & Briefing [COMPLETED]
- [x] Build Threat Level Banner component
- [x] Create Today's Briefing card
- [x] Implement briefing data integration

### Phase 4: Dashboard - Action Items [COMPLETED]
- [x] Build Action Items widget (3-column)
- [x] Create action card component
- [x] Implement urgency-based sorting
- [x] Add dismiss/snooze functionality

### Phase 5: Dashboard - Quick Stats [COMPLETED]
- [x] Build Quick Stats row component
- [x] Create individual stat cards
- [x] Add sparkline trend charts

### Phase 6: Daily Briefing Page [COMPLETED]
- [x] Create briefing page layout
- [x] Build Executive Summary section
- [x] Build Key Threats section
- [x] Build Recommended Actions section

### Phase 7: Threat Feed [COMPLETED]
- [x] Create feed page layout
- [x] Build filter bar component
- [x] Create threat card components
- [x] Implement scroll area for feed

### Phase 8: Intel Chat [COMPLETED]
- [x] Migrate chat components from V1
- [x] Update styling for V2 design
- [x] Add suggested questions

### Phase 9: Polish & Testing [COMPLETED]
- [x] Responsive design audit
- [x] Accessibility improvements
- [x] Performance optimization
- [ ] Playwright test suite (optional)

---

## 4. Future Phases

### Phase 10: Threat Actor Profiles
Build comprehensive threat actor detail pages (based on V1 Intrusion Set pages):
- [ ] Actor header with name, aliases, last modified date
- [ ] Description section with rich text
- [ ] Motivation & resource level badges
- [ ] Goals list
- [ ] Victimology card (targeted countries and sectors)
- [ ] Used Malware with pagination
- [ ] Used Tools list
- [ ] MITRE ATT&CK Techniques table
- [ ] Mitigating Actions (Course of Action) for TTPs
- [ ] Related Reports table
- [ ] Indicators of Compromise (IOCs) table
- [ ] Exploited Vulnerabilities
- [ ] External References links
- [ ] PDF export functionality

### Phase 11: CVE Detail Pages
Individual vulnerability pages:
- [ ] CVE header with ID and severity badge
- [ ] CVSS score breakdown (base, impact, exploitability)
- [ ] EPSS score and percentile
- [ ] Affected products/vendors
- [ ] Description and technical details
- [ ] Related threat actors exploiting this CVE
- [ ] Related malware exploiting this CVE
- [ ] Remediation/mitigation guidance
- [ ] External references (NVD, vendor advisories)

### Phase 12: Industry Customization
- [ ] Industry selection during onboarding (healthcare, finance, retail, manufacturing, etc.)
- [ ] Filter dashboard and briefings by industry-relevant threats
- [ ] Industry-specific threat actor targeting alerts
- [ ] Sector-based vulnerability prioritization

### Phase 13: Asset Inventory
Register company assets for targeted monitoring:
- [ ] Domain registration and monitoring
- [ ] Email domain tracking
- [ ] Asset-to-threat correlation (alert when actor targets your domain)
- [ ] Breach/exposure monitoring for registered assets

### Phase 14: IOC Search
- [ ] Global search for indicators (IPs, domains, file hashes, URLs)
- [ ] Search results with related context (what actors/malware use this IOC)
- [ ] IOC timeline showing first/last seen dates
- [ ] Bulk IOC lookup for incident response

### Phase 15: Historical Trends
- [ ] 7/30/90 day trend charts for threat activity
- [ ] Ransomware victim counts over time
- [ ] Vulnerability disclosure trends
- [ ] Threat actor activity timeline
- [ ] Comparison with previous periods

### Phase 16: PDF Report Generation
- [ ] Export daily briefings as branded PDFs
- [ ] Export threat actor profiles as PDFs
- [ ] Export vulnerability reports as PDFs
- [ ] Customizable report templates
- [ ] Company branding/logo support

### Phase 17: Email Digest
- [ ] Daily/weekly email summary configuration
- [ ] Stakeholder email list management
- [ ] Email template customization
- [ ] Delivery schedule settings
- [ ] Unsubscribe management

### Phase 18: Executive Dashboard View
- [ ] Simplified, non-technical view for C-suite
- [ ] Key metrics only (threat level, action items count)
- [ ] Risk score summary
- [ ] One-click sharing to executives
- [ ] Print-friendly layout

### Phase 19: Real-time Alerts
- [ ] Push notifications for critical threats
- [ ] Configurable alert thresholds
- [ ] Browser notifications
- [ ] Alert history and acknowledgment
- [ ] Quiet hours configuration

### Phase 20: Slack/Teams Integration
- [ ] Webhook configuration for Slack/Teams
- [ ] Daily briefing delivery to channels
- [ ] Critical alert notifications
- [ ] Interactive message actions
- [ ] Channel selection per alert type

### Phase 21: Team Workspaces
- [ ] Multi-user organization accounts
- [ ] Shared threat tracking and bookmarks
- [ ] Role-based access (admin, analyst, viewer)
- [ ] Activity audit log
- [ ] Team member management

### Phase 22: Threat Bookmarks
- [ ] Save threats of interest for later review
- [ ] Organize bookmarks into collections/folders
- [ ] Notes and annotations on bookmarked items
- [ ] Share bookmarks with team members
- [ ] Bookmark expiration/cleanup

### Phase 23: Playbook Library
- [ ] Pre-built incident response playbooks
- [ ] Playbooks linked to threat types (ransomware, phishing, etc.)
- [ ] Step-by-step response procedures
- [ ] Customizable playbook templates
- [ ] Playbook assignment to action items

### Phase 24: Onboarding Wizard
- [ ] Guided first-time user setup
- [ ] Industry selection
- [ ] Asset registration prompts
- [ ] Notification preferences
- [ ] Dashboard tour/tutorial

### Phase 25: Dark/Light Theme Toggle
- [ ] User preference for UI theme
- [ ] System preference detection
- [ ] Persistent theme storage
- [ ] Smooth theme transition

### Phase 26: Mobile Responsive Overhaul
- [ ] Touch-optimized interactions
- [ ] Mobile navigation patterns
- [ ] Responsive data tables
- [ ] Mobile-specific layouts for detail pages

### Lower Priority (Phase 27+)
- [ ] Dashboard widget customization (drag-and-drop, show/hide)
- [ ] Keyboard shortcuts for power users

---

## 5. Technical Architecture

### Frontend Stack
- React 18 + TypeScript
- Vite (build tool)
- Tailwind CSS + shadcn/ui components
- TanStack Query (data fetching & caching)
- React Router DOM

### Backend Architecture (OpenCTI Wrapper)

Intel Bridge acts as a **lightweight wrapper for OpenCTI**, with threat intelligence data synced to Supabase every few minutes. This architecture provides:
- Simplified querying via Supabase REST API
- Real-time subscriptions for live updates
- Type-safe data access with TypeScript
- No direct OpenCTI dependency in the frontend

```
┌─────────────────┐
│    OpenCTI      │  (STIX data source)
│   Instance      │
└────────┬────────┘
         │ Sync (every few minutes)
         ▼
┌─────────────────────────────────────┐
│        Supabase PostgreSQL          │
│  ┌─────────────────────────────┐   │
│  │     intel.object_current    │   │  ← All STIX entities as JSON
│  └─────────────────────────────┘   │
│  ┌─────────────────────────────┐   │
│  │  intel.relationship_current │   │  ← Entity relationships
│  └─────────────────────────────┘   │
│  ┌─────────────────────────────┐   │
│  │   public.intel_summaries    │   │  ← AI-generated daily briefings
│  └─────────────────────────────┘   │
└────────┬────────────────────────────┘
         │ REST API / Realtime
         ▼
┌─────────────────┐
│  React Frontend │
│  (Intel Bridge) │
└─────────────────┘
```

### Database Schema

**Intel Schema** (`intel.*`) - OpenCTI Data:

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `object_current` | All STIX entities | `internal_id`, `entity_type`, `name`, `data` (JSON), `source_updated_at`, `is_deleted` |
| `relationship_current` | Entity relationships | `source_id`, `target_id`, `relationship_type`, `data` |

**Public Schema** - Application Data:

| Table | Purpose |
|-------|---------|
| `intel_summaries` | AI-generated daily briefings with threat analysis |
| `profiles` | User profiles |
| `user_roles` | Role assignments (admin/user) |
| `reports` | User-generated reports |
| `domain_blacklist` | Filtered domains |
| `media_source_blacklist` | Filtered media sources |

### Entity Types Available

| Entity Type | Description | Example Data |
|-------------|-------------|--------------|
| `Intrusion-Set` | Threat actors/APT groups | APT29, Lazarus Group |
| `Campaign` | Coordinated attack campaigns | SolarWinds, Log4Shell exploitation |
| `Malware` | Malware families | Emotet, Cobalt Strike |
| `Tool` | Hacking tools | Mimikatz, BloodHound |
| `Attack-Pattern` | MITRE ATT&CK techniques | T1566 Phishing, T1059 Command Line |
| `Vulnerability` | CVEs | CVE-2024-XXXX with CVSS/EPSS scores |
| `Indicator` | IOCs | IPs, domains, file hashes |
| `Report` | Intelligence reports | Ransomware reports, media reports, advisories |
| `Sector` | Industry sectors | Healthcare, Finance, Manufacturing |
| `Country` | Geographic locations | With regions |
| `Course-Of-Action` | MITRE mitigations | Defensive recommendations |

### Relationship Types

| Type | Meaning | Example |
|------|---------|---------|
| `uses` | Entity uses another | Intrusion-Set → uses → Malware |
| `targets` | Entity targets | Campaign → targets → Sector |
| `exploits` | Exploits vulnerability | Malware → exploits → Vulnerability |
| `indicates` | IOC indicates threat | Indicator → indicates → Malware |
| `attributed-to` | Attribution | Campaign → attributed-to → Intrusion-Set |
| `mitigates` | Defensive measure | Course-Of-Action → mitigates → Attack-Pattern |
| `object-ref` | Report contains | Report → object-ref → Any Entity |

### Existing Data Hooks (from V1)

These hooks are available for querying Supabase:

| Hook | Returns |
|------|---------|
| `useIntrusionSets` / `useIntrusionSetDetail` | Threat actors with TTPs, targets |
| `useMalware` / `useMalwareDetail` | Malware families with capabilities |
| `useCampaigns` / `useCampaignDetail` | Attack campaigns |
| `useTools` / `useToolDetail` | Hacking tools |
| `useAttackPatterns` / `useAttackPatternDetail` | MITRE ATT&CK techniques |
| `useIndicators` / `useIndicatorDetail` | IOCs (IPs, domains, hashes) |
| `useVulnerabilities` / `useVulnerabilityDetail` | CVEs with CVSS/EPSS |
| `useRansomwareVictims` / `useRansomwareVictimDetail` | Ransomware victims |
| `useMediaReports` | News/media intelligence |
| `useEntityCounts` | Dashboard statistics |
| `useIntelOptions` | Filter dropdowns (sectors, countries, actors) |
| `useIntelSummaries` | AI-generated daily briefings |
| `useIntelChat` | Chat sessions and messages |

### Query Patterns

```typescript
// Access intel schema
const intelDb = supabase.schema('intel');

// List entities with pagination
intelDb.from('object_current')
  .select('*', { count: 'exact' })
  .eq('entity_type', 'Intrusion-Set')
  .eq('is_deleted', false)
  .order('source_updated_at', { ascending: false })
  .range(0, 19);

// Get entity relationships
intelDb.from('relationship_current')
  .select('*')
  .eq('source_id', entityId)
  .eq('relationship_type', 'uses');

// Filter by report type
intelDb.from('object_current')
  .eq('entity_type', 'Report')
  .contains('data', { report_types: ['Ransomware-report'] });
```

### Auth Configuration

Auth can be disabled for testing via environment variable:
```
VITE_AUTH_DISABLED=true
```

When disabled, the app uses a mock session for development/Playwright testing.

---

*This PRD is designed for iterative development using the Ralph Loop workflow.*
