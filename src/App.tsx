import { Routes, Route } from "react-router-dom";
import { Dashboard } from "@/pages/Dashboard";
import { Briefing } from "@/pages/Briefing";
import { Feed } from "@/pages/Feed";
import { Chat } from "@/pages/Chat";
import { ThreatActors } from "@/pages/ThreatActors";
import { ThreatActorDetail } from "@/pages/ThreatActorDetail";
import { Vulnerabilities } from "@/pages/Vulnerabilities";
import { VulnerabilityDetail } from "@/pages/VulnerabilityDetail";
import { Settings } from "@/pages/Settings";
import { Assets } from "@/pages/Assets";

function App() {
  return (
    <Routes>
      <Route path="/" element={<Dashboard />} />
      <Route path="/briefing" element={<Briefing />} />
      <Route path="/feed" element={<Feed />} />
      <Route path="/chat" element={<Chat />} />
      <Route path="/threat-actors" element={<ThreatActors />} />
      <Route path="/threat-actors/:id" element={<ThreatActorDetail />} />
      <Route path="/vulnerabilities" element={<Vulnerabilities />} />
      <Route path="/vulnerabilities/:id" element={<VulnerabilityDetail />} />
      <Route path="/settings" element={<Settings />} />
      <Route path="/assets" element={<Assets />} />
    </Routes>
  );
}

export default App;
