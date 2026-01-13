import { Routes, Route } from "react-router-dom";
import { Dashboard } from "@/pages/Dashboard";
import { Briefing } from "@/pages/Briefing";
import { Feed } from "@/pages/Feed";
import { Chat } from "@/pages/Chat";

function App() {
  return (
    <Routes>
      <Route path="/" element={<Dashboard />} />
      <Route path="/briefing" element={<Briefing />} />
      <Route path="/feed" element={<Feed />} />
      <Route path="/chat" element={<Chat />} />
    </Routes>
  );
}

export default App;
