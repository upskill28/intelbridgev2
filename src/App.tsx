import { Routes, Route } from "react-router-dom";
import { Dashboard } from "@/pages/Dashboard";

function App() {
  return (
    <Routes>
      <Route path="/" element={<Dashboard />} />
      <Route path="/briefing" element={<Dashboard />} />
      <Route path="/feed" element={<Dashboard />} />
      <Route path="/chat" element={<Dashboard />} />
    </Routes>
  );
}

export default App;
