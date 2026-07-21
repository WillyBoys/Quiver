import { Routes, Route, Navigate } from "react-router-dom";
import { Network, Building2 } from "lucide-react";
import Layout from "./components/layout/Layout.jsx";
import SessionDetailPage from "./pages/SessionDetailPage.jsx";
import ToolsPage from "./pages/ToolsPage.jsx";
import WordlistsPage from "./pages/WordlistsPage.jsx";
import RemotePage from "./pages/RemotePage.jsx";
import ActivityPage from "./pages/ActivityPage.jsx";
import ApprovalQueuePage from "./pages/ApprovalQueuePage.jsx";
import ShannonScansPage from "./pages/ShannonScansPage.jsx";
import EngagementTrackPage from "./pages/EngagementTrackPage.jsx";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/external" replace />} />

        {/* Three engagement tracks */}
        <Route
          path="/external"
          element={
            <EngagementTrackPage
              type="external"
              label="External"
              description="Network and infrastructure attack surface — from the outside in"
              icon={Network}
            />
          }
        />
        <Route
          path="/internal"
          element={
            <EngagementTrackPage
              type="internal"
              label="Internal"
              description="Post-access enumeration, Active Directory, lateral movement"
              icon={Building2}
            />
          }
        />
        <Route path="/web-app" element={<ShannonScansPage />} />

        {/* Engagement workspace — shared between external and internal */}
        <Route path="/sessions/:sessionId" element={<SessionDetailPage />} />

        {/* Platform utilities */}
        <Route path="/approvals" element={<ApprovalQueuePage />} />
        <Route path="/activity" element={<ActivityPage />} />
        <Route path="/tools" element={<ToolsPage />} />
        <Route path="/wordlists" element={<WordlistsPage />} />
        <Route path="/remote" element={<RemotePage />} />
      </Routes>
    </Layout>
  );
}
